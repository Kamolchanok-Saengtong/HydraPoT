"""
ssh_server.py — asyncssh server for HydraPot.

The handler we receive from main.py has signature:
    handle(cmd, write_fn, read_fn) -> (response, new_prompt)

  - write_fn(text)  : push partial output to the attacker mid-command
  - read_fn()       : non-blocking poll for the next attacker keystroke
                      (used during interactive commands; returns None
                       when nothing is queued)
"""

import asyncio
import os
import queue
import threading
import asyncssh
from datetime import datetime
import json

HOST_KEY_PATH = "data/hostkey_asyncssh.key"

AUTH_LOG_PATH = "data/logs/auth_log.json"

def _append_json(path, entry):
    """Append entry to a JSON list file. Creates file if missing."""
    existing = []
    if os.path.exists(path):
        try:
            with open(path) as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except json.JSONDecodeError:
            existing = []
    existing.append(entry)
    with open(path, "w") as f:
        json.dump(existing, f, indent=2)

def get_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(HOST_KEY_PATH)
    print(f"[ssh_server] Generated new host key → {HOST_KEY_PATH}")
    return key


class HoneypotServer(asyncssh.SSHServer):
    def __init__(self):
        self._peer = ("?", 0)

    def connection_made(self, conn):
        self._peer = conn.get_extra_info("peername") or ("?", 0)
        print(f"[ssh_server] Connection from {self._peer[0]}:{self._peer[1]}")

    def connection_lost(self, exc):
        if exc:
            print(f"[ssh_server] Connection lost: {exc}")

    def begin_auth(self, username):           return True
    def password_auth_supported(self):        return True
    def public_key_auth_supported(self):      return True

    def validate_password(self, username, password):
        ip, port = self._peer
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ssh_server] [{ts}] {ip}:{port} login attempt → {username}:{password}")
        _append_json(AUTH_LOG_PATH, {
            "timestamp": ts,
            "src_ip":    ip,
            "src_port":  port,
            "username":  username,
            "password":  password,
            "auth_type": "password",
        })
        return True

    def validate_public_key(self, username, key):
        ip, port = self._peer
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # key.get_fingerprint() gives a short hash we can log instead of the raw key
        try:
            fp = key.get_fingerprint()
        except Exception:
            fp = "(unknown)"
        print(f"[ssh_server] [{ts}] {ip}:{port} pubkey attempt → {username} ({fp})")
        _append_json(AUTH_LOG_PATH, {
            "timestamp": ts,
            "src_ip":    ip,
            "src_port":  port,
            "username":  username,
            "password":  fp,           # store fingerprint where password would go
            "auth_type": "publickey",
        })
        return True


async def _shell_session(process, handler_factory):
    peer     = process.get_extra_info("peername")
    src_ip   = peer[0] if peer else "?"
    src_port = peer[1] if peer else 0
    peer_str = f"{src_ip}:{src_port}"

    command_handler = handler_factory(src_ip=src_ip)

    prompt = "root@svr04:~# "
    process.stdout.write("Welcome to Ubuntu 12.04 LTS\r\n\r\n")
    process.stdout.write(prompt)

    loop = asyncio.get_running_loop()
    def write_fn(text: str):
        try:
            loop.call_soon_threadsafe(process.stdout.write, text)
        except Exception as e:
            print(f"[ssh_server] write_fn error from {src_ip}: {e!r}")

    keystroke_q: queue.Queue = queue.Queue()
    def read_fn():
        try:
            return keystroke_q.get_nowait()
        except queue.Empty:
            return None

    try:
        while True:
            try:
                async for line in process.stdin:
                    cmd = line.rstrip("\r\n").strip()

                    ts = datetime.now().strftime("%H:%M:%S")
                    if cmd:
                        print(f"\033[36m[{ts}] {peer_str} ➜\033[0m {cmd}")

                    if not cmd:
                        process.stdout.write(prompt)
                        continue
                    if cmd in ("exit", "logout", "quit"):
                        process.stdout.write("logout\r\n")
                        print(f"[ssh_server] {peer_str} clean exit via '{cmd}'")
                        raise SystemExit

                    if cmd == "clear":
                        process.stdout.write("\x1b[H\x1b[2J\x1b[3J" + prompt)
                        continue

                    try:
                        response, new_prompt = await asyncio.to_thread(
                            command_handler, cmd, write_fn, read_fn
                        )
                    except Exception as e:
                        import traceback
                        print(f"[ssh_server] Handler error on '{cmd}' from {peer_str}:")
                        traceback.print_exc()
                        response, new_prompt = (f"bash: error: {e}", "")

                    if new_prompt:
                        prompt = new_prompt if new_prompt.endswith(" ") else new_prompt + " "

                    if response:
                        response = response.replace("\r\n", "\n").replace("\n", "\r\n")
                        try:
                            process.stdout.write(response + "\r\n")
                        except Exception as e:
                            print(f"[ssh_server] stdout.write error from {peer_str}: {e!r}")

                    try:
                        process.stdout.write(prompt)
                    except Exception as e:
                        print(f"[ssh_server] prompt write error from {peer_str}: {e!r}")

                print(f"[ssh_server] {peer_str} stdin closed (client disconnected)")
                break

            except asyncssh.TerminalSizeChanged:
                continue

            except asyncssh.BreakReceived:
                process.stdout.write("^C\r\n" + prompt)
                continue

    except (SystemExit, asyncssh.ConnectionLost):
        pass
    except Exception as e:
        import traceback
        print(f"[ssh_server] Session error from {peer_str}: {e!r}")
        traceback.print_exc()
    finally:
        print(f"[ssh_server] {peer_str} session ending")
        process.exit(0)


async def _run_server(handler_factory, host, port):   # ← renamed param
    host_key = get_host_key()
    async def process_factory(process):
        await _shell_session(process, handler_factory)   # ← pass factory
    await asyncssh.create_server(
        HoneypotServer, host, port,
        server_host_keys=[host_key],
        process_factory=process_factory,
        encoding="utf-8",
        line_editor=True,
        line_echo=True,
    )
    print(f"[HydraPot] SSH server listening on {host}:{port}")
    print(f"[HydraPot] Test with: ssh root@{host} -p {port}")


def start_server(handler_factory, host="127.0.0.1", port=2223):  # ← renamed param
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_server(handler_factory, host, port))
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[ssh_server] Shutdown requested...")
    finally:
        loop.close()
