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

HOST_KEY_PATH = "hostkey_asyncssh.key"


def get_host_key():
    if os.path.exists(HOST_KEY_PATH):
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(HOST_KEY_PATH)
    print(f"[ssh_server] Generated new host key → {HOST_KEY_PATH}")
    return key


class HoneypotServer(asyncssh.SSHServer):
    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        print(f"[ssh_server] Connection from {peer[0]}:{peer[1]}")

    def connection_lost(self, exc):
        if exc:
            print(f"[ssh_server] Connection lost: {exc}")

    def begin_auth(self, username):           return True
    def password_auth_supported(self):        return True
    def public_key_auth_supported(self):      return True
    def validate_password(self, u, p):
        print(f"[ssh_server] Login attempt: {u}:{p}")
        return True
    def validate_public_key(self, u, k):      return True


async def _shell_session(process, command_handler):
    prompt = "root@svr04:~# "
    process.stdout.write("Welcome to Ubuntu 12.04 LTS\r\n\r\n")
    process.stdout.write(prompt)

    # ── write_fn: synchronous from agent's POV, async-safe under the hood ──
    loop = asyncio.get_running_loop()
    def write_fn(text: str):
        # called from a worker thread; schedule the write on the loop
        loop.call_soon_threadsafe(process.stdout.write, text)

    # ── read_fn: a queue the agent polls. Filled by an async task. ──
    keystroke_q: queue.Queue = queue.Queue()
    interactive_active = threading.Event()

    async def keystroke_pump():
        """While interactive is active, forward stdin lines into the queue."""
        try:
            async for line in process.stdin:
                if interactive_active.is_set():
                    keystroke_q.put(line)
                else:
                    # not interactive → shove it back as a normal command
                    keystroke_q.put(("__NORMAL__", line))
                    return
        except asyncssh.BreakReceived:
            keystroke_q.put("__BREAK__")
        except Exception:
            pass

    def read_fn():
        try:
            return keystroke_q.get_nowait()
        except queue.Empty:
            return None

    try:
        async for line in process.stdin:
            cmd = line.rstrip("\r\n").strip()

            # live attacker monitoring on server console
            peer = process.get_extra_info("peername")
            peer_str = f"{peer[0]}:{peer[1]}" if peer else "?"
            ts = datetime.now().strftime("%H:%M:%S")
            if cmd:
                print(f"\033[36m[{ts}] {peer_str} ➜\033[0m {cmd}")

            if not cmd:
                process.stdout.write(prompt)
                continue
            if cmd in ("exit", "logout", "quit"):
                process.stdout.write("logout\r\n")
                break
            if cmd == "clear":
                process.stdout.write("\x1b[H\x1b[2J\x1b[3J" + prompt)
                continue

            # dispatch in worker thread — handler can block freely
            try:
                response, new_prompt = await asyncio.to_thread(
                    command_handler, cmd, write_fn, read_fn
                )
            except Exception as e:
                print(f"[ssh_server] Handler error on '{cmd}': {e}")
                response, new_prompt = (f"bash: error: {e}", "")

            if new_prompt:
                prompt = new_prompt if new_prompt.endswith(" ") else new_prompt + " "

            if response:
                response = response.replace("\r\n", "\n").replace("\n", "\r\n")
                process.stdout.write(response + "\r\n")

            process.stdout.write(prompt)

    except asyncssh.BreakReceived:
        process.stdout.write("^C\r\n" + prompt)
    except asyncssh.TerminalSizeChanged:
        pass   # attacker resized their window — don't care, don't log
    except Exception as e:
        print(f"[ssh_server] Session error: {e}")
    finally:
        process.exit(0)


async def _run_server(command_handler, host, port):
    host_key = get_host_key()
    async def process_factory(process):
        await _shell_session(process, command_handler)
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


def start_server(command_handler, host="127.0.0.1", port=2223):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_run_server(command_handler, host, port))
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[ssh_server] Shutdown requested...")
    finally:
        loop.close()