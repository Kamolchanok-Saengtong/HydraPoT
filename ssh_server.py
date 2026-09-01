"""
ssh_server.py — asyncssh server for HydraPot.

The handler we receive from main.py has signature:
    handle(cmd, write_fn, read_fn) -> (response, new_prompt)
"""

import asyncio
import signal
import threading
import os
import queue
import json
import asyncssh
from datetime import datetime

from config_loader import load_config
import storage

HOST_KEY_PATH = "data/hostkey_asyncssh.key"
_cfg = load_config()
AUTH_LOG_PATH = _cfg.logging.auth_log
INSTANCE_NAME = _cfg.honeypot.instance_name

async def _read_hidden(process, prompt_text: str) -> str:
    """Read password input — accepts one line then returns."""
    process.stdout.write(prompt_text)
    try:
        line = await asyncio.wait_for(process.stdin.readline(), timeout=30.0)
        return line.rstrip("\r\n")
    except asyncio.TimeoutError:
        return ""

def _append_json(path, entry):
    """Record one auth event. `path` is kept in the signature for the callers
    but is no longer written to — auth attempts live in SQLite now.

    This used to read the entire auth_log.json, append one entry, and write the
    whole array back. Unlike the session logs that file is shared by every
    session and never rolls over, so the cost of recording a login attempt grew
    with every login attempt ever recorded — worst possible shape for the one
    file an internet-facing honeypot appends to most."""
    try:
        storage.insert_auth(entry)
    except Exception as e:
        print(f"[storage] auth insert failed: {e}")


def get_host_key():
    os.makedirs(os.path.dirname(HOST_KEY_PATH) or ".", exist_ok=True)
    if os.path.exists(HOST_KEY_PATH):
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.write_private_key(HOST_KEY_PATH)
    print(f"[ssh_server] Generated new host key → {HOST_KEY_PATH}")
    return key


# Live session counter. Model calls are serialised (ondevice_agent._MODEL_LOCK
# — concurrent access aborts the process), so every extra session lengthens the
# queue everyone else waits in. Unbounded, a flood makes the honeypot answer
# nobody: still "up", still logging connections, useless. Refusing past a cap
# reads as a busy server, which is ordinary; hanging forever does not.
MAX_SESSIONS = 0        # set from config in start_server(); 0 = unlimited
_active_sessions = 0
_sessions_lock = threading.Lock()


def _session_slots() -> tuple:
    with _sessions_lock:
        return _active_sessions, MAX_SESSIONS


class HoneypotServer(asyncssh.SSHServer):
    """Records every auth attempt and remembers the username for the session."""

    def __init__(self):
        self._peer    = ("?", 0)
        self.username = None
        self._counted = False

    def connection_made(self, conn):
        global _active_sessions
        self._peer = conn.get_extra_info("peername") or ("?", 0)
        ip, port = self._peer

        # Refuse over the cap BEFORE auth, so a flood costs us a TCP accept
        # and nothing else — no shell, no model queue slot. The attempt is
        # still logged: knowing you were flooded is the point.
        if MAX_SESSIONS:
            with _sessions_lock:
                over = _active_sessions >= MAX_SESSIONS
                if not over:
                    _active_sessions += 1
                    self._counted = True
            if over:
                print(f"[ssh_server] REFUSED {ip}:{port} — at capacity "
                      f"({MAX_SESSIONS} sessions)")
                _append_json(AUTH_LOG_PATH, {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": ip, "src_port": port,
                    "event": "refused_capacity", "username": None,
                    "password": None, "auth_type": "tcp_connect",
                    "instance": INSTANCE_NAME,
                })
                conn.abort()
                return
        else:
            with _sessions_lock:
                _active_sessions += 1
                self._counted = True
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[ssh_server] Connection from {ip}:{port}")
        _append_json(AUTH_LOG_PATH, {
            "timestamp": ts,
            "src_ip":    ip,
            "src_port":  port,
            "event":     "connection",
            "username":  None,
            "password":  None,
            "auth_type": "tcp_connect",
            "instance":  INSTANCE_NAME,
        })

    def connection_lost(self, exc):
        global _active_sessions
        # Release the slot exactly once, whatever the reason for the drop —
        # a leak here would silently shrink capacity until nobody gets in.
        if self._counted:
            self._counted = False
            with _sessions_lock:
                _active_sessions = max(0, _active_sessions - 1)
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
            "instance":  INSTANCE_NAME,
        })
        self.username = username
        return True

    def validate_public_key(self, username, key):
        ip, port = self._peer
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            "password":  fp,
            "auth_type": "publickey",
            "instance":  INSTANCE_NAME,
        })
        self.username = username
        return True


async def _shell_session(process, handler_factory, hostname, os_banner):
    peer     = process.get_extra_info("peername")
    src_ip   = peer[0] if peer else "?"
    src_port = peer[1] if peer else 0
    peer_str = f"{src_ip}:{src_port}"

    # asyncssh has no "server" extra_info key, so the old lookup always
    # returned None and every session silently fell back to root — logging in
    # as `admin` still gave `root@psu:~#`. Ask asyncssh directly, then the
    # connection owner (our HoneypotServer, which records username in
    # validate_password), then give up.
    conn     = process.get_extra_info("connection")
    username = process.get_extra_info("username")
    if not username and conn is not None:
        username = conn.get_extra_info("username")
        if not username:
            owner = conn.get_owner() if hasattr(conn, "get_owner") else None
            username = getattr(owner, "username", None)
    username = username or "root"

    prompt_char = "#" if username == "root" else "$"
    # Home follows the account, like a real box. Was hardcoded "/root", so
    # logging in as `admin` showed `admin@psu:~$` while `pwd` returned /root —
    # a giveaway an attacker checks in the first few commands.
    home        = "/root" if username == "root" else f"/home/{username}"
    cwd         = home

    # ── resolve public IP for geo mapping ─────────────────────────
    import ipaddress
    try:
        is_private = ipaddress.ip_address(src_ip).is_private
    except ValueError:
        is_private = True

    if is_private:
        # testing locally — can't geolocate private IPs
        public_ip = src_ip
    else:
        # real attacker from internet — their IP is already public
        public_ip = src_ip

    def make_prompt():
        display = "~" if cwd == home else cwd
        return f"{username}@{hostname}:{display}{prompt_char} "

    prompt = make_prompt()
    swallow = {"lines": 0}
    # handler_factory() connects to the Cowrie backend (main.py's
    # _make_cowrie()), a blocking socket call now bounded by
    # CowrieAgent.CONNECT_TIMEOUT but still slow. asyncssh runs every session
    # on one event loop, so calling this inline used to freeze every other
    # connected attacker's I/O for the duration — off-loaded the same way
    # per-command dispatch already is below.
    command_handler = await asyncio.to_thread(
        handler_factory, src_ip=src_ip, public_ip=public_ip, username=username)

    try:
        process.stdout.write(f"Welcome to {os_banner}\r\n\r\n")
        process.stdout.write(prompt)
    except (BrokenPipeError, asyncssh.ConnectionLost):
        print(f"[ssh_server] {peer_str} disconnected before shell opened")
        process.exit(0)
        return

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

                    if swallow["lines"] > 0:
                        swallow["lines"] -= 1
                        process.stdout.write(prompt)
                        continue

                    if cmd in ("exit", "logout", "quit"):
                        process.stdout.write("logout\r\n")
                        print(f"[ssh_server] {peer_str} clean exit via '{cmd}'")
                        raise SystemExit

                    is_cd = False
                    if cmd == "clear":
                        process.stdout.write("\x1b[H\x1b[2J\x1b[3J" + prompt)
                        continue

                    # ── cd: tracked locally AND forwarded ────────────────
                    # Local tracking keeps the prompt instant. Forwarding is
                    # what was missing: this block used to `continue`, so the
                    # agent never saw `cd` and SYSTEM_STATE["cwd"] stayed at
                    # its initial value forever — the prompt said /home while
                    # `pwd` and `ls` still answered from /root.
                    is_cd = cmd == "cd" or cmd.startswith("cd ")
                    if is_cd:
                        parts = cmd.split(None, 1)
                        # bare `cd` and `cd ~` go to THIS account's home, not
                        # always /root — same reason as the prompt above
                        target = parts[1].strip() if len(parts) > 1 else home

                        if target == "~":
                            target = home
                        elif target.startswith("~/"):
                            target = home.rstrip("/") + target[1:]
                        elif target == "-":
                            target = cwd          # simplification
                        elif not target.startswith("/"):
                            target = cwd.rstrip("/") + "/" + target

                        # resolve . and ..
                        segments = []
                        for p in target.split("/"):
                            if p == "..":
                                if segments:
                                    segments.pop()
                            elif p and p != ".":
                                segments.append(p)
                        cwd = "/" + "/".join(segments)
                        if not cwd:
                            cwd = "/"

                        prompt = make_prompt()
                        # no `continue` — fall through to the agent so it can
                        # update its own cwd and report a real cd error
                    actual = cmd.strip()[5:].strip() if cmd.strip().startswith("sudo ") else cmd.strip()
                    if actual.split()[0] == "passwd":
                        try:
                            pw1 = await asyncio.wait_for(
                                _read_hidden(process, "New password: "), timeout=30.0
                            )
                            pw2 = await asyncio.wait_for(
                                _read_hidden(process, "\r\nRetype new password: "), timeout=30.0
                            )
                            process.stdout.write("\r\npasswd: password updated successfully\r\n")
                        except asyncio.TimeoutError:
                            process.stdout.write("\r\npasswd: Authentication token manipulation error\r\n")
                        process.stdout.write(prompt)
                        continue

                    # ── everything else goes to the agent ──
                    try:
                        response, new_prompt = await asyncio.to_thread(
                            command_handler, cmd, write_fn, read_fn
                        )
                    except Exception as e:
                        import traceback
                        print(f"[ssh_server] Handler error on '{cmd}' from {peer_str}:")
                        traceback.print_exc()
                        response, new_prompt = (f"bash: error: {e}", "")

                    # only accept new_prompt from agent if it contains path info
                    # otherwise we keep our locally tracked prompt. For `cd` the
                    # local prompt already reflects the move and carries the
                    # real username, so it stays authoritative.
                    if new_prompt and not is_cd:
                        prompt = new_prompt if new_prompt.endswith(" ") else new_prompt + " "
                        
                    if isinstance(response, str) and response.startswith("__SWALLOW_"):
                        try:
                            swallow["lines"] = int(response.split("_")[-1])
                        except ValueError:
                            swallow["lines"] = 2
                        response = ""

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


async def _run_server(handler_factory, host, port, hostname, os_banner):
    host_key = get_host_key()

    async def process_factory(process):
        await _shell_session(process, handler_factory, hostname, os_banner)

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


def start_server(handler_factory, host="127.0.0.1", port=2223,
                 hostname="svr04", os_banner="Ubuntu 12.04 LTS",
                 max_sessions=0):
    global MAX_SESSIONS
    MAX_SESSIONS = int(max_sessions or 0)
    if MAX_SESSIONS:
        print(f"[ssh_server] session cap: {MAX_SESSIONS} concurrent")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # SIGTERM is what systemd and Docker send to stop a service; Ctrl-C sends
    # SIGINT. Only SIGINT became KeyboardInterrupt, so under a service manager
    # the process was killed outright and main()'s `finally` — which flushes
    # buffered SIEM events — never ran. Every restart silently dropped
    # whatever had not been exported yet.
    #
    # loop.stop() returns run_forever() normally, so the finally blocks here
    # and in main() both execute. add_signal_handler is Unix-only and raises
    # on some embedded loops, hence the guard.
    def _graceful(signame):
        print(f"\n[ssh_server] {signame} received — closing sessions and "
              f"flushing buffers...")
        loop.stop()

    for signame in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, _graceful, signame)
        except (NotImplementedError, RuntimeError):
            pass   # non-Unix or a loop that does not support it

    try:
        loop.run_until_complete(
            _run_server(handler_factory, host, port, hostname, os_banner)
        )
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[ssh_server] Shutdown requested...")
    finally:
        loop.close()