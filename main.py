"""
main.py — HydraPoT's entry point. What is wired to what.

This file starts things and connects them. It deliberately holds no honeypot
behaviour: if you are looking for how a command is answered, it is not here.

    shell/session.py   one SSH session's command handler (and shell/ beneath it)
    ssh_server.py      the listener; calls the handler for every command
    agent_manager/     who answers: cowrie, on_device, cloud
    plugins/           FI rules, static handlers, SIEM exporters
    threat_intel/      correlation -> detection -> severity -> alerting
    storage.py         SQLite

Run with `hp --run`, or `python main.py`.
"""
import os
import sys

# docker-compose.yml lives beside this file; compose is run from here so it
# finds both it and .env regardless of the caller's working directory.
_HERE = os.path.dirname(os.path.abspath(__file__))

from config_loader import load_config, sync_compose_env, CLOUD_API_KEY_ENV
from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.ondevice_agent import OnDeviceAgent
from agent_manager.cloud_agent import CloudAgent
from plugins.plugin_loader import PluginManager
from shell import session as _session
from ssh_server import start_server
from threat_intel import sweeper
import storage

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set by main(). Kept as module globals because the SSH server builds a handler
# per connection and needs them, and because `import main; main.config = ...` is
# how the tests stand a session up without booting the whole honeypot.
config   = None
ondevice = None
cloud    = None


def make_command_handler(cowrie, **kwargs):
    """One session's handler. The work is in shell/session.py.

    A thin wrapper so config and the two model agents -- which live here because
    main() builds them -- reach the session without shell/ importing main.
    """
    return _session.make_command_handler(
        cowrie, config=config, ondevice=ondevice, cloud=cloud, **kwargs)


# Re-exported because hp.py and the dashboard import these names from main.
ALERT_SWEEP_SEC = sweeper.SWEEP_INTERVAL_SEC


def _exit_no_cloud_key() -> None:
    """Explain the missing key and stop, instead of a traceback."""
    from setup_wizard import sad_squid

    lines = [
        "",
        *[f"      {row}" for row in sad_squid().splitlines()],
        "",
        "  HydraPoT can't start: the cloud agent has no API key.",
        "",
        f"  Set one:      export {CLOUD_API_KEY_ENV}=sk-...   (in .env or your shell)",
        "  Or turn it off in config.yaml:",
        "                agents:",
        "                  cloud:",
        "                    enabled: false",
        "",
        "  The honeypot runs fine without it — Cowrie and the local model",
        "  answer everything, per routing.fi_routing.",
        "",
    ]
    try:
        from rich.console import Console
        Console().print("\n".join(lines), style="yellow", highlight=False)
    except ImportError:
        print("\n".join(lines))

    # os._exit, not sys.exit: the local model may already be loaded, and
    # llama_cpp's destructor runs after its own globals are gone, printing 15
    # lines of teardown traceback that bury the message above.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(1)


def _compose_cmd() -> list | None:
    """['docker', 'compose'] or ['docker-compose'], whichever exists."""
    import shutil
    import subprocess
    if shutil.which("docker"):
        probe = subprocess.run(["docker", "compose", "version"],
                               capture_output=True, timeout=15)
        if probe.returncode == 0:
            return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    return None


def _recreate_cowrie(port: int) -> None:
    """Republish the container on the new port.

    `restart` is not enough: a port mapping is fixed when the container is
    CREATED, so only `up -d` picks up a change. Never fatal -- Cowrie being
    down degrades a session, it does not stop the honeypot.
    """
    import subprocess

    cmd = _compose_cmd()
    if cmd is None:
        print("[HydraPot] docker compose not found — start Cowrie yourself "
              f"once it publishes {port}")
        return

    print(f"[HydraPot] republishing Cowrie on {port}: {' '.join(cmd)} up -d")
    try:
        r = subprocess.run(cmd + ["up", "-d"], cwd=_HERE,
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("[HydraPot] ⚠ compose timed out; start it yourself")
        return
    if r.returncode != 0:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-3:]
        print("[HydraPot] ⚠ compose failed — Cowrie may be unreachable:")
        for line in tail:
            print(f"    {line}")
        print(f"    run it yourself: {' '.join(cmd)} up -d")
    else:
        print(f"[HydraPot] Cowrie now published on 127.0.0.1:{port}")


def _exit_port_in_use(host: str, port: int) -> None:
    """Name the taken port and how to move, instead of a bind traceback."""
    from setup_wizard import sad_squid

    finder = ("lsof -nP -iTCP:%d -sTCP:LISTEN" % port if sys.platform == "darwin"
              else "ss -ltnp | grep :%d" % port)
    lines = [
        "",
        *[f"      {row}" for row in sad_squid().splitlines()],
        "",
        f"  HydraPoT can't start: {host}:{port} is already in use.",
        "",
        "  Pick another port:",
        f"                hp --run --port {port + 1}",
        "  Or set it permanently in config.yaml:",
        "                honeypot:",
        f"                  port: {port + 1}",
        "",
        "  To see what is holding it:",
        f"                {finder}",
        "",
        "  A previous `hp --run` that did not exit cleanly is the usual cause.",
        "",
    ]
    try:
        from rich.console import Console
        Console().print("\n".join(lines), style="yellow", highlight=False)
    except ImportError:
        print("\n".join(lines))
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(1)


def _start_alert_sweeper(plugins=None):
    sweeper.start(config, plugins=plugins)


def _get_alert_manager():
    return sweeper.get_alert_manager()


def main():
    global config, ondevice, cloud
    config = load_config()
    # No path argument: PluginManager anchors its own directories to the repo
    # root. Passing "plugins/" made loading depend on the cwd, so anything that
    # did not start HydraPoT from the repo root got zero FI rules and zero
    # static handlers, silently -- no error, just a honeypot missing plugins.
    plugins = PluginManager()
    plugins.load_all()

    ondevice = OnDeviceAgent(
        model        = config.agents.on_device.model,
        quantization = config.agents.on_device.quantization,
        gguf_file    = config.agents.on_device.gguf_file,
        temperature  = config.agents.on_device.temperature,
        max_tokens   = config.agents.on_device.max_tokens,
        do_sample    = config.agents.on_device.do_sample,
        mode         = getattr(config.agents.on_device, "mode", "local"),
        base_url     = getattr(config.agents.on_device, "base_url", None),
    ) if config.agents.on_device.enabled else None

    try:
        cloud = CloudAgent(
            provider    = config.agents.cloud.provider,
            model       = config.agents.cloud.model,
            base_url    = getattr(config.agents.cloud, "base_url", "https://ai.psu.blue/v1"),
            temperature = config.agents.cloud.temperature,
            max_tokens  = config.agents.cloud.max_tokens,
        ) if config.agents.cloud.enabled else None
    except EnvironmentError:
        # Shipped config enables cloud, so a first run with no key raised a
        # traceback before the honeypot ever started.
        _exit_no_cloud_key()

    if ondevice is not None:
        # Bounds how long a session waits for its turn at the serialised
        # model; see ondevice_agent._MODEL_LOCK.
        ondevice.wait_timeout = float(
            getattr(config.honeypot, "model_wait_timeout", 20.0) or 0)
    print(f"[HydraPot] on_device: {'loaded' if ondevice else 'DISABLED'}")
    print(f"[HydraPot] cloud: {'loaded' if cloud else 'DISABLED'}")

    # Keep docker-compose publishing the port config.yaml connects to. Done on
    # every run so hand-editing config.yaml is enough -- the two cannot drift.
    if config.agents.cowrie.enabled and sync_compose_env(config.agents.cowrie.port):
        print(f"[HydraPot] .env COWRIE_PORT -> {config.agents.cowrie.port}")
        _recreate_cowrie(config.agents.cowrie.port)

    # Optional startup prune. Off unless logging.retention_on_start is true —
    # nothing should silently delete capture data just because the process
    # restarted. Failures are reported and ignored: a retention problem must
    # never stop the honeypot from starting.
    if getattr(config.logging, "retention_on_start", False):
        try:
            res = storage.prune(
                retention_days=config.logging.retention_days,
                max_rows=config.logging.retention_max_rows,
                protect_instances=config.logging.retention_protect_instances,
                vacuum=config.logging.retention_vacuum,
                dry_run=False,
            )
            gone = sum(v["deleted"] for v in res.values() if isinstance(v, dict))
            if gone:
                print(f"[HydraPot] retention: pruned {gone:,} rows, "
                      f"{res['size_before']/1048576:.0f}MB -> "
                      f"{res['size_after']/1048576:.0f}MB")
        except Exception as e:
            print(f"[HydraPot] retention FAILED ({type(e).__name__}: {e}) — continuing")

    def _make_cowrie():
        c = CowrieAgent(
            host     = config.agents.cowrie.host,
            port     = config.agents.cowrie.port,
            username = config.agents.cowrie.username,
            password = config.agents.cowrie.password,
        )
        # Cowrie backend login can fail — most often the config creds don't match
        # Cowrie's userdb (e.g. the username was changed to one Cowrie doesn't know).
        # We must NOT let that exception propagate: it is raised at session setup,
        # so an uncaught failure kills the attacker's whole session with a bare
        # "connection closed by remote host" and no hint why. Instead: print a loud,
        # clear diagnostic and return the agent UNCONNECTED. CowrieAgent.send()
        # returns ("","") on a dead/None shell, so cowrie-routed commands degrade
        # quietly while the session (and the LLM paths) keep working.
        try:
            c._connect()
        except Exception as e:
            print("=" * 72)
            print(f"[HydraPot] ⚠  COWRIE BACKEND LOGIN FAILED as "
                  f"'{config.agents.cowrie.username}:{config.agents.cowrie.password}'")
            print(f"[HydraPot] ⚠  {type(e).__name__}: {e}")
            print(f"[HydraPot] ⚠  Fix: make config.yaml agents.cowrie creds match "
                  f"Cowrie's userdb (Cowrie's default is root/admin).")
            print(f"[HydraPot] ⚠  Session continues WITHOUT Cowrie — cowrie-routed "
                  f"commands will be degraded, but the attacker is not disconnected.")
            print("=" * 72)
        return c

    # Headless analysis loop. Started only when at least one notification
    # channel is configured, so a sensor nobody is watching does not burn CPU
    # correlating for an audience that does not exist.
    _am = _get_alert_manager()
    if _am and _am._enabled_channels():
        _start_alert_sweeper(plugins)
        print(f"[HydraPot] alert sweep every {ALERT_SWEEP_SEC}s -> "
              f"{', '.join(_am._enabled_channels())}")

    try:
        start_server(
            handler_factory = lambda src_ip="?", public_ip="?", username="root": make_command_handler(
                _make_cowrie(), src_ip=src_ip, public_ip=public_ip,
                plugins=plugins, username=username
            ),
            host            = config.honeypot.host,
            port            = config.honeypot.port,
            hostname        = config.honeypot.hostname,
            os_banner       = config.honeypot.os,
            max_sessions    = getattr(config.honeypot, "max_sessions", 0),
        )
    except KeyboardInterrupt:
        print("\n[HydraPot] Shutting down...")
    except OSError as e:
        # EADDRINUSE is 48 on macOS/BSD, 98 on Linux
        if e.errno not in (48, 98):
            raise
        _exit_port_in_use(config.honeypot.host, config.honeypot.port)
    finally:
        plugins.flush_exporters()
        print("[HydraPot] Done.")


if __name__ == "__main__":
    main()
