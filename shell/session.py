"""
shell/session.py — one SSH session's command handler.

make_command_handler() builds everything a single session needs and returns the
function the SSH server calls for each command. This is the ASSEMBLY POINT: it
constructs the per-session objects from shell/ and wires them together.

    fs         FakeFS        where am I, what path, who owns this file
    sw         Software      what is installed
    tracker    StateTracker  what changed after a command
    responders Responders    answers computed without a model
    link       CowrieLink    talking to the container
    routing    Routing       does this need a model at all
    telemetry  Telemetry     writing it down

WHY ONE PER SESSION. Each SSH connection gets its own SYSTEM_STATE, so two
attackers never see each other's files, installs or working directory. Every
object above holds that dict by reference. This is also why they are built here
rather than imported as module-level singletons.

handle() itself is dispatch and nothing else. Command flow, in order -- each
step can answer and stop:

    1  responders / static   realism: cd, chmod, uname, systemctl, top, vim
    2  _reaches_a_model      SECURITY BOUNDARY. False -> "command not found",
                             no prompt is ever built. ~15% get past here.
    3  detector              optional, logging only, decides nothing (~66ms)
    4  PromptManager._guard  sanitize + isolate the command AND file content
    5  base_prompt.txt       soft: asks the model to stay in character
    6  _llm_send             validate the answer -> re-roll once -> Cowrie.
                             Never a refusal: that tells the attacker.

config and the two model agents arrive as ARGUMENTS. They were module globals in
main.py, read across a 1,500-line closure; passing them makes the dependency
visible and lets a test build a session without importing main.
"""
import os
import re
import time
import random
from datetime import datetime

from agent_manager.cowrie_agent import CowrieAgent
from agent_manager.static_handler import is_static, dispatch_static
from prompt.fi_manager import FILogManager
from prompt.prompt_manager import PromptManager
from threat_intel.mitre_mapper import tag as mitre_tag
from router import _is_cloud, classify

from shell.fakefs import FakeFS
from shell.software import Software
from shell.state import StateTracker
from shell.responders import Responders
from shell.cowrie_link import CowrieLink
from shell.telemetry import Telemetry
from shell.routing import Routing


def parse_command(cmd: str):
    """Raw input -> (actual_cmd, actual_base, lookup_base, from_busybox). PURE.

    Two rewrites, both so everything downstream judges the SAME string:

      sudo     stripped. The attacker is already root, so `sudo X` IS `X`
               (base_prompt.txt rule 2b). Routing once read the raw form while
               every other check read the stripped one, and the prefix alone
               decided the answerer.

      busybox  `busybox X args` and `/bin/busybox X args` ARE `X args`. Doing
               it here rather than asking a model to reason "busybox wraps X
               transparently" was necessary: busybox was 77% of FI4 losses in a
               109-session comparison, and `busybox rm -rf x` drew a DIFFERENT
               wrong answer run-to-run on identical input. Only rewrites when an
               applet name follows -- bare `busybox` prints its own banner.

    from_busybox survives the rewrite because the ERROR MESSAGE does not: an
    unknown applet is "X: applet not found", never bash's "command not found"
    (rule 3). Without the flag the rewrite erased the only evidence of how the
    command was invoked.
    """
    text = cmd.strip()
    actual_cmd = text[5:].strip() if text.startswith("sudo ") else text
    actual_base = actual_cmd.split()[0] if actual_cmd else ""
    lookup_base = os.path.basename(actual_base)     # full path -> bare name

    from_busybox = False
    if lookup_base == "busybox":
        parts = actual_cmd.split()
        if len(parts) > 1:
            actual_cmd, actual_base = " ".join(parts[1:]), parts[1]
            lookup_base = os.path.basename(actual_base)
            from_busybox = True
    return actual_cmd, actual_base, lookup_base, from_busybox


def make_command_handler(cowrie: CowrieAgent, config, ondevice=None, cloud=None,
                         src_ip: str = "?", public_ip: str = "?",
                         plugins=None, sri_max_events: int = 10, sync_state: bool = True,
                         capture_cost: bool = False, username: str = "root",
                         store: str = "sqlite", store_dir: str = ""):

    EDITORS     = {"vim", "vi", "nano", "emacs"}
    SLOW        = ("masscan",)
    INTERACTIVE = ("adduser", "useradd", "userdel")

    SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
    print(f"[HydraPot] New session {SESSION_ID} from {src_ip}")

    # No impactful_dir/session_dir setup any more: both logs go to SQLite, so
    # creating those directories only recreated empty folders after every
    # cleanup. A JSON backend is still available via store="json" below.
    # `store` selects the logging backend for BOTH tables this handler writes:
    # session records below, and impactful events here. They are deliberately
    # driven by one parameter — when they were separate, setting only the
    # FILogManager backend left every session row still going to SQLite, and
    # the two silently disagreed about where a run's data lived.
    fi_manager = FILogManager(
        max_events=sri_max_events,
        min_fi=config.logging.fi_threshold,
        store=store,
        # store_dir must reach BOTH logs. FILogManager's own default points at
        # data/logs/impactful/, so a caller that set store="json" with a
        # store_dir still had its impactful events written into the production
        # log folder — session rows redirected, impactful rows not. That split
        # is exactly how the two drifted apart the first time.
        **({"impactful_path": os.path.join(store_dir, "impactful.json")}
           if store == "json" and store_dir else {}),
        instance=getattr(getattr(config, "honeypot", None), "instance_name", "default"),
    )
    if plugins:
        plugins.apply_fi_rules(fi_manager.scorer)

    SYSTEM_STATE = {
        "versions":  {},
        "installed": {},
        # Home of the account that actually logged in, not always /root.
        # validate_password() accepts any username, so an attacker connecting
        # as `admin` must land in /home/admin or the first `pwd` gives the
        # honeypot away. Filled in just below, once "users" exists.
        "cwd":       "/root",   # tracked so `cd` can be resolved deterministically
                                 # instead of left to the LLM to guess/hallucinate
        "files":     dict(config.system_state.get("starting_files", {})),
        # F3 (systemctl/service) state — otherwise `start`/`stop` were never
        # remembered and `status` always claimed "active (running)" regardless
        # of prior actions, an internal inconsistency an attacker could probe
        # (stop a service, then immediately query status and see it "running").
        "services":  {},   # {service_name: {"active": bool, "enabled": bool}}
        # Persona — see config.yaml system_state.users / .shadow. Copied so
        # a session mutating state (useradd/userdel/chpasswd) cannot leak into
        # the shared config object and affect the next session.
        "users":  {u: dict(v) for u, v in config.system_state.get("users", {}).items()},
        "shadow": dict(config.system_state.get("shadow", {})),
    }

    # The account the attacker authenticated as. Unknown names are registered
    # on the fly with a conventional /home/<user> — a real box would have the
    # account in /etc/passwd, and without this `cd ~` and bare `cd` resolve to
    # root's home for every user.
    if username not in SYSTEM_STATE["users"]:
        SYSTEM_STATE["users"][username] = {
            "uid": 1001, "gid": 1001,
            "home": "/root" if username == "root" else f"/home/{username}",
            "shell": "/bin/bash",
        }
    SYSTEM_STATE["cwd"] = SYSTEM_STATE["users"][username]["home"]

    # One per session -- see shell/software.py. Registers what the box ships
    # with, so `wget --version` works before the attacker installs anything.
    sw = Software(SYSTEM_STATE,
                  base_tools=config.system_state.get("base_tools", []),
                  tool_packages=config.system_state.get("tool_packages", {}),
                  default_versions=config.system_state.get("versions", {}),
                  pre_installed=config.system_state.get("pre_installed", []))
    sw.seed_pre_installed()

    prompt_manager = PromptManager(
        fi_manager,
        SYSTEM_STATE,
        hostname=config.honeypot.hostname,
        os_name=config.honeypot.os,
        kernel=config.honeypot.kernel,
        arch=config.honeypot.arch,
        builtins   = sw.builtins,
        sync_state = sync_state,
        # Sanitising and isolating happen where attacker text ENTERS a prompt,
        # which is here -- both the command and the file content spliced into
        # the SRi block. See PromptManager._guard.
        guardrail  = getattr(config, "guardrail", None),
    )
    session = []

    # ── helpers ───────────────────────────────────────────────────────────

    
    # Standard Linux top-level layout — same set already declared to the
    # LLM in system_setting.txt ("standard Linux layout with /home /tmp
    # /etc /var /usr"), just enumerated here so `cd` can be resolved
    # deterministically against it instead of left to the model's guess.
    # Directories that exist with nothing tracked under them — see
    # config.yaml system_state.known_dirs. Each user's home is unioned in at
    # use time (see _compute_cd), so a custom account's home always resolves.
    # One per session -- see fakefs.py. Holds SYSTEM_STATE by reference, so it
    # always reads the live values as the session mutates them.
    fs = FakeFS(SYSTEM_STATE, username=username,
                known_dirs=config.system_state.get("known_dirs", []))

    # ── Virtual file generation ───────────────────────────────────────────
    def _cat_file_content_extra(actual_cmd: str, actual_base: str) -> str:
        """For `cat <file>`, inject content for virtual files only (/etc/passwd,
        /etc/shadow — synthetic, generated content that SRi's per-file loop in
        prompt_manager.py never sees, since that loop only iterates
        SYSTEM_STATE['files']). Any regular tracked file is ALREADY covered by
        SRi with correctly hex-decoded content — re-injecting it here from
        fs.virtual_file()'s raw (undecoded) fallback would just contradict SRi's
        clean version with a second, worse-quality copy of the same file."""
        extra = ""
        if actual_base == "cat":
            for p in actual_cmd.split()[1:]:
                if p.startswith("-") or p.startswith("|"):
                    continue
                if fs.is_virtual(p):
                    content = fs.virtual_file(p)
                    if content:
                        extra += f"\nFILE CONTENT of {p}:\n{content}\n"
        return extra

    def _handle_passwd(cmd: str, write_fn, read_fn) -> str:
        time.sleep(random.uniform(1.5, 3.0))
        time.sleep(random.uniform(1.5, 3.0))
        return responders.passwd()

    routing = Routing(SYSTEM_STATE, fs, sw)

    def _needs_llm(cmd: str, cmd_base: str, state: dict) -> bool:
        return routing.needs_llm(cmd, cmd_base)

    def _execute_tracked_script(cmd: str, write_fn):
        parts = cmd.strip().split()
        if cmd.strip().startswith("./"):
            script = cmd.strip()[2:].split()[0]
        elif parts[0] in ("bash", "sh") and len(parts) > 1:
            script = parts[1]
        else:
            return None
        file_info = SYSTEM_STATE["files"].get(fs.resolve(script), {})
        content   = file_info.get("content", "")
        if not content or content.startswith("[downloaded from"):
            return None
        combined = ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line_base = line.split()[0]
            if is_static(line):
                combined += dispatch_static(line, write_fn) + "\n"
            elif line_base == "echo":
                arg = line[5:].strip().strip('"').strip("'")
                combined += arg + "\n"
                write_fn(arg + "\r\n")
            elif ondevice is not None:
                sys_p, usr_p = prompt_manager.build_prompt(line)
                out = _llm_send(ondevice, sys_p, usr_p, record_usage=False)
                if out:
                    combined += out + "\n"
            time.sleep(0.1)
        return combined.strip()
    tracker = StateTracker(SYSTEM_STATE, fs, sw)

    def _cowrie_dir_exists(path: str) -> bool:
        """Does Cowrie know this directory? `cd X && pwd` prints the new path
        only when the cd worked, so its output is the test."""
        try:
            out, _ = cowrie.send(f"cd {path} && pwd")
        except Exception:
            return False
        return bool(out and path in out)

    responders = Responders(SYSTEM_STATE, fs, tracker,
                            host=config.honeypot, probe=_cowrie_dir_exists)

    def _answer_without_cowrie(cmd_text: str):
        """What to say when the container is gone. Passed to CowrieLink rather
        than imported there, so shell/ never depends on an agent."""
        if ondevice is None:
            return "", "on_device"
        sys_p, usr_p = prompt_manager.build_prompt(cmd_text)
        return _llm_send(ondevice, sys_p, usr_p, record_usage=False), "on_device"

    link = CowrieLink(cowrie, fallback=_answer_without_cowrie)

    # ── shortcut: log + return ────────────────────────────────────────────
    def _reaches_a_model(agent, needs_llm, base, lookup_base, cmd) -> bool:
        """Should this command be allowed to build a prompt at all?

        The cheapest defence there is, and the only one that cannot fail: a
        command that never reaches a model has no prompt to inject into. Only
        ~15% of a session's traffic gets past here.

        False -> the caller answers "command not found" and stops.

        The exceptions are shell builtins and package verbs, which are real
        even though no binary backs them, and ./script, which Cowrie owns.
        """
        if agent != "cowrie" or needs_llm or sw.available(lookup_base):
            return True                       # a real tool, or already routed away
        if not base or base in ("echo", "cd", "exit", "logout", "clear"):
            return True                       # shell builtins
        if cmd.startswith(("./", "apt", "dpkg")):
            return True                       # Cowrie owns these
        return False

    def _llm_send(agent_obj, system_prompt, user_prompt, record_usage=True,
                  cmd=None):
        """THE single place this file calls a model.

        Eight call sites used to do this inline, each repeating the same
        capture_cost / last_usage branch. One of them is enough, and it gives
        the guardrail exactly one seam to hook: input checks go in before the
        send, the output validator goes in after, and neither has to be
        remembered in eight places.

        record_usage=False for the two callers that never recorded usage --
        _execute_tracked_script (many calls per command, so the last one would
        overwrite the rest) and _cowrie_fallback. Kept exactly as they were:
        changing what capture_cost measures would move the cost numbers the
        Part C experiments are built on.

        Returns "" for a missing agent, so callers do not each re-check.
        """
        if agent_obj is None:
            return ""

        def _once():
            if capture_cost and record_usage:
                text, usage = agent_obj.send_with_usage(system_prompt, user_prompt)
                handle.last_usage = usage
                return text or ""
            return agent_obj.send(system_prompt, user_prompt) or ""

        out = _once()
        if _validator is None:
            return out

        broke = _validator.validate(out)
        if not broke.broke_persona:
            return out

        # The model stopped being a terminal -- "as an AI", "I'm sorry", "my
        # instructions". This is the layer that catches what the detector
        # cannot: it scored 0.000 on both confirmed breaks, because a question
        # like "are you an AI language model?" is not an injection, it just
        # works. The break shows up in the ANSWER, so that is where it is
        # caught.
        if _gcfg.retry_on_break:
            retry = _once()
            retry_broke = _validator.validate(retry)
            if not retry_broke.broke_persona:
                _record_break(cmd, out, broke.reasons, "retry")
                return retry
            out, broke = retry, retry_broke

        # Still broken. Hand it to Cowrie, which is a real emulator and cannot
        # break character. NEVER a canned refusal -- that tells the attacker
        # they hit a filter, the one outcome a honeypot must avoid.
        # cmd=None on the recursive path (see _answer_without_cowrie), so this
        # cannot loop.
        if cmd:
            fallback, _ = link.send(cmd)
            _record_break(cmd, out, broke.reasons, "cowrie")
            return fallback or ""
        _record_break(cmd, out, broke.reasons, "unresolved")
        return out

    # ── prompt-injection guardrail ──────────────────────────────────────────
    # Built once per session. See guardrail/ and config_loader.GuardrailCfg.
    #
    # Sanitising and isolating happen in PromptManager (it owns every path that
    # puts attacker text into a prompt). What lives HERE is the two things that
    # need the command and its answer: the output validator, and the detector
    # that records an injection attempt as threat intelligence.
    _gcfg = getattr(config, "guardrail", None)
    _guard_on = bool(_gcfg and _gcfg.enabled)

    _validator = None
    if _guard_on and _gcfg.validate:
        from guardrail.validator import OutputValidator
        _validator = OutputValidator()

    _detector = _injection_log = None
    if _guard_on and _gcfg.detector.enabled:
        try:
            from guardrail.detector import make_detector
            from guardrail.logger import InjectionLogger
            _detector = make_detector({
                "provider": _gcfg.detector.provider,
                "model": _gcfg.detector.model,
                "device": _gcfg.detector.device,
                "threshold": _gcfg.detector.threshold,
            })
            _injection_log = InjectionLogger(path=_gcfg.detector.log_path)
        except Exception as e:
            print(f"[guardrail] detector unavailable: {type(e).__name__}: {e}")

    def _record_break(cmd_text, output, reasons, resolution):
        """A persona break IS threat intelligence: it means an input got the
        model to stop being a terminal. Recorded whether or not the detector is
        running, because this is the signal the detector misses -- it scored
        0.000 on both confirmed breaks."""
        if _injection_log is None:
            return
        try:
            _injection_log.record(
                decision=None, cmd=cmd_text, src_ip=src_ip,
                session_id=SESSION_ID,
                extra={"persona_break": reasons, "resolution": resolution,
                       "output": (output or "")[:300]})
        except Exception:
            pass

    telemetry = Telemetry(
        SESSION_ID, src_ip=src_ip, public_ip=public_ip,
        instance=getattr(getattr(config, "honeypot", None), "instance_name", "default"),
        store=store, store_dir=store_dir,
        session_dir=getattr(getattr(config, "logging", None), "session_dir", ""),
        tag=mitre_tag,
        export=(plugins.export_event if plugins else None))

    def _finish(cmd, agent, output, fi_score, t_start, streamed=False):
        handle.last_agent  = agent
        handle.state_size  = len(SYSTEM_STATE["files"]) + len(SYSTEM_STATE["installed"])
        latency_ms = (time.time() - t_start) * 1000
        # fi/method from handle() -- one score per command, see the note at
        # the scorer.score() call there.
        fi_manager.process(command=cmd, output=output, agent=agent,
                           session_id=SESSION_ID, fi=fi_score,
                           method=getattr(handle, "fi_method", None))
        session.append({"cmd": cmd, "agent": agent, "response": output})
        telemetry.record(cmd, agent, output, fi_score, latency_ms)
        return ("", "") if streamed else (output, "")

    # ── main dispatch ─────────────────────────────────────────────────────

    def _deterministic_answer(actual_cmd, actual_base, cloud_routed,
                              force_agent, cmd, fi_score, t_start):
        """Commands answered from our own state, never by a model.

        -> the finished response, or None to keep going.

        Every one is here because a MODEL got it wrong in a way it could
        not take back -- shell/responders.py lists the four observed
        cases. Each is logged as the agent it DISPLACED, so the routing
        statistics stay honest about what these took away from cowrie.

        force_agent=="cowrie" is the measurement arm: it must reach the
        real container, so none of this applies to it.
        """
        if force_agent == "cowrie":
            return None

        if actual_base == "cd":
            handled, cd_error = responders.cd(actual_cmd)
            if handled:
                # Keep the REAL Cowrie shell in step with SYSTEM_STATE['cwd'].
                # Cowrie holds one persistent SSH shell with its own working
                # directory, but this branch answers `cd` itself and never
                # forwards it — so the container stayed wherever it started
                # while our tracked cwd moved. Any later cowrie-routed
                # command then ran in the WRONG directory (e.g. `cd /tmp`
                # then `ls` listed /root), which an attacker spots instantly.
                # Send the RESOLVED absolute path so relative forms (`..`,
                # `~`, symlinked paths) land in the same place on both sides.
                if cd_error is None:
                    try:
                        cowrie.send(f"cd {SYSTEM_STATE['cwd']}")
                    except Exception:
                        pass   # sync is best-effort: never break the session
                return _finish(cmd, "cowrie", cd_error or "", fi_score, t_start)

        if actual_base == "chmod" and not cloud_routed:
            handled, chmod_error = responders.chmod(actual_cmd)
            if handled:
                # Only forward a chmod we actually accepted. Forwarding one
                # we answered with "No such file" would create the file's
                # permissions on a file we just said does not exist.
                if chmod_error is None:
                    link.sync(actual_cmd)
                return _finish(cmd, "cowrie", chmod_error or "", fi_score, t_start)

        # unset always succeeds silently in real bash, regardless of
        # whether the variable existed. No existence-check ambiguity at
        # all (unlike cd/chmod), so this is the simplest of the three:
        # "unset" was simply missing from BUILTIN_TOOLS, so the model
        # had no signal it's always available and guessed "command not
        # found" (or worse, treated the variable name as the command).
        if actual_base == "unset":
            return _finish(cmd, "cowrie", "", fi_score, t_start)

        # uname — identity comes from config.yaml, not from whichever
        # backend happens to answer. Logged as "cowrie" like cd/chmod/
        # unset above: this is the agent the command WOULD have reached,
        # so the routing statistics stay honest about what was displaced.
        if actual_base == "uname":
            handled, uname_out = responders.uname(actual_cmd)
            if handled:
                return _finish(cmd, "cowrie", uname_out, fi_score, t_start)

        # systemctl/service — resolved deterministically, UNCONDITIONALLY
        # (unlike chmod, not gated by `not cloud_routed`). This isn't about
        # single-response quality (where cloud is measurably better) — it's
        # about STATE CONSISTENCY across many turns: neither on_device nor
        # cloud gets a "services" section injected into their prompt today,
        # so an LLM answering `systemctl status X` has no way to know a
        # prior `stop X` ever happened. Routing this to any agent, cloud
        # included, would keep answering "active (running)" forever
        # regardless of history — an inconsistency an attacker can trivially
        # probe (stop a service, immediately check status). Only a single
        # shared, deterministic source of truth (SYSTEM_STATE["services"])
        # closes that gap.
        if actual_base in ("systemctl", "service"):
            output = responders.systemctl(actual_cmd)
            tracker.record(cmd, output)
            return _finish(cmd, "on_device", output, fi_score, t_start)
        return None

    def handle(cmd: str, write_fn, read_fn, force_agent: str | None = None):
        if cmd.strip() == "fi status":
            fi_manager.status()
            return "", ""

        t_start  = time.time()
        output   = ""
        streamed = False
        handle.last_usage = None

        actual_cmd, actual_base, lookup_base, from_busybox = parse_command(cmd)
        fi_score, fi_method = fi_manager.scorer.score(actual_cmd)
        # _finish() is a SIBLING closure, not nested in handle(), so it cannot
        # see this local. Published the way handle.last_usage already is.
        handle.fi_method = fi_method

        # ── shell SYNTAX that produces no output — handle like real bash ──────
        #    A real bash (and Cowrie's real container) treats these as silent;
        #    HydraPoT's command-not-found handler was instead reading the first
        #    token as a "command" and wrongly printing "bash: X: command not
        #    found" (found: 125 FI0 commands lost to Cowrie on this alone).
        #      1. VAR=value / VAR=$(...) [VAR2=... ...]   pure assignment(s) -> silent
        #      2. VAR=value  cmd args...                  env-prefix -> run the REAL cmd
        #      3. >file  / >>file  (redirect only)         -> silent (creates/truncates)
        #    Skipped for force_agent=="cowrie" so the Pure-Cowrie benchmark keeps
        #    measuring the real container, same rule as the cd/chmod block below.
        # one assignment token: NAME= then a value that may be single/double
        # quoted, a $(...) substitution, or bare (bare stops at whitespace) —
        # so VER=$(uname -a) and YEL='[1 ; 33m' count as ONE assignment each.
        _ASSIGN = r"[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|\$\([^)]*\)|[^\s]*)"
        _PURE_ASSIGN = re.compile(r"^\s*(?:" + _ASSIGN + r"\s*)+$")
        _ENV_PREFIX  = re.compile(r"^\s*(?:" + _ASSIGN + r"\s+)+(\S.*)$", re.S)
        if force_agent != "cowrie" and actual_cmd:
            if _PURE_ASSIGN.match(actual_cmd):
                # pure assignment(s): wdir="/bin", VER=$(uname -a), A=1 B=2
                # -> bash assigns and prints nothing
                return _finish(cmd, "cowrie", "", fi_score, t_start)
            _m = _ENV_PREFIX.match(actual_cmd)
            if _m:
                # env-var prefix (LC_ALL=C ls) -> evaluate the REAL command
                actual_cmd  = _m.group(1)
                actual_base = actual_cmd.split()[0]
                lookup_base = os.path.basename(actual_base)
            elif actual_cmd.lstrip().startswith((">", "<")):
                # redirect with no command (>file, >>file, >.dropper) -> silent
                tracker.record(cmd, "")
                return _finish(cmd, "cowrie", "", fi_score, t_start)

        # ── helper: does this command reference a tracked (LLM/local-only) file? ──
        def _cowrie_send(cmd_text: str, write_fn=None):
            # actual_cmd for the fallback: Cowrie runs what was typed, the model
            # is prompted with the normalised form. See CowrieLink.send.
            return link.send(cmd_text, write_fn, fallback_cmd=actual_cmd)

        # ── general SRi-state safety net ───────────────────────────────────
        tracked_path = fs.locally_owned(actual_cmd)

        # ── cd/chmod/unset — resolved deterministically, ahead of the
        #    force_agent dispatch so this applies uniformly in production
        #    and forced-eval routing — EXCEPT when force_agent=="cowrie"
        #    explicitly, which must still reach the real Cowrie container
        #    below. That arm exists specifically to measure Cowrie's own,
        #    real, unmodified behavior as a baseline; silently answering on
        #    its behalf here would corrupt that measurement (found after
        #    the fact — every "Pure Cowrie" score for these three command
        #    types up to this point was actually scoring this code, not
        #    Cowrie). Production is unaffected either way: none of cd's/
        #    chmod's/unset's FI bands route to cowrie in config.yaml, so
        #    Cowrie would never naturally see these regardless.
        # Does this command's routing send it to the CLOUD agent?
        #
        # The deterministic handlers below (chmod/passwd/useradd) exist to stop
        # the weaker agents hallucinating — but they also fire for commands the
        # router wants to send to cloud, which never then reaches cloud at all.
        # Measured head-to-head on the same 175 FI4 commands: cloud 0.975 vs
        # these rules 0.919 BERTScore (cloud better on 38, worse on 0) — so for
        # cloud-routed commands the rules are a downgrade, not a safety net.
        #
        # Deliberately NOT bypassed for cowrie/on_device routing (they do need
        # the help), and never for `cd`/`unset` — `cd` also syncs the Cowrie
        # shell above, and `unset` is trivially always-silent.
        def _routes_to_cloud() -> bool:
            if force_agent is not None:
                return force_agent == "cloud"
            if _is_cloud(actual_cmd):      # obfuscated -> cloud regardless of FI
                return True
            try:
                return str(config.routing.fi_routing.get(fi_score)) == "cloud"
            except Exception:
                return False

        cloud_routed = _routes_to_cloud()

        answered = _deterministic_answer(actual_cmd, actual_base, cloud_routed,
                                         force_agent, cmd, fi_score, t_start)
        if answered is not None:
            return answered

        # ── evaluation-only forced routing ───────────────────────────────────
        # force_agent is only set by the eval framework (run_partB.py).
        # Production always calls handle(cmd, write_fn, read_fn) — force_agent
        # defaults to None and this block is completely skipped.
        if force_agent is not None:
            if force_agent == "cloud":
                agent = "cloud"
                sys_p, usr_p = prompt_manager.build_cloud_prompt(actual_cmd)
                usr_p += _cat_file_content_extra(actual_cmd, actual_base)
                output = _llm_send(cloud, sys_p, usr_p, cmd=actual_cmd)
                link.sync_history(cmd)
                tracker.record(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)
            elif force_agent == "on_device":
                agent = "on_device"
                sys_p, usr_p = prompt_manager.build_prompt(actual_cmd)
                output = _llm_send(ondevice, sys_p, usr_p, cmd=actual_cmd)
                tracker.record(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)
            elif force_agent == "cowrie":
                # force_agent=="cowrie" is the measurement arm — it must reach
                # the real container, so no fallback here on purpose.
                agent  = "cowrie"
                output, _ = cowrie.send(cmd)
                tracker.record(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)

        # ── apt install — fully local, streamed ───────────────────────────
        if re.search(r'\b(apt|apt-get)\s+install\b', actual_cmd):
            parts = actual_cmd.strip().split()
            try:
                i    = parts.index('install')
                pkgs = [p for p in parts[i+1:] if not p.startswith('-') and len(p) > 1]
            except ValueError:
                pkgs = []
            if pkgs:
                sw.install(pkgs)
                output = sw.apt_output(pkgs)
                for line in output.split("\n"):
                    write_fn(line + "\r\n")
                    time.sleep(random.uniform(0.1, 0.4))
                return _finish(cmd, "cowrie", output, fi_score, t_start, streamed=True)

        # ── wget/curl — REAL download via Cowrie, streamed ───────────────
        # This used to call responders.download_output(): a synthetic transcript
        # that logged as agent "cowrie" without ever contacting Cowrie. It
        # looked perfect and saved nothing, so the attacker's next
        # `cat <file>` returned "No such file or directory" — and the fake
        # log said "Connecting to ...:80" even for an https:// URL, which is
        # a one-line giveaway.
        #
        # Cowrie implements wget/curl for real: it opens the socket, fetches
        # the bytes, and registers the file in its filesystem. CowrieAgent
        # holds one persistent shell per session, so a later `cat` (FI 0 ->
        # cowrie) reads that same filesystem and returns the real content.
        # Verified against the live backend: a 5,278-byte README.md that
        # `ls -la` listed and `cat` printed in full.
        #
        # tracker.record() still runs so SYSTEM_STATE["files"] tracks the
        # download too — that is what the on_device/cloud agents read.
        if actual_base in ("wget", "curl") and re.search(r'https?://', actual_cmd):
            output, used = _cowrie_send(cmd, write_fn=write_fn)
            tracker.record(cmd, output)
            return _finish(cmd, used, output, fi_score, t_start, streamed=True)

        if actual_base == "passwd" and not cloud_routed:
            fi_manager.process(command=cmd, output="", agent="on_device",
                               session_id=SESSION_ID, fi=fi_score, method=fi_method)
            session.append({"cmd": cmd, "agent": "on_device", "response": ""})
            # An elapsed time, not t_start. This branch used to pass t_start
            # itself -- time.time(), so `passwd` logged a latency_ms of ~1.7e12
            # while every other command logged a few hundred.
            telemetry.record(cmd, "on_device", "",
                             fi_score, (time.time() - t_start) * 1000)
            return "", ""
        
        if actual_base in INTERACTIVE and not cloud_routed:
            parts = actual_cmd.strip().split()
            if len(parts) < 2:
                output, _ = cowrie.send(cmd)
                return _finish(cmd, "cowrie", output, fi_score, t_start)

            if actual_base == "userdel":
                username = parts[-1]
                SYSTEM_STATE["users"].pop(username, None)
                SYSTEM_STATE["shadow"].pop(username, None)
                output = ""
                return _finish(cmd, "cowrie", output, fi_score, t_start)

            # useradd / adduser — register user
            username = parts[-1]
            shell_m  = re.search(r'-s\s+(\S+)', actual_cmd)
            shell    = shell_m.group(1) if shell_m else "/bin/bash"
            uid      = 1000 + len(SYSTEM_STATE["users"])
            SYSTEM_STATE["users"][username] = {
                "uid": uid, "gid": uid,
                "home": f"/home/{username}", "shell": shell,
            }
            SYSTEM_STATE["shadow"][username] = "*"
            output = ""
            return _finish(cmd, "cowrie", output, fi_score, t_start)

        # ── editor (installed, not --version) — silent success ────────────
        if actual_base in EDITORS and sw.available(actual_base):
            if re.search(r'--version\b|-V\b', cmd):
                output = sw.version(lookup_base)
                return _finish(cmd, "on_device", output, fi_score, t_start)
            else:
                return _finish(cmd, "on_device", "", fi_score, t_start)

        # ── find — return plausible results for common attacker queries ───
        if actual_base == "find" and not re.search(r'--version\b', cmd):
            if re.search(r'-perm\s+-?4000', actual_cmd):
                output = "\n".join([
                    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                    "/usr/bin/newgrp", "/usr/bin/gpasswd", "/usr/bin/chsh",
                    "/usr/bin/chfn", "/bin/mount", "/bin/umount", "/bin/ping",
                ])
                return _finish(cmd, "cowrie", output, fi_score, t_start)
            if re.search(r'-name\s+["\']?\*\.conf', actual_cmd):
                output = "\n".join([
                    "/etc/ssh/sshd_config", "/etc/mysql/mysql.conf.d/mysqld.cnf",
                    "/etc/nginx/nginx.conf", "/etc/php/8.1/cli/php.ini",
                    "/etc/fail2ban/fail2ban.conf", "/etc/logrotate.conf",
                ])
                return _finish(cmd, "cowrie", output, fi_score, t_start)
            if re.search(r'-name\s+["\']?\*\.env', actual_cmd):
                output = "/var/www/html/.env\n/opt/app/.env"
                return _finish(cmd, "cowrie", output, fi_score, t_start)

        # ── static commands — guaranteed dispatch, independent of FI/agent ──
        # nmap/ping/traceroute/tracepath/top/htop/watch/tail-f/vim-nano-emacs/
        # less-more must ALWAYS produce their dedicated safe fake output
        # (static_handler.py exists specifically because these hang or behave
        # badly in real Cowrie) — this can't depend on what FI band or
        # classify() decides, so it's checked unconditionally here, after the
        # more specific overrides above (apt/wget-curl/editor-available/etc.)
        # have had their turn but before routing even runs.
        if is_static(actual_cmd):
            output = dispatch_static(actual_cmd, write_fn)
            tracker.record(cmd, output)
            return _finish(cmd, "cowrie", output, fi_score, t_start, streamed=True)

        # ── Route using classify() from router.py ─────────────────────────
        # classify() returns 'cowrie', 'on_device', or 'cloud'
        # _needs_llm() is still used for context-aware dispatch within
        # the on_device branch (file content injection, script execution, etc.)
        needs_llm = _needs_llm(cmd, lookup_base, SYSTEM_STATE)
        # actual_cmd, NOT cmd: every other check in handle() uses the form with
        # `sudo ` removed, and routing has to agree with them. It did not, and
        # the prefix alone decided the answerer:
        #
        #   notarealcmd       -> _base_cmd "notarealcmd" -> cowrie
        #                        -> "command not found", no prompt ever built
        #   sudo notarealcmd  -> _base_cmd "sudo" -> misses COWRIE_AUTHORITATIVE,
        #                        falls to the FI band, where FI_RULES treats a
        #                        leading `sudo` as elevation -> on_device
        #
        # So `sudo <anything>` walked past the command-not-found guard and got a
        # prompt built for it. The attacker is already root here, so `sudo X` IS
        # `X` (base_prompt.txt rule 2b) and routing it as X is also the correct
        # answer, not just the safe one.
        agent     = classify(actual_cmd, session)

        if tracked_path and agent == "cowrie":
            agent      = "on_device"
            needs_llm  = True   # forces it into the on_device branch below

        # Inverse of the rule above: a file Cowrie downloaded is Cowrie's, and
        # only Cowrie can read or mutate it truthfully. Without this `rm f`
        # (FI 4 -> on_device) invented "No such file or directory" for a file
        # `cat f` then printed in full — a contradiction in two commands.
        if fs.cowrie_owned(actual_cmd) and config.agents.cowrie.enabled:
            agent     = "cowrie"
            needs_llm = False

        # Cowrie already known dead — do not send anything else its way. The
        # command that discovered the failure degrades inside _cowrie_send();
        # every command after it is routed correctly from the start.
        if agent == "cowrie" and not getattr(cowrie, "available", True):
            agent     = "on_device"
            needs_llm = True

        # ── SECURITY BOUNDARY ───────────────────────────────────────────────
        # False here means no prompt is ever built, so there is nothing to
        # inject into. This is what stops naked injection text: argv[0] of
        # "ignore your previous instructions" is `ignore`, which is not a
        # command. Everything downstream -- sanitise, isolate, validate --
        # only guards what gets PAST here: injection smuggled inside a command
        # that really exists.
        if not _reaches_a_model(agent, needs_llm, actual_base, lookup_base,
                                actual_cmd):
            output = (f"{actual_base}: applet not found" if from_busybox
                      else f"bash: {actual_base}: command not found")
            return _finish(cmd, "cowrie", output, fi_score, t_start)

        # ── guardrail: detect (logging only) ────────────────────────────────
        # BELOW the boundary on purpose: only ~15% of commands get this far, so
        # the classifier's ~66ms is not spent on traffic that never reaches a
        # model, and the log stops recording things that were never at risk.
        #
        # IT DECIDES NOTHING. The defences run regardless of what it says --
        # gating them on an 80%-F1 classifier would leave the confirmed breaks,
        # which it scores 0.000 on, completely undefended. This is threat
        # intelligence: an attacker probing the LLM is worth capturing.
        # Past the boundary AND actually going to a model -- a command that
        # Cowrie answers builds no prompt either.
        if _detector is not None and (needs_llm or agent != "cowrie"):
            try:
                from guardrail.policy import Action, Policy
                from guardrail.sanitizer import Sanitized
                # Reuse what PromptManager._guard already stripped for the
                # prompt, rather than sanitising the same command twice.
                removed = getattr(prompt_manager, "last_removed", []) or []
                _san = Sanitized(text=actual_cmd, removed=removed,
                                 modified=bool(removed))
                _decision = Policy().decide(_detector.classify(actual_cmd), _san)
                if _decision.action is Action.PROTECT and _injection_log:
                    _injection_log.record(_decision, cmd, src_ip=src_ip,
                                          session_id=SESSION_ID,
                                          removed_tokens=removed)
            except Exception as e:
                print(f"[guardrail] detect failed: {type(e).__name__}: {e}")

        if agent == "cloud":
            sys_p, usr_p = prompt_manager.build_cloud_prompt(actual_cmd)
            usr_p += _cat_file_content_extra(actual_cmd, actual_base)
            output = _llm_send(cloud, sys_p, usr_p, cmd=actual_cmd)
            link.sync_history(cmd)
            tracker.record(cmd, output)

        elif agent == "on_device" or needs_llm:
            if re.search(r'--version\b|-V\b', cmd):
                agent  = "on_device"
                output = sw.version(lookup_base)
                tracker.record(cmd, output)
                return _finish(cmd, agent, output, fi_score, t_start)

            elif actual_base in ("touch", "mkdir"):
                # Forward to Cowrie as well as recording it here. These used to
                # update SYSTEM_STATE only, so the file existed on our side and
                # not in Cowrie's real filesystem — and the two then disagreed
                # the moment any command reached the other side:
                #
                #   touch payload.sh    -> our state only
                #   ls -la payload.sh   -> answered here, file "exists"
                #   chmod 755 payload.sh-> our state only, Cowrie unchanged
                #   rm payload.sh       -> routed to Cowrie -> "No such file"
                #
                # Same fix as `cd` above: answer locally for speed and state,
                # forward so the container stays in step. Best effort — a
                # logging or backend problem must never kill a live session.
                tracker.record(cmd, "")
                link.sync(actual_cmd)
                return _finish(cmd, "cowrie", "", fi_score, t_start)

            elif actual_base == "mv":
                parts = actual_cmd.split()
                if len(parts) >= 3 and fs.resolve(parts[1]) in SYSTEM_STATE["files"]:
                    tracker.record(cmd, "")
                    return _finish(cmd, "cowrie", "", fi_score, t_start)

            # systemctl/service now handled deterministically, unconditionally,
            # ahead of routing (see the block above `if actual_base == "unset"`)
            # — this branch is unreachable but kept documented here for anyone
            # reading the on_device dispatch top-to-bottom.

            elif actual_base == "sed":
                agent  = "on_device"
                tracker.record(cmd, "")
                output = ""

            elif ondevice is not None:
                agent         = "on_device"
                script_output = _execute_tracked_script(cmd, write_fn)
                if script_output is not None:
                    output, streamed = script_output, True
                else:
                    file_key  = cmd.strip()[2:].split()[0] if cmd.strip().startswith("./") else actual_cmd.split()[-1]
                    file_info = SYSTEM_STATE["files"].get(fs.resolve(file_key), {})
                    # Executing a path we do NOT track: hand it to Cowrie, which
                    # owns the real filesystem and therefore knows whether the
                    # file is there and whether it carries an exec bit. Asking
                    # the model instead made it guess, and a guess is not stable:
                    # the SAME command answered "Permission denied" once and
                    # "command not found" the next time — and both were wrong,
                    # because the file was /tmp/scanner.sh while the cwd was
                    # /tmp/tools, so the honest answer was "No such file or
                    # directory". A real shell never contradicts itself about
                    # its own filesystem, and contradiction is exactly what an
                    # attacker probes for.
                    if not file_info and (cmd.strip().startswith("./")
                                          or actual_base in ("bash", "sh")):
                        output, agent = _cowrie_send(actual_cmd, write_fn=write_fn)
                        streamed = True
                    elif file_info.get("content", "").startswith("[downloaded from"):
                        sys_p = (
                            f"You are a Linux terminal. The attacker ran: {cmd}\n"
                            f"This is a script downloaded from the internet. "
                            f"Simulate realistic terminal output as if it executed. "
                            f"3-6 lines max. No explanation, no markdown."
                        )
                        output = _llm_send(ondevice, sys_p, cmd, cmd=actual_cmd)
                    else:
                        extra = _cat_file_content_extra(actual_cmd, actual_base)
                        sys_p, usr_p = prompt_manager.build_prompt(actual_cmd)
                        if extra:
                            usr_p = usr_p + extra
                        output = _llm_send(ondevice, sys_p, usr_p, cmd=actual_cmd)
                link.sync_history(cmd)
                tracker.record(cmd, output)

            else:
                output, agent = _cowrie_send(cmd)
                tracker.record(cmd, output)

        else:  # agent == "cowrie"
            output, agent = _cowrie_send(cmd)
            tracker.record(cmd, output)

        if (agent == "cowrie" and not streamed
                and ("command not found" in (output or "") or "cannot execute binary file" in (output or ""))
                and sw.available(actual_base)
                and ondevice is not None):
            sys_p, usr_p = prompt_manager.build_prompt(actual_cmd)
            llm_out = _llm_send(ondevice, sys_p, usr_p, cmd=actual_cmd)
            if llm_out and "command not found" not in llm_out:
                output = llm_out
                agent  = "on_device"
                tracker.record(cmd, output)
        return _finish(cmd, agent, output, fi_score, t_start, streamed)

    handle.fi_manager = fi_manager
    handle.prompt_manager = prompt_manager
    return handle
