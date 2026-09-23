"""
threat_intel/sweeper.py — run the analysis on a timer, for a headless sensor.

    correlation -> detection -> severity -> alert_records

MINUTES, NOT SECONDS. Correlation needs a WINDOW of sessions to find anything,
so running this per command would burn CPU to discover nothing. The dashboard
triggers the same pipeline whenever it renders, so an operator with a browser
open sees findings sooner than this interval.

DAEMON THREAD. A slow Slack POST or an unreachable collector must never block an
attacker's session response, and the sweep must not keep the process alive at
shutdown. Failures are logged and the loop continues: losing one sweep is
recoverable, dying is not.

Lived in main.py, which is why it is here now -- main.py should show what is
wired together, not carry the alerting loop itself.
"""
import threading
import time

SWEEP_INTERVAL_SEC = 300

_started = False
# Loaded once, lazily. False is a sentinel meaning "tried and failed, do not
# retry". Distinct from alert_records, which owns the alert RECORD lifecycle
# (new/acknowledged/closed); AlertManager only DELIVERS.
_alert_manager = None


def get_alert_manager():
    global _alert_manager
    if _alert_manager is None:
        try:
            from threat_intel.alert_channels import AlertManager
            _alert_manager = AlertManager()
        except Exception as e:
            print(f"[alert] alerting unavailable: {e}")
            _alert_manager = False
    return _alert_manager or None


def start(config, plugins=None, interval=SWEEP_INTERVAL_SEC):
    """Start the sweep thread. Idempotent -- a second call is a no-op."""
    global _started
    if _started:
        return
    _started = True

    def _loop():
        import storage
        from threat_intel import alert_records
        while True:
            time.sleep(interval)
            inst = getattr(getattr(config, "honeypot", None),
                           "instance_name", "default")
            try:
                # exclude_row is the caller's policy for what counts as real
                # traffic. Not passing it meant a headless sensor could raise
                # alerts off its own replay runs -- latent so far only because
                # the dashboard, which does filter, has been doing the raising.
                out = alert_records.sweep(instance=inst, plugins=plugins,
                                          exclude_row=storage.is_experiment_row)
                if out["new"]:
                    print(f"[alert] {len(out['new'])} new finding(s) raised")
                # Heartbeat. The API runs in a different process and cannot
                # see this thread, so a sweeper that died is indistinguishable
                # from one that found nothing -- unless it says so here.
                storage.record_health(
                    "sweeper", True, f"{len(out['new'])} new", instance=inst)
            except Exception as e:
                print(f"[alert] sweep failed: {e}")
                storage.record_health(
                    "sweeper", False, f"{type(e).__name__}: {e}", instance=inst)

    threading.Thread(target=_loop, name="hp-alert-sweep", daemon=True).start()
