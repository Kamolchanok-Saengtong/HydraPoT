"""
nemo_config/actions.py — HydraPoT's custom NeMo action.

NeMo loads actions.py from the config directory, so this registers without
touching the installed nemoguardrails package. The check itself is ours and
lives in detector_arm/character_break.py; this file is only the adapter that
makes it callable from a Colang flow.
"""
import os
import sys
import time

from nemoguardrails.actions import action

_ARM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ARM not in sys.path:
    sys.path.insert(0, _ARM)


@action(name="CharacterBreakDetectionAction")
async def character_break_detection(context: dict = None, **kwargs) -> dict:
    """Is the user probing the system's identity rather than running a command?

    Returns NeMo's action shape -- {"is_blocked": bool, ...} -- so the flow
    looks like the jailbreak flows that ship with the library.
    """
    from character_break import check_character_break

    prompt = (context or {}).get("user_message") or ""
    threshold = float(os.environ.get("CHARACTER_BREAK_THRESHOLD", "0.5"))
    t0 = time.time()
    result = check_character_break(prompt, threshold=threshold)
    return {
        "is_blocked": bool(result["character_break"]),
        "score": float(result["score"]),
        "signals": result["signals"],
        "latency_ms": (time.time() - t0) * 1000.0,
    }
