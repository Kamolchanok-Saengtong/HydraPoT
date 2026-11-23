"""
guardrail/detector_arm/ -- the shipped detector: NeMo Guardrails.

`character_break.py` is NeMo's fallback on a machine without `nemoguardrails`
installed (same verdicts, see nemo.py). The detectors that were compared against NeMo
are in experiment_data/guardrail/arms/.
"""
from guardrail.detector_arm import nemo

NAME = nemo.NAME


def build(cfg: dict = None):
    return nemo.build(cfg or {})
