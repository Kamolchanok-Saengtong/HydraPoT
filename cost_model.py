"""
cost_model.py — what a command costs to answer, in electricity and in cloud fees.

Production module. The dashboard uses it live; the experiment sandbox imports
it too, so a measured constant is never written down in two places.

Why it exists
-------------
`GPU_AVG_WATT = 112.89` was hardcoded in BOTH dashboard.py and
experiment_data/PartC/cost_analysis.py. Two copies of one measured number is a
silent trap: re-measure it, update one, and the dashboard and the thesis figure
quietly disagree about the same GPU.

Both numbers below are measurements, not guesses, and both come from
config.yaml so a different deployment (different GPU, different cloud model)
can state its own without editing Python:

  gpu_avg_watt      average board draw while the on-device model is inferring.
                    Measured with measure.GPUPowerSampler over a calibration
                    batch — see experiment_data/PartC/estimate_electricity_bill.py.
                    On an RTX 4060 (driver 550.54.14) power.draw reports 'N/A'
                    even at full load, so the sampler falls back to a
                    utilization-scaled estimate. It is labelled that way in the
                    output and must not be cited as a hardware sensor reading.

  cloud_usd_per_cmd measured $ per cloud-routed command, from the Part C cloud
                    arm's own billing records.

Electricity is converted to baht by power_cost.kwh_to_thb(), which applies
Thailand's MEA/PEA progressive tariff (tiers + Ft + VAT) from config.yaml.
"""
from config_loader import load_config

# A single on-device inference cannot realistically exceed ~2 minutes of GPU
# time. Some log rows carry a corrupt latency_ms (e.g. 1.7e9 ms ~ 495 hours,
# from a bad t_start); left unclamped a handful of those dominate the whole
# energy sum — roughly 100x inflation. Cap each command's contribution.
LATENCY_CAP_MS = 120_000

_DEFAULTS = {
    "gpu_avg_watt":      112.89,
    "cloud_usd_per_cmd": 0.0301 / 67,
}


def _cfg(config=None) -> dict:
    cfg = config or load_config()
    raw = getattr(cfg, "cost_model", None) or {}
    return {k: raw.get(k, v) for k, v in _DEFAULTS.items()}


def energy_kwh(total_inference_ms: float, config=None) -> float:
    """kWh drawn by the on-device GPU for this much inference time."""
    watts = _cfg(config)["gpu_avg_watt"]
    hours = (total_inference_ms / 1000.0) / 3600.0
    return watts * hours / 1000.0


def energy_thb(total_inference_ms: float, config=None) -> float:
    """Electricity cost in baht for this much on-device inference."""
    from power_cost import kwh_to_thb
    cfg = config or load_config()
    return kwh_to_thb(energy_kwh(total_inference_ms, cfg), cfg.power_tariff)["total_thb"]


def cloud_usd(n_cloud_commands: int, config=None) -> float:
    """Cloud spend for this many cloud-routed commands."""
    return n_cloud_commands * _cfg(config)["cloud_usd_per_cmd"]


def gpu_avg_watt(config=None) -> float:
    return _cfg(config)["gpu_avg_watt"]


def cloud_usd_per_cmd(config=None) -> float:
    return _cfg(config)["cloud_usd_per_cmd"]
