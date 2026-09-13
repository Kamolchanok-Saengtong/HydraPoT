"""
SIEM/cost.py — dashboard-local cost/energy estimation.

This is NOT threat_intel/aggregator.py's real per-session cost (which reads
actual measured numbers from replay data). Production session logs record
`agent` + `latency_ms` per command, but NOT tokens/cost (cost capture is off
in the real run). So this module ESTIMATES, for the live dashboard:

  on-device electricity  — from the REAL logged latency_ms of on_device
    commands (GPU busy time) x measured avg draw, converted via config.yaml's
    MEA tariff. This is a genuine per-command estimate, not a flat guess.
  cloud cost             — logs have no token count, so this is (# cloud
    commands) x a per-cloud-command $ rate measured in Part C. Coarser, but
    the only signal available live. Both are clearly labelled "(est.)".

Numbers below come from Part C measurement (see experiment_data/PartC/results/…):
  avg GPU draw during on_device inference : 112.89 W  (utilization-scaled;
    this GPU's driver reports power.draw as N/A — see estimate_electricity_bill.py)
  avg cloud $ per cloud-routed command    : $0.0301 / 67 cmds ≈ $0.000449
Both measured values now come from cost_model.py (config.yaml), not from a
copy kept here. They used to be hardcoded in this file AND in the Part C
analysis script — two copies of one measurement, so re-measuring and updating
only one made the dashboard and the thesis figure disagree about the same GPU.
"""
try:
    import cost_model as _cost
    GPU_AVG_WATT             = _cost.gpu_avg_watt()
    CLOUD_COST_PER_CLOUD_CMD = _cost.cloud_usd_per_cmd()
except Exception:
    GPU_AVG_WATT             = 112.89
    CLOUD_COST_PER_CLOUD_CMD = 0.0301 / 67
# A single on_device inference can't realistically exceed ~2 min of GPU time.
# Some log records carry corrupt latency_ms (e.g. 1.7e9 ms ≈ 495 h — a bad
# t_start / timing artifact); left unclamped, a handful of these dominate the
# whole energy sum (~100x inflation). Cap each command's contribution here.
LATENCY_CAP_MS            = 120_000

try:
    # power_cost.py lives in the project root, NOT in the experiment sandbox.
    # It used to be imported by inserting experiment_data/PartA onto sys.path,
    # which made the production dashboard depend on the sandbox — so moving or
    # renaming the sandbox silently broke the cost panel. Production code must
    # not reach into experiment_data at all.
    from power_cost import kwh_to_thb as _kwh_to_thb
    from config_loader import load_config as _load_config
    _POWER_TARIFF = _load_config().power_tariff
except Exception:
    _kwh_to_thb = None
    _POWER_TARIFF = None


def estimate_savings(df):
    """What HydraPoT's routing saved, over the WHOLE visible dataset.

    Scoped to the WHOLE visible dataset on purpose. (An earlier month-scoped
    cost helper lived here; it was removed once the KPI strip stopped using it,
    because month-to-date reads as zero on historical data.) This is the
    research claim: every command answered by a cheaper agent is one an
    all-cloud honeypot would have paid for.

      cloud saved  — commands NOT sent to cloud x the same per-command rate
                     CLOUD_COST_PER_CLOUD_CMD, i.e. vs an all-cloud baseline.
      energy saved — commands answered by Cowrie (deterministic, no GPU) x the
                     measured average energy of an on-device command, i.e. vs
                     an all-LLM baseline.

    Both are estimates against an explicit baseline, not measured counterfactuals.
    """
    out = {"cloud_saved_usd": 0.0, "cloud_avoided_pct": 0.0,
           "energy_saved_thb": 0.0, "energy_avoided_pct": 0.0,
           "n_total": 0, "n_cloud": 0, "n_switches": 0}
    if df is None or df.empty or "agent" not in df.columns:
        return out

    n_total = len(df)
    n_cloud = int((df["agent"] == "cloud").sum())
    n_od    = int((df["agent"] == "on_device").sum())
    n_cow   = int((df["agent"] == "cowrie").sum())
    out.update(n_total=n_total, n_cloud=n_cloud)

    out["cloud_saved_usd"]   = (n_total - n_cloud) * CLOUD_COST_PER_CLOUD_CMD
    out["cloud_avoided_pct"] = (n_total - n_cloud) / n_total * 100.0

    # average energy of one on-device command, measured from real latency
    if n_od and "latency_ms" in df.columns:
        od_ms = float(df.loc[df["agent"] == "on_device", "latency_ms"]
                      .fillna(0).clip(upper=LATENCY_CAP_MS).sum())
        kwh_per_cmd = (GPU_AVG_WATT * (od_ms / 1000.0 / 3600.0) / 1000.0) / n_od
        if _kwh_to_thb and _POWER_TARIFF:
            out["energy_saved_thb"] = _kwh_to_thb(kwh_per_cmd * n_cow, _POWER_TARIFF)["total_thb"]
    if n_cow + n_od:
        out["energy_avoided_pct"] = n_cow / (n_cow + n_od) * 100.0

    # how often routing actually changed agent mid-session — the multi-agent
    # behaviour in one number
    if {"session_id", "seq"} <= set(df.columns):
        # one pass over the sorted arrays: a switch is "agent changed AND we are
        # still inside the same session". groupby().apply() ran a Python lambda
        # per session for the same answer.
        srt = df.sort_values(["session_id", "seq"])
        ag, sid = srt["agent"].to_numpy(), srt["session_id"].to_numpy()
        out["n_switches"] = int(((ag[1:] != ag[:-1]) & (sid[1:] == sid[:-1])).sum())
    return out
