"""
power_cost.py — kWh -> THB conversion via Thailand's MEA/PEA
residential tariff (ประเภท 1.2).
─────────────────────────────────────────────────────────────────
Progressive tier pricing + Ft surcharge + VAT, matching how a real MEA/PEA
household electricity bill is actually calculated. Nothing here is hardcoded
— tiers, Ft, and VAT all come from config.yaml's power_tariff section, since
Ft changes every 4 months and tiers are occasionally revised by the ERC
(สำนักงานคณะกรรมการกำกับกิจการพลังงาน).

Source/citation for the thesis:
  การไฟฟ้านครหลวง (MEA) — https://www.mea.or.th/our-services/mea-service/e-service/electric-monthly-calculate
  Rates set by สำนักงานคณะกรรมการกำกับกิจการพลังงาน (กกพ./ERC).
  VERIFY current tier rates + Ft against the MEA link above before citing in
  the thesis — this file only applies whatever config.yaml says, it does not
  fetch or validate rates itself.
─────────────────────────────────────────────────────────────────
"""


def kwh_to_thb(kwh: float, tariff_cfg: dict) -> dict:
    """
    tariff_cfg (from config.yaml's power_tariff section):
      {
        "tiers": [
          {"max_units": 15,  "rate_thb_per_unit": 2.3488},
          {"max_units": 150, "rate_thb_per_unit": 3.2484},
          {"max_units": 400, "rate_thb_per_unit": 4.2218},
          {"max_units": null,"rate_thb_per_unit": 4.4217},
        ],
        "ft_surcharge_thb_per_unit": 0.1623,
        "vat_rate": 0.07,
      }
    "units" = kWh, 1:1 (this is how MEA bills define a unit).

    Returns: {
      "kwh": ..., "energy_charge_thb": ..., "ft_charge_thb": ...,
      "subtotal_thb": ..., "vat_thb": ..., "total_thb": ...,
      "tier_breakdown": [(units_in_tier, rate, charge), ...],
    }
    """
    tiers = tariff_cfg["tiers"]
    ft_rate = tariff_cfg["ft_surcharge_thb_per_unit"]
    vat_rate = tariff_cfg["vat_rate"]

    remaining = kwh
    prev_cap = 0.0
    energy_charge = 0.0
    breakdown = []

    for tier in tiers:
        cap = tier["max_units"]
        rate = tier["rate_thb_per_unit"]
        tier_size = (cap - prev_cap) if cap is not None else remaining
        units_in_tier = min(remaining, tier_size) if remaining > 0 else 0.0
        units_in_tier = max(units_in_tier, 0.0)
        charge = units_in_tier * rate
        if units_in_tier > 0:
            breakdown.append((round(units_in_tier, 6), rate, round(charge, 6)))
        energy_charge += charge
        remaining -= units_in_tier
        prev_cap = cap if cap is not None else prev_cap
        if remaining <= 0:
            break

    ft_charge = kwh * ft_rate
    subtotal = energy_charge + ft_charge
    vat = subtotal * vat_rate
    total = subtotal + vat
    print("finish")

    return {
        "kwh": round(kwh, 6),
        "energy_charge_thb": round(energy_charge, 4),
        "ft_charge_thb": round(ft_charge, 4),
        "subtotal_thb": round(subtotal, 4),
        "vat_thb": round(vat, 4),
        "total_thb": round(total, 4),
        "tier_breakdown": breakdown,
    }

if __name__ == "__main__":
    import argparse
    import yaml  # pip install pyyaml, if not already installed

    ap = argparse.ArgumentParser(description="Convert kWh to THB using MEA/PEA tariff.")
    ap.add_argument("kwh", type=float, help="Energy used, in kWh")
    ap.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    args = ap.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    tariff_cfg = cfg["power_tariff"]
    result = kwh_to_thb(args.kwh, tariff_cfg)

    print(f"kWh:            {result['kwh']}")
    print(f"Energy charge:  {result['energy_charge_thb']} THB")
    print(f"Ft charge:      {result['ft_charge_thb']} THB")
    print(f"Subtotal:       {result['subtotal_thb']} THB")
    print(f"VAT (7%):       {result['vat_thb']} THB")
    print(f"Total:          {result['total_thb']} THB")
    print()
    print("Tier breakdown (units, rate/unit, charge):")
    for units, rate, charge in result["tier_breakdown"]:
        print(f"  {units:>10.4f} kWh × {rate:.4f} THB = {charge:.4f} THB")