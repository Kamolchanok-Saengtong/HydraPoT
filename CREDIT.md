## Threat Intelligence Source

HydraPoT implements a dedicated Threat Intelligence feature that leverages
established and trusted open-source cybersecurity resources to enhance its
attack analysis capabilities.

The feature integrates threat intelligence from **SigmaHQ, MISP, and MITRE**
to support attack pattern detection, MITRE ATT&CK technique identification,
IOC filtering, and security analytics evaluation.

### Threat Intelligence Sources

| Threat Intelligence Source | HydraPoT Implementation | Purpose | Local Path |
|---|---|---|---|
| **[SigmaHQ Rules](https://github.com/SigmaHQ/sigma)** | Sigma rule integration | Detects suspicious attack patterns and supports mapping observed attacker behavior to relevant techniques. | `threat_intel/rules/upstream/` |
| **[MISP Warninglists](https://github.com/MISP/misp-warninglists)** | IOC filtering | Identifies known benign or commonly observed indicators to reduce false positives during IOC extraction and analysis. | `threat_intel/.fp_cache/` |
| **[MITRE CAR Analytics](https://github.com/mitre-attack/car)** | Offline validation reference | Provides security analytics that support the evaluation and validation of HydraPoT's threat detection and technique-tagging results. | `threat_intel/.car_cache/` |
| **[MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data)** | ATT&CK metadata catalog | Provides standardized technique and tactic metadata used for threat analysis, classification, and reporting. | `threat_intel/mitre_catalog.json` |

### Attribution & Acknowledgements

The HydraPoT Threat Intelligence feature builds upon the valuable work of the
open-source cybersecurity community. We gratefully acknowledge and thank the
maintainers and contributors of the following projects for providing the
security resources used by HydraPoT:

- **SigmaHQ** — for the [Sigma](https://github.com/SigmaHQ/sigma) detection
  rule format and community-maintained detection rules.

- **MISP Project** — for the
  [MISP Warninglists](https://github.com/MISP/misp-warninglists), which help
  identify commonly observed or non-actionable indicators and reduce potential
  false positives.

- **MITRE** — for the
  [Cyber Analytics Repository (CAR)](https://github.com/mitre-attack/car),
  which provides security analytics used as a reference for evaluating
  defensive detection capabilities.

- **MITRE** — for the
  [ATT&CK STIX Data](https://github.com/mitre-attack/attack-stix-data),
  which provides structured MITRE ATT&CK knowledge used to construct
  HydraPoT's local technique catalog.

We sincerely thank the respective maintainers and contributors for making
these resources openly available to the cybersecurity community. Their work
provides an important foundation for HydraPoT's threat intelligence and
attack analysis capabilities.

> **Attribution Notice:** The original rules, analytics, datasets, and
> associated intellectual property remain with their respective authors,
> contributors, and organizations. HydraPoT does not claim ownership of these
> third-party resources, and their inclusion does not imply endorsement,
> affiliation, or ownership by HydraPoT. Please refer to each upstream
> repository for the applicable license, attribution requirements, and terms
> of use.