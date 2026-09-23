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
| **[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)** | Ground truth for rule evaluation | Provides red-team test commands with a known technique label, used as independent ground truth when measuring the accuracy of HydraPoT's ATT&CK mapping. | fetched by `threat_intel/validate_rules.py` |
| **[IANA TLD List](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)** | Domain validation | Authoritative list of valid top-level domains, used to reject non-existent domains during IOC extraction. | `threat_intel/.fp_cache/tlds.txt` |


### Scope of Use

To make the boundary explicit, the following describes precisely how each
resource is used and what remains HydraPoT's own work.

**ATT&CK technique mapping**

| Component | Origin |
|---|---|
| 180 upstream detection rules (`threat_intel/rules/upstream/`) | SigmaHQ |
| 39 detection rules (`threat_intel/rules/local_custom/`) | **HydraPoT** — authored for this project, written in Sigma's schema. They are not SigmaHQ rules. |
| Two-tier resolution (upstream consulted first, local as fallback; `tag()` strict priority, `tag_all()` union) | **HydraPoT** |
| Technique IDs, names, tactics | MITRE ATT&CK |
| Accuracy measurement against labelled red-team commands | Atomic Red Team (ground truth) |
| Independent detection-theory cross-check | MITRE CAR — **validation only; CAR never produces a tag at runtime** |

**IOC extraction**

| Component | Origin |
|---|---|
| Observable patterns — URL, IPv4, IPv6, MD5/SHA1/SHA256, BTC/ETH/XMR wallet addresses, CVE, email, file paths | **HydraPoT** — the regex table in `threat_intel/ioc_extractor.py`. No external rule template is used for detection. |
| Extraction approach (a regex table per observable type) | Follows the design of Microsoft's [msticpy](https://github.com/microsoft/msticpy) `IoCExtract`. **msticpy is not a dependency and is not installed.** |
| False-positive suppression | MISP Warninglists + IANA TLD list |
| STIX 2.1 export (indicator, attack-pattern, identity, malware, relationship objects) | **HydraPoT** |

Only benign-listing sources are consulted. No external malicious-indicator
feed is used, so every positive detection produced by HydraPoT originates from
its own rules.

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

- **Red Canary** — for
  [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), whose
  labelled test commands make an independent, reproducible accuracy
  measurement of technique mapping possible.

- **IANA** — for the publicly maintained
  [TLD list](https://data.iana.org/TLD/tlds-alpha-by-domain.txt), used to
  validate extracted domain indicators.

- **Microsoft** — for [msticpy](https://github.com/microsoft/msticpy), whose
  `IoCExtract` informed the design of HydraPoT's IOC extraction. No msticpy
  code is used.

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