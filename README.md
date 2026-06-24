# JDY Botnet — Defensive Analysis

A complete defensive analysis of the **JDY botnet**: reverse engineering of the implant,
enumeration of its control infrastructure, three-tier intelligence reporting, deployable
detections, and a working tasking decryptor.

**JDY** is a China-nexus **reconnaissance** capability in the Volt Typhoon / KV-botnet
ecosystem (MITRE **G1017**). It fingerprints internet-exposed edge and SOHO devices at scale
and pivots to newly disclosed vulnerabilities within hours. It is the **targeting and
prepositioning layer** that makes follow-on intrusion fast — it does not itself exploit or
deploy ransomware.

**Classification:** TLP:CLEAR · ICD-203 estimative language · findings tagged **NOVEL / CORROBORATED / PUBLISHED / EXCLUDED**

---

## TL;DR — what this analysis established

- The implant is a **MIPS64 big-endian scanner** with **no exploit code** and **no hardcoded
  C2** (the control host is injected by the dropper).
- Its encrypted tasking was recovered at the instruction level: **base64 → AES-128-CBC → JSON**,
  key `bdb718bdf47cbcde`, IV `0x30`×16. The published "key" is **IV ∥ KEY**, not AES-256. A
  working decryptor is included.
- The control cluster is **deliberately atomized** — six independent hunts all bottomed out in
  commodity infrastructure. The relays are findable individually but **unlinkable to one
  another** in public data. The absence of a pivotable cluster **is** the finding.
- The durable anchors are the **jdyfj certificate**, the **implant hash**, and a **novel build
  path**. Everything else (relay IPs, web-stack versions) rotates or is commodity.

---

## Start here

| If you are a… | Read |
|---|---|
| **Reverse engineer** | [Reverse Engineering front door](docs/REVERSE_ENGINEERING.md) → the methodology and headline findings, linking the full teardown |
| **CISO / leadership** | [Strategic Intelligence Report](docs/STRATEGIC_INTELLIGENCE_REPORT.md) → business impact and decisions |
| **TI analyst / IR lead** | [Operational Intelligence Report](docs/OPERATIONAL_INTELLIGENCE_REPORT.md) → capability, kill-chain, ATT&CK |
| **SOC / hunter** | [Tactical Intelligence Report](docs/TACTICAL_INTELLIGENCE_REPORT.md) + [Threat Hunting Guide](docs/THREAT_HUNTING_GUIDE.md) |
| **Incident responder** | [Incident Response Playbook](docs/INCIDENT_RESPONSE_PLAYBOOK.md) |
| **Detection engineer** | [`detections/`](detections) → Sigma + YARA |

---

## Full navigation

### Reverse engineering
| Document | Contents |
|---|---|
| [REVERSE_ENGINEERING.md](docs/REVERSE_ENGINEERING.md) | RE front door — methodology, headline findings, links to the teardown |
| [TECHNICAL_WRITEUP.md](docs/TECHNICAL_WRITEUP.md) | The decryption chain: Ghidra anchors, the AES path, the AES-128-vs-256 resolution, key/IV recovery, endpoints |
| [IMPLANT_COMPONENTS_RE.md](docs/IMPLANT_COMPONENTS_RE.md) | Component teardown: `meth_*` transports, the scan engine, SYN/ICMP markers, `dmap`, build fingerprint |
| [CORRECTIONS_LOG.md](docs/CORRECTIONS_LOG.md) | Every claim reversed on the bench, with evidence and tags |

### Intelligence reporting
| Document | Audience |
|---|---|
| [STRATEGIC_INTELLIGENCE_REPORT.md](docs/STRATEGIC_INTELLIGENCE_REPORT.md) | CISO / leadership / risk |
| [OPERATIONAL_INTELLIGENCE_REPORT.md](docs/OPERATIONAL_INTELLIGENCE_REPORT.md) | TI analysts / IR |
| [TACTICAL_INTELLIGENCE_REPORT.md](docs/TACTICAL_INTELLIGENCE_REPORT.md) | SOC / hunt / detection |

### Operator guides
| Document | Use |
|---|---|
| [INCIDENT_RESPONSE_PLAYBOOK.md](docs/INCIDENT_RESPONSE_PLAYBOOK.md) | Triage → scope → contain → eradicate → recover, with decision trees |
| [THREAT_HUNTING_GUIDE.md](docs/THREAT_HUNTING_GUIDE.md) | Six hypothesis-driven hunts mapped to ATT&CK |

### Infrastructure and method
| Document | Contents |
|---|---|
| [INFRASTRUCTURE_ENUMERATION.md](docs/INFRASTRUCTURE_ENUMERATION.md) | The cluster, the pivots, the exclusions, the atomization finding |
| [NON_DISCRIMINATING_SELECTORS.md](docs/NON_DISCRIMINATING_SELECTORS.md) | Commodity selectors and their false-positive populations |
| [INVESTIGATION_METHODOLOGY.md](docs/INVESTIGATION_METHODOLOGY.md) | Posture, tagging, estimative language, tooling, limitations |

### Detections and IOCs
| Path | Contents |
|---|---|
| [detections/](detections) | Sigma rules (log-based) + YARA (sample clustering) + network/cert notes |
| [iocs/JDY_IOCs.md](iocs/JDY_IOCs.md) | Full IOC table with per-claim tags |
| [iocs/JDY_IOCs.csv](iocs/JDY_IOCs.csv) | Machine-readable IOCs |
| [tools/jdy_decrypt.py](tools/jdy_decrypt.py) | Tasking decryptor |

---

## Repository structure

```
jdy-botnet-analysis/
├── README.md                            # this file
├── docs/
│   ├── REVERSE_ENGINEERING.md           # RE front door
│   ├── TECHNICAL_WRITEUP.md             # decryption chain, key/IV recovery
│   ├── IMPLANT_COMPONENTS_RE.md         # transports, scan engine, dmap
│   ├── CORRECTIONS_LOG.md               # reversed claims, tagged
│   ├── STRATEGIC_INTELLIGENCE_REPORT.md
│   ├── OPERATIONAL_INTELLIGENCE_REPORT.md
│   ├── TACTICAL_INTELLIGENCE_REPORT.md
│   ├── INCIDENT_RESPONSE_PLAYBOOK.md
│   ├── THREAT_HUNTING_GUIDE.md
│   ├── INFRASTRUCTURE_ENUMERATION.md
│   ├── NON_DISCRIMINATING_SELECTORS.md
│   └── INVESTIGATION_METHODOLOGY.md
├── detections/
│   ├── README.md
│   ├── sigma/                           # 4 log-based rules
│   │   ├── jdy_jdyfj_certificate.yml
│   │   ├── jdy_dispatch_service_uri.yml
│   │   ├── jdy_cluster_outbound.yml
│   │   └── jdy_syn_recon_profile.yml
│   └── yara/
│       ├── jdy_mips64_implant_clustering.yar
│       └── jdy_network_cert_notes.md
├── iocs/
│   ├── JDY_IOCs.md
│   └── JDY_IOCs.csv
└── tools/
    └── jdy_decrypt.py
```

---

## Quick start — decrypt a tasking blob

The decryptor turns a captured `probe_task` body (base64) into the plaintext tasking JSON —
the IP ranges, ports, and CVE/fingerprint rules a bot was told to scan.

```bash
pip install pycryptodome

# verify the wiring (no input needed)
python3 tools/jdy_decrypt.py --selftest        # -> selftest: PASS

# see the targeting fields it extracts
python3 tools/jdy_decrypt.py --demo

# decrypt a captured base64 blob
python3 tools/jdy_decrypt.py captured_task.b64
```

If decryption fails the PKCS#7 check, the input is almost certainly **not the raw AES blob**
(HTTP framing left on it, or the wrong field captured) — re-extract the exact response body.
The cipher is correct; suspect the input.

---

## The one operating rule for everything here

**Never act on a single commodity selector.** JDY's relays sit on ordinary VPS hosting and
share infrastructure with tens of thousands of benign services. Any signal that is not the
**jdyfj certificate** or the **paired payload-host profile** must be combined with a second,
independent discriminator. A real JDY selector returns a handful of hosts; a commodity one
returns thousands. The false-positive populations are catalogued in
[NON_DISCRIMINATING_SELECTORS.md](docs/NON_DISCRIMINATING_SELECTORS.md).

---

## Key facts at a glance

| Item | Value |
|---|---|
| Implant | MIPS64 BE ELF, SHA-256 `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed` |
| Tasking crypto | base64 → AES-128-CBC → JSON; key `bdb718bdf47cbcde`; IV `0x30`×16 |
| Cluster anchor | jdyfj cert, serial `0xab8f51eb48f363f1`, CN=jdyfj, RSA-4096, to 2033-11-11 |
| Build fingerprint | `/usr/local/openssl/1.0.2u/mips64/` (nested form is the discriminator) |
| Scan markers | SYN sport 19000; ISN seed `0x3251d2d` (+1/target); ICMP id 19037, seq 36765 |
| Backend | nginx → Django (DRF), behind a Tor-hidden dispatch service |

---

*AI-assisted analysis throughout; all findings are leads for analyst reproduction. TLP:CLEAR.*
