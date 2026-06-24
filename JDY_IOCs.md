# JDY Botnet — Indicators of Compromise

Consolidated IOCs for the JDY botnet, with per-claim tags and context. Machine-readable
version: [`JDY_IOCs.csv`](JDY_IOCs.csv).

**Classification:** TLP:CLEAR · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

**Handling note.** Network indicators rotate — treat IPs as leads, not durable blocks. The
**jdyfj certificate**, the **implant hash**, and the **build path** are the durable anchors.
Apply the promotion rule (jdyfj cert or paired payload-host profile) before acting on any
candidate host.

---

## Files / samples

| Indicator | Type | Context | Tag |
|---|---|---|---|
| `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed` | SHA-256 | Primary JDY implant, MIPS64 BE ELF (`tz.tar.gz`, ~3 MB) | CORROBORATED |

## Control infrastructure (IPs)

| Indicator | Role | Provider / AS | Tag |
|---|---|---|---|
| `216.173.65.250` | Relay (live) | Evoxt / AS149440 | CORROBORATED |
| `194.14.217.88` | Relay (live) | M247 RO / AS9009 | CORROBORATED |
| `23.27.120.240` | Relay | Evoxt | CORROBORATED |
| `109.104.154.116` | Relay | BrainStorm NL | CORROBORATED |
| `140.82.23.123` | Historical anchor (2023 lineage) | Vultr -> Cloudflare | CORROBORATED |
| `149.248.3.38` | Payload / tasking host | Vultr LA | CORROBORATED |

## Certificate

| Field | Value |
|---|---|
| SHA-256 | `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf` |
| Serial | `0xab8f51eb48f363f1` (= 12362189573138375665) |
| Subject | CN=jdyfj (RDN C=en, ST=rg, L=df, O=vb, OU=ty) |
| SAN | `1.2.3.4` |
| Key / validity | RSA-4096, valid to 2033-11-11 |
| Tag | CORROBORATED (cluster anchor) |

## SSH host key

| Indicator | Context | Tag |
|---|---|---|
| `51:d6:bd:be:10:e9:45:a8:c7:cb:79:a7:73:59:93:ef` | Unique per box (independent provisioning) | CORROBORATED |

## Host artifacts / build fingerprint

| Indicator | Type | Context | Tag |
|---|---|---|---|
| `/usr/local/openssl/1.0.2u/mips64/` | Build path | Nested install prefix; clustering selector | **NOVEL** |
| `1.8.3.9` | Version string | Supporting selector | NOVEL |

## Network markers (behavioral)

| Indicator | Context | Tag |
|---|---|---|
| SYN source port `19000` | Scan engine; pair with seeded ISN | CORROBORATED |
| SYN ISN seed `0x3251d2d` (+1 per target) | The discriminating part of the SYN profile | **NOVEL** |
| ICMP echo id `19037` (`0x4a5d`) | Port-80 scan path | CORROBORATED |
| ICMP echo sequence `36765` (`0x8f9d`) | This sample (published variant: 35765) | **NOVEL** |

## Dispatch endpoints

| Indicator | Role | Tag |
|---|---|---|
| `POST /dispatch_service/v2/probe_task` | Pull tasking | PUBLISHED |
| `POST /dispatch_service/v2/probe_status` | Submit results | **NOVEL** |
| `POST /dispatch_service/v2/test` | Liveness stub (`{"code": 200}`) | **NOVEL** |
| `/dispatch/v2/dmap/<digest>` | Fingerprint-DB fetch | CORROBORATED |
| `/data/v2/pscan`, `/wscan` | Strategy endpoints | CORROBORATED |

## Payload-host service profile (paired)

| Indicator | Context | Tag |
|---|---|---|
| Platypus on port `13339` | Pair with the Acme Co block | CORROBORATED (paired) |
| Acme Co Go-TLS on ports `9960-9964` | Go default test cert; pair with Platypus | CORROBORATED (paired) |

## Tasking cryptography

| Element | Value |
|---|---|
| Scheme | base64 -> AES-128-CBC -> JSON |
| Key | `bdb718bdf47cbcde` (16 ASCII bytes, raw) |
| IV | `0x30` x 16 |
| Published "key" clarification | `0000000000000000bdb718bdf47cbcde` = IV \|\| KEY (not AES-256) |
| Tag | **NOVEL** (recovered by RE) |

---

## Excluded indicators (do NOT label as JDY)

These surfaced during investigation and were ruled out with primary evidence. Labeling them
JDY would mislabel co-residency noise. Full reasoning in
[`INFRASTRUCTURE_ENUMERATION.md`](../docs/INFRASTRUCTURE_ENUMERATION.md).

| Item | Why excluded |
|---|---|
| `185.212.44.147` | MikroTik L2TP VPN — graph adjacency only |
| `47.239.105.221` | Finstars fintech agent API |
| `162.159.36.2` | Cloudflare co-hosting fan-out |
| `nebodune.com` | Russian C2 of a NetSupport RAT co-tenant |
| `prueba.txt` (`2e971ebfcae02acfd9913736426040c6ad211533afb3e0b090e7e20dbecf69b3`) | Third-party researcher artifact |
| Cobalt Strike watermark `987654321` | Trivial sequential default riding crimeware |
| 8 peexe + 1 pedll VT relations | Windows PE — cannot be JDY siblings (implant is MIPS64 BE) |
| EKZ Infostealer (CVE-2026-35616 campaign) | Separate Windows-targeting actor; JDY only scans the CVE |

---

