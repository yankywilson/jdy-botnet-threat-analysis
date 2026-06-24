# Operational Intelligence Report — JDY Botnet

**Audience:** threat-intelligence analysts, incident responders, detection leads
**Capability profile, kill-chain, collection guidance, and ATT&CK mapping.**

**Classification:** TLP:CLEAR · ICD-203 estimative language · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

---

## 1. Capability profile

JDY is a **reconnaissance and fingerprinting botnet** with centralized, encrypted tasking.
The implant is a scanner, not an exploit framework.

| Attribute | Detail | Tag |
|---|---|---|
| Lineage | China-nexus, Volt Typhoon / KV-botnet (MITRE G1017) | PUBLISHED |
| Primary implant | MIPS64 big-endian ELF (`tz.tar.gz`, ~3 MB) | CORROBORATED |
| Target estate | Internet-exposed edge / SOHO devices (routers, firewalls, IoT) | PUBLISHED |
| Function | SYN scanning, banner grabbing, service fingerprinting | CORROBORATED |
| Exploitation | **None in the implant** — recon only | CORROBORATED |
| Tasking | Pulled from a Tor-hidden dispatch service | PUBLISHED |
| Tasking crypto | base64 → AES-128-CBC → JSON (key `bdb718bdf47cbcde`, IV `0x30`×16) | **NOVEL** |
| C2 in binary | None — supplied by dropper (`-s <web_ip>`) | CORROBORATED |
| Central updates | `dmap` digest-gated fingerprint-DB push | NOVEL (mechanism) |
| Tooling preference | Platypus/Termite (Chinese open-source session manager) on the payload host | PUBLISHED |

---

## 2. Architecture

JDY runs a **two-layer** control architecture:

**Victim layer (where the stealth lives).** Compromised edge / SOHO devices run the implant
using living-off-the-land techniques. This is the hard-to-find layer; prepositioning is
designed to be quiet and persistent.

**Control layer (deliberately disposable).** Rented commodity VPS nodes act as **relays** in
front of a **Tor-hidden dispatch service**, plus a separate **payload/tasking host**. The
relays carry the `jdyfj` self-signed TLS certificate — the one durable cluster anchor — and
reverse-proxy (nginx) to a Python **Django (DRF)** backend. The dispatch logic itself is Tor-
hidden, so the relays are fronts, not the brain.

```
[compromised edge device: JDY implant]
        | outbound, dropper-supplied -s <web_ip>
        v
[relay VPS: nginx + jdyfj cert]  --reverse proxy-->  [Tor-hidden dispatch (Django/DRF)]
        |
        +-- pulls encrypted tasking (probe_task), submits results (probe_status)
        +-- fetches fingerprint DB (dmap, digest-gated)
[separate payload host: Platypus :13339 + Acme Co Go-TLS :9960-9964]
```

---

## 3. Operational kill-chain

JDY occupies the **reconnaissance and resource-development** phases and stages access for
later actors.

1. **Resource development.** Operators rent disposable VPS relays, provision each
   independently (unique SSH host keys per box), and stand up the Tor-hidden dispatch service.
2. **Initial access (victim layer).** Edge / SOHO devices are compromised (vectors largely
   outside this implant's scope) and the implant is dropped, with the C2 host injected via
   `-s <web_ip>`.
3. **Tasking.** The implant beacons to a relay, pulls an encrypted `probe_task`, decrypts it
   (base64 → AES-128-CBC → JSON), and obtains target ranges, ports, and CVE/fingerprint rules.
4. **Reconnaissance.** It performs SYN scans (source port 19000, seeded ISN), ICMP probes,
   banner grabs, and service fingerprinting against the assigned targets.
5. **Reporting.** Results are submitted to `probe_status`; the fingerprint DB is refreshed via
   `dmap` when its digest changes.
6. **Hand-off.** The targeting data enables rapid follow-on exploitation by the broader
   ecosystem (a separate step, not performed by this implant).

---

## 4. Rapid-CVE pivoting

JDY's defining operational behavior is **speed**. It scans for newly disclosed
vulnerabilities within hours of disclosure — for example, FortiClient EMS CVE-2026-35616 was
scanned for within hours of going public. The `dmap` mechanism is the enabler: operators push
an updated fingerprint database to the whole fleet centrally, so the bots can recognize and
report a new vulnerable service without any implant redeployment.

**Important disambiguation.** JDY *scans* for CVE-2026-35616; it does **not** exploit it. The
public exploitation campaign on that CVE (the EKZ Infostealer, delivered to Windows hosts) is
a **separate criminal actor** sharing interest in the same CVE. Do not conflate the two — see
[`CORRECTIONS_LOG.md`](CORRECTIONS_LOG.md) (C6).

---

## 5. Infrastructure (operational reference)

The enumerated control cluster. Full detail, pivots, and exclusions are in
[`INFRASTRUCTURE_ENUMERATION.md`](INFRASTRUCTURE_ENUMERATION.md); machine-readable IOCs are in
[`../iocs/JDY_IOCs.csv`](../iocs/JDY_IOCs.csv).

| Host | Role | Provider / AS | Status |
|---|---|---|---|
| `216.173.65.250` | Relay | Evoxt / AS149440 | CORROBORATED, live. nginx 1.20.1; serves jdyfj cert; also runs a 3X-UI panel on :10000; fronted as `h04.zova.cc` |
| `194.14.217.88` | Relay | M247 RO / AS9009 | CORROBORATED, live. nginx 1.14.1 |
| `23.27.120.240` | Relay | Evoxt | CORROBORATED |
| `109.104.154.116` | Relay | BrainStorm NL | CORROBORATED |
| `140.82.23.123` | Historical anchor | Vultr (rotated to Cloudflare) | CORROBORATED, 2023 lineage |
| `149.248.3.38` | Payload / tasking host | Vultr LA | CORROBORATED. Platypus :13339; Acme Co Go-TLS :9960-9964 |

**Cluster anchor — the jdyfj certificate:**
- SHA-256 `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf`
- Serial `0xab8f51eb48f363f1` (= 12362189573138375665)
- CN=jdyfj, SAN=1.2.3.4, RSA-4096, valid to 2033-11-11; RDN C=en/ST=rg/L=df/O=vb/OU=ty/CN=jdyfj

**Promotion rule.** A candidate host is JDY-relevant **only** if it carries the cluster
signature — the **jdyfj cert** or the **payload-host profile (Platypus :13339 + Acme Co
Go-TLS :9960-9964 together)** — verified against stored scanner data. Graph adjacency, a
shared provider, or any single common selector is **not** sufficient for promotion.

---

## 6. Collection guidance

**Highest-value collection is on your own egress and edge.** Network indicators for this
actor rotate; technique and behavior persist.

| Collection source | What to gather | Why |
|---|---|---|
| Perimeter NetFlow / firewall egress | Outbound sessions from edge devices to commodity VPS, especially the cluster IPs | The detectable beacon |
| Zeek / IDS at the egress | SYN-scan profile (sport 19000, seeded ISN), `dispatch_service/v2/*` URIs, the jdyfj cert | Behavior + identity anchor |
| Edge-device inventory | Every internet-facing router/firewall/VPN/IoT, firmware level, support status | The attack surface |
| TLS-certificate monitoring | The jdyfj cert across providers (passive DNS, cert-transparency, internet scan platforms) | Cluster tracking |
| Sample feeds | New MIPS BE ELF samples carrying the build path `/usr/local/openssl/1.0.2u/mips64/` | Variant discovery |

---

## 7. ATT&CK mapping

JDY is catalogued under **G1017** (Volt Typhoon). Implant- and campaign-level behaviors
observed in this investigation:

| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance | Active Scanning (T1595) — IP block / port scanning | SYN engine, sport 19000, seeded ISN |
| Reconnaissance | Active Scanning: Vulnerability Scanning (T1595.002) | dmap fingerprint DB; rapid-CVE scanning |
| Resource Development | Acquire Infrastructure (T1583) — disposable VPS relays | Independently provisioned relay cluster |
| Resource Development | Compromise Infrastructure (T1584) — edge/SOHO victim layer | LOTL prepositioning on edge devices |
| Command and Control | Application Layer Protocol: Web (T1071.001) — HTTPS dispatch | `dispatch_service/v2/*` over TLS |
| Command and Control | Proxy / Multi-hop (T1090) — relay in front of Tor-hidden dispatch | Two-layer relay architecture |
| Command and Control | Encrypted Channel: Symmetric (T1573.001) — AES-128-CBC tasking | Recovered crypto scheme |
| Collection | Automated Collection (T1119) — fingerprint results | `probe_status`, `banner_list` |

(Technique IDs are provided as a mapping aid; validate against your ATT&CK version.)

---

## 8. Intelligence gaps

- **dmap record format** — the fingerprint-DB archive structure is not mapped (needs a captured
  archive).
- **Initial-access vectors** at the victim layer — largely outside this implant's scope; not
  characterized here.
- **Operator-to-relay management plane** — the Tor-hidden dispatch logic is not directly
  observable.
- **Sibling samples** — none surfaced on public platforms during this investigation; a build-
  path corpus retrohunt is the remaining untried discovery path.

---

