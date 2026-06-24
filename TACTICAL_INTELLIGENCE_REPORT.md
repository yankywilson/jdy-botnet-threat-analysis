# Tactical Intelligence Report — JDY Botnet

**Audience:** SOC analysts, threat hunters, detection engineers, network defenders
**Hunt signals, IOCs, the decrypt command, triage discipline, and perimeter actions.**

**Classification:** TLP:CLEAR · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

> Companion documents: hypothesis-driven hunts in the [Threat Hunting Guide](THREAT_HUNTING_GUIDE.md);
> live-incident handling in the [Incident Response Playbook](INCIDENT_RESPONSE_PLAYBOOK.md);
> deployable rules in [`../detections/`](../detections); machine-readable IOCs in
> [`../iocs/JDY_IOCs.csv`](../iocs/JDY_IOCs.csv).

---

## 1. The one rule that governs everything here

**Never alert on a single commodity selector.** JDY's relays sit on ordinary VPS hosting and
share infrastructure with tens of thousands of benign services. Every selector below that is
not the **jdyfj cert** or the **paired payload-host profile** must be combined with a second
discriminator. The non-discriminating-selector catalog
([`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md)) lists the traps and
their false-positive populations (e.g. 63,870 / 88,452 / 2,369). A real JDY selector returns
a handful of hosts; a commodity one returns thousands.

---

## 2. High-confidence hunt signals (host/identity)

These are strong on their own.

| Signal | Detail | Confidence |
|---|---|---|
| **jdyfj TLS certificate** | SHA-256 `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf`; serial `0xab8f51eb48f363f1`; CN=jdyfj, SAN=1.2.3.4, RSA-4096, to 2033-11-11 | **High** — cluster identity anchor |
| **Implant hash** | `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed` (MIPS64 BE ELF) | **High** |
| **Build path** in a sample | `/usr/local/openssl/1.0.2u/mips64/` (nested form) | **High** for clustering — zero public matches |
| **Paired payload-host profile** | Platypus :13339 **and** Acme Co Go-TLS :9960-9964 on the same host | **High** when paired; each alone is commodity |

---

## 3. Behavioral hunt signals (network)

Strong **in combination**; weak alone.

### 3.1 Outbound scanning profile (JDY bot is the source)

- **SYN source port 19000** with **no payload**, **plus**
- an **ascending ISN run seeded at `0x3251d2d`** (≈ 52,696,877) — the first SYN of a batch
  carries the seed exactly; subsequent SYNs increment by 1.

A normal OS randomizes the ISN per connection. A run of SYNs from source port 19000 whose
sequence numbers climb monotonically from a fixed low seed is the discriminator. **Source
port 19000 alone is not** — it overlaps Mirai-class and SSH brute-force scanners.

### 3.2 ICMP probe markers

- ICMP echo **id 19037** (`0x4a5d`) and **sequence 36765** (`0x8f9d`), on the port-80 scan
  path. (Note: published reporting lists sequence 35765; this sample uses 36765 — treat both
  as candidate variants.)

### 3.3 Dispatch traffic (JDY bot to relay)

- HTTPS to a relay whose cert is **jdyfj**, with URIs under **`/dispatch_service/v2/`**:
  `probe_task` (pull tasking), `probe_status` (submit results), `test` (liveness), and
  `/dispatch/v2/dmap/<digest>` (fingerprint-DB fetch).
- The relay fronts (nginx) a **Django (DRF)** backend; an unauthenticated probe to
  `/dispatch_service/v2/test` returns `{"code": 200}`, and malformed requests surface Django's
  `Server Error (500)` HTML.

---

## 4. IOC quick reference

Full table with first/last-seen and per-claim tags: [`../iocs/JDY_IOCs.md`](../iocs/JDY_IOCs.md).
Machine-readable: [`../iocs/JDY_IOCs.csv`](../iocs/JDY_IOCs.csv).

**Relays / control IPs**
```
216.173.65.250    relay (Evoxt)       live, jdyfj cert, nginx 1.20.1, :10000 3X-UI, h04.zova.cc
194.14.217.88     relay (M247 RO)     live, nginx 1.14.1
23.27.120.240     relay (Evoxt)
109.104.154.116   relay (BrainStorm NL)
140.82.23.123     historical anchor (Vultr -> Cloudflare), 2023 lineage
149.248.3.38      payload host (Vultr LA), Platypus :13339, Acme Co :9960-9964
```

**Certificate**
```
jdyfj  SHA-256 2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf
       serial  0xab8f51eb48f363f1   CN=jdyfj  SAN=1.2.3.4  RSA-4096  valid->2033-11-11
```

**Sample**
```
SHA-256 40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed  (MIPS64 BE ELF)
build path  /usr/local/openssl/1.0.2u/mips64/    version 1.8.3.9
```

**Tasking crypto**
```
base64 -> AES-128-CBC -> JSON
key bdb718bdf47cbcde (16 ASCII bytes, raw)   IV 0x30 x 16
published "key" 0000000000000000bdb718bdf47cbcde = IV || KEY  (not AES-256)
```

**Endpoints**
```
POST /dispatch_service/v2/probe_task     pull tasking
POST /dispatch_service/v2/probe_status   submit results          (NOVEL)
POST /dispatch_service/v2/test           liveness stub           (NOVEL)
     /dispatch/v2/dmap/<digest>          fingerprint-DB fetch
```

---

## 5. Decrypt a captured tasking blob

If you capture a `probe_task` / `content` response body (base64 text), decrypt it offline:

```bash
python3 tools/jdy_decrypt.py task.b64
```

Output is the plaintext tasking JSON — the target IP ranges, ports, and CVE/fingerprint rules
the bot was pointed at. Verify the tool first with `python3 tools/jdy_decrypt.py --selftest`.

If decryption fails the PKCS#7 check, the input is most likely **not the raw AES blob** (HTTP
framing or a wrong field captured), not a wrong cipher — re-extract the exact response body.

---

## 6. Triage discipline — is this JDY or commodity noise?

A short gate to run before you escalate. Score against the cluster signature, not adjacency.

1. **Does it carry the jdyfj cert, or the paired payload-host profile?** If yes -> strong JDY.
   If no -> keep going, do not promote yet.
2. **Is there a second, independent discriminator?** Behavioral (seeded-ISN SYN run) +
   identity (cert) or build-path is promotable. A single commodity selector is not.
3. **Check the false-positive population.** If the selector you matched returns thousands of
   hosts (see the catalog), it is commodity by definition — down-weight to EXCLUDED.
4. **Architecture sanity.** A Windows PE "relation" cannot be a JDY sibling — the implant is
   MIPS64 BE. Sandbox "contacted IPs" from an x86 detonation are host telemetry, not C2.
5. **Co-tenancy caution.** Large shared providers (M247, Vultr, Evoxt) produce coincidental
   overlaps. A shared ASN or prefix is not promotion.

---

## 7. Perimeter actions

Defensive, low-regret steps for network defenders:

- **Inventory and harden internet-facing edge devices** (routers, firewalls, VPN
  concentrators, IoT). Retire end-of-life devices; they are the actor's preferred real estate.
- **Compress emergency-patch latency** on perimeter devices — the scan-to-CVE window is hours.
- **Enable and retain egress logging** (NetFlow / firewall / Zeek) at the perimeter; the
  detectable signal is outbound.
- **Watchlist the cluster IPs and the jdyfj cert** for egress matches — but treat IP hits as
  leads (relays rotate), and prioritize the cert and behavioral signals.
- **Deploy the detection content** in [`../detections/`](../detections) (Sigma + YARA),
  tuning the paired-selector logic to your environment to avoid the commodity false positives.

---

## 8. What not to do

- **Do not block on bare commodity selectors** (source port 19000 alone, "Acme Co" alone,
  Platypus :13339 alone, a JARM on a common nginx stack). You will drown in false positives.
- **Do not treat IP blocklists as the control** — the relay layer is disposable.
- **Do not engage the live infrastructure.** This is a passive-defense posture; investigation
  is read-only against scan data and your own logs.

---

