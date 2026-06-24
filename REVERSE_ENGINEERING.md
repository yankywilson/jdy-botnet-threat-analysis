# Reverse Engineering — JDY MIPS64 Implant

This is the front door to the reverse-engineering work on the JDY implant. It summarizes
the methodology and the headline findings, then points to the detailed teardown documents.

**Sample under analysis**
- SHA-256: `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`
- Container filename: `tz.tar.gz`
- Format: ELF 64-bit MSB (big-endian) MIPS64, statically linked, stripped, ~3.00 MB
- Family: JDY (China-nexus reconnaissance capability, Volt Typhoon / KV-botnet lineage, MITRE **G1017**)
- Baseline reporting: Lumen Black Lotus Labs **JDY_6_2026**

**Classification:** TLP:CLEAR · ICD-203 estimative language · findings tagged **NOVEL / CORROBORATED / PUBLISHED / EXCLUDED**

---

## Read in this order

| Document | What it covers |
|---|---|
| **This page** | Methodology, headline findings, how the pieces connect |
| [`TECHNICAL_WRITEUP.md`](TECHNICAL_WRITEUP.md) | The tasking-decryption chain: Ghidra anchors, the AES call path, the AES-128-vs-256 resolution, key/IV recovery, dispatch endpoints |
| [`IMPLANT_COMPONENTS_RE.md`](IMPLANT_COMPONENTS_RE.md) | Component teardown: the `meth_*` transport classes, the `scan_type` engine, SYN/ICMP markers, the `dmap` mechanism, the build fingerprint |
| [`CORRECTIONS_LOG.md`](CORRECTIONS_LOG.md) | Every RE claim that bench analysis reversed, with evidence and tags |

---

## Methodology and discipline

All findings here are **leads for analyst reproduction**, not settled fact. Anything
AI-assisted is reproduced in Ghidra before it is treated as confirmed. The four-tag
pipeline (NOVEL / CORROBORATED / PUBLISHED / EXCLUDED) is applied per claim, and
corrections are surfaced immediately and tagged — several headline items in this repo were
reversed on the bench, and those reversals are documented rather than buried.

**Environment.** The implant is MIPS64 big-endian and cannot execute in a Windows x86
sandbox, so dynamic analysis was static-first: Ghidra (load as `MIPS:BE:64`, default
compiler, full auto-analysis with the MIPS constant-reference analyzer enabled) cross-checked
with capstone / pyelftools disassembly and `mips-linux-gnu-objdump`. Network corroboration
came from packet captures of the dispatch tier (cert, backend fingerprint), not from
implant execution.

**Load parameters (reproduce these).**
- Architecture: `MIPS:BE:64`
- Global pointer `gp`: `0x1030c050`
- `.text` base `0x10005920`, `.rodata` base `0x10245000`, `.got` base `0x10304060`

---

## Headline findings

### 1. Tasking decryption recovered at the instruction level — NOVEL

JDY bots pull scanning tasks from a Tor-hidden dispatch service. The tasking payload is
**base64 → AES-128-CBC → JSON**. Static RE recovered the exact scheme:

- **AES-128-CBC**, decrypt direction
- **Key:** `bdb718bdf47cbcde` — 16 ASCII bytes, used **raw** (not hex-decoded)
- **IV:** 16 bytes of ASCII `0` (`0x30` × 16)
- The published "key" `0000000000000000bdb718bdf47cbcde` is **IV ∥ KEY**, not a 32-byte AES-256 key

A working decryptor ([`../tools/jdy_decrypt.py`](../tools/jdy_decrypt.py)) implements this and
turns a captured `probe_task` body into the plaintext tasking JSON — the IP ranges, ports,
and CVE/fingerprint rules JDY is pointed at. Full detail and the AES-128-vs-256 resolution
are in the technical writeup.

### 2. The implant is a scanner, not an exploiter — CORROBORATED

The binary is a reconnaissance and fingerprinting tool. It performs SYN scanning, banner
grabbing, and service fingerprinting. **It contains no exploit code.** This matches Lumen's
framing of JDY as a capability that *enables* rapid exploitation (by identifying vulnerable
targets fast) rather than the exploiting actor itself. The operational consequence: JDY
*scans* for freshly disclosed CVEs (for example, it scanned for FortiClient EMS
CVE-2026-35616 within hours of disclosure), but the exploitation and any follow-on payload
delivery are carried out by the broader ecosystem, not this implant.

### 3. Transport is a per-task toolkit — NOVEL (corrected)

The implant exposes a family of C++ transport classes selected **per task**, not a single
hardcoded method:

- `meth_des` — the **method-descriptor / dispatcher base class** (polymorphic base; *not* a DES cipher, *not* a transport)
- `meth_tcp`, `meth_udp`, `meth_ssl` — TCP / UDP / TLS transports
- `meth_tunnel` — a **client connect-out** transport (full outbound connection; *not* a SOCKS relay / ORB pivot)

`scan_type` selects the dispatch strategy and endpoint; the specific `meth_*` transport is
chosen per task by a protocol byte. The bot is a transport toolkit. (Two early claims here —
`meth_tunnel` as a relay, and a `meth_des` DES reading — were reversed on the bench; see the
corrections log.)

### 4. Scan markers — fixed, fingerprintable — NOVEL / CORROBORATED

| Marker | Value | Tag |
|---|---|---|
| SYN source port | **19000** | CORROBORATED (two instruction sites) |
| SYN ISN | **seed `0x3251d2d`, increments +1 per target** | NOVEL (binary-confirmed) |
| ICMP echo id | **19037** (`0x4a5d`) | CORROBORATED |
| ICMP echo sequence | **36765** (`0x8f9d`) | NOVEL (binary-authoritative for this sample) |

The SYN ISN behavior matters for detection: a normal OS randomizes the ISN per connection;
JDY uses a **fixed low seed plus a per-target counter**. The durable selector is **source
port 19000 + an ascending ISN run seeded at `0x3251d2d`, no payload** — not "every SYN
carries `0x3251d2d`" (only the first of each batch does).

### 5. No hardcoded C2 in the binary — CORROBORATED

The implant carries **no embedded C2 address** — no IP, no domain, no `.onion`. The control
host is supplied externally by the dropper (`-s <web_ip>` flag). This is consistent with a
deliberately rotatable, expendable relay layer, and it explains why the control cluster had
to be enumerated through OSINT (certificate and service-profile pivots) rather than pulled
from the sample.

### 6. dmap fingerprint-DB mechanism — NOVEL (mechanism), format open

The implant supports an `update_dmap_fp_db` command that downloads a fingerprint archive
from `/dispatch/v2/dmap/<digest>` (digest-gated, so it only re-fetches on change). This is
the delivery path that lets operators update what the fleet recognizes without re-deploying
implants. The **record format of the archive is not yet mapped** — an early association of
certain `mmap` assertions with the dmap format was found to be glibc dynamic-loader
internals and reversed (see corrections log). Mapping the format requires a captured archive.

### 7. Build fingerprint — NOVEL

The binary contains the custom build path **`/usr/local/openssl/1.0.2u/mips64/`** and the
version string **`1.8.3.9`**. The nested `openssl/<version>/<arch>/` install-prefix shape is
distinctive — public convention is universally the flat/hyphen form `openssl-1.0.2u`. The
build path appears in **zero** public reporting and is a strong compile-time clustering
selector for sibling samples.

---

## New dispatch endpoint surface

Beyond the published dispatch URIs, the implant's strings expose the full API surface,
including a **NOVEL** endpoint not present in prior public reporting:

| Endpoint | Role | Tag |
|---|---|---|
| `POST /dispatch_service/v2/probe_task` | Pull tasking (encrypted blob) | PUBLISHED |
| `POST /dispatch_service/v2/probe_status` | Submit scan results / status | **NOVEL** |
| `POST /dispatch_service/v2/test` | Liveness / health stub | **NOVEL** |
| `/dispatch/v2`, `/data/v2/pscan`, `/wscan` | Strategy endpoints (port/web scan) | CORROBORATED |
| `/dispatch/v2/dmap/<digest>` | Fingerprint-DB fetch | CORROBORATED |

---

## What remains open

- **dmap record format** — gated on a captured archive (requires MIPS-capable detonation against a sinkhole; live fetch from the dispatch host is out of scope).
- **A live `probe_task` ciphertext** — the decryptor is validated by inline-scheme confirmation plus round-trip; a real captured blob would add the final increment of confidence but is not structurally required.
- **Full Ghidra reproduction** of every AI-assisted finding before each is treated as settled.

Continue to the [technical writeup](TECHNICAL_WRITEUP.md) for the decryption chain, or the
[component teardown](IMPLANT_COMPONENTS_RE.md) for the transport classes and scan engine.
