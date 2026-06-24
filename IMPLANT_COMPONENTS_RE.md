# Implant Component Teardown

Component-by-component reverse engineering of the JDY MIPS64 implant: the transport
classes, the scan-type engine, the scan markers, the `dmap` fingerprint-DB mechanism, and
the build artifacts. Reversed claims are flagged here and detailed in
[`CORRECTIONS_LOG.md`](CORRECTIONS_LOG.md).

**Sample:** `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`
(MIPS64 BE ELF). Load `MIPS:BE:64`, `gp` = `0x1030c050`.

---

## 1. Transport classes (`meth_*`)

The implant exposes a family of C++ transport classes with RTTI names and vtables. They are
selected **per task**, not hardcoded — the bot is a transport toolkit.

| Class (RTTI) | Role |
|---|---|
| `meth_des` | **Method-descriptor / dispatcher base class** — the polymorphic base the others derive from. *Not* a DES cipher; *not* a transport. |
| `meth_tcp` | TCP transport |
| `meth_udp` | UDP transport |
| `meth_ssl` | TLS transport |
| `meth_tunnel` | **Client connect-out transport** — a full outbound connection to a task-supplied address |

### `meth_tunnel` is a client, not a relay

`meth_tunnel` makes **outbound, non-blocking `connect()`** calls to addresses the task
supplies. It does **not** listen or accept. The implant code contains **no `listen` and no
`accept`** (the only `accept` references resolve into libc). The object holds a single
socket descriptor (initialized to `-1`), and the driver handles the non-blocking connect
idiom (`EINPROGRESS` / `EAGAIN`). The transport is chosen by a **task protocol byte**
(6 = TCP, 17 = UDP, 18 = unlabeled), not by the literal string `"tunnel"` — whose
cross-references are all JSON field-name uses.

This reverses an earlier claim that JDY bots act as SOCKS relays / ORB pivot nodes. See the
corrections log.

---

## 2. The `scan_type` engine and its binding to transports

**Key structural finding:** `scan_type` and `meth_*` are **different categories**, not a
1:1 map. `scan_type` selects the dispatch strategy and endpoint; the specific `meth_*`
transport is chosen **per task** by the protocol byte.

| `scan_type` | Dispatch endpoint | Transport (per-task) | Confidence |
|---|---|---|---|
| `port_scan` | `/dispatch/v2/pscan`, `/data/v2/pscan` | `meth_tcp` / `meth_udp` | CORROBORATED endpoint; transport per-task |
| `web_scan` | `/wscan` | `meth_ssl` (+ `meth_tcp`) | CORROBORATED endpoint; transport ASSESSED |
| `banner` | banner-grab path | `meth_tcp` (+ `meth_ssl`) | ASSESSED |
| `content` | response-body path | `meth_ssl` | ASSESSED |
| `tunnel` | — | `meth_tunnel` (proto 6/17) | `meth_tunnel` CORROBORATED; the `"tunnel"` string is a JSON key, not the selector |

The dispatcher is implemented as C++ vtables (polymorphic method classes), not a `switch`.

---

## 3. Scan engine and packet markers

The scan engine builds raw SYN and ICMP probes with fixed, fingerprintable fields.

| Marker | Value | Notes | Tag |
|---|---|---|---|
| SYN source port | **19000** | Two instruction sites, `sockaddr_in` context | CORROBORATED |
| SYN ISN | **seed `0x3251d2d`, +1 per target** | See below | NOVEL (binary-confirmed) |
| ICMP echo id | **19037** (`0x4a5d`) | One site, built on the port-80 scan path | CORROBORATED |
| ICMP echo sequence | **36765** (`0x8f9d`) | See discrepancy note | NOVEL (binary-authoritative for this sample) |

### SYN ISN — seed plus counter

The SYN initial sequence number is a **fixed seed `0x3251d2d`** (≈ 52,696,877) that
**increments by 1 per target** within a scan batch. The per-probe sequence is stored in the
in-flight probe entry, and the receive parser validates a reply as a SYN-ACK by checking
`reply_ack == sent_seq + 1`. The seed is re-set per scan batch.

Detection consequence: a normal OS randomizes the ISN per connection. JDY uses a
**predictable low seed plus a monotonic counter**. The durable selector is **source port
19000 + an ascending ISN run seeded at `0x3251d2d`, no payload** — not "every SYN carries
`0x3251d2d`," since only the first packet of each batch carries the seed value exactly.

### ICMP sequence discrepancy — resolved

This sample loads `0x8f9d` (36765) at the ICMP sequence field; `0x8bb5` (35765) from public
reporting is **not present anywhere in the binary**. Resolution: **36765 is authoritative
for this sample.** The published 35765 differs by exactly 1,000 and is assessed as a
different build/variant or a transcription difference in reporting — not a binary error.

### Scan-result schema

`banner_list` entries are `{ip, port, tunnel, protocol, banner}`, plus `syn_ttl` and
`save_task_id`. Result counters: `probe_task_count`, `probe_task_banner_count`.

---

## 4. The `dmap` fingerprint-DB mechanism

The implant supports an `update_dmap_fp_db` command that maintains a fingerprint database
the fleet uses to recognize services.

- The handler builds `/dispatch/v2/dmap/<digest>` and downloads the archive via the dispatch
  fetch routine.
- The fetch is **digest-gated** (`dmap_fp_digest`) — the bot only re-downloads when the
  published digest changes, an efficient fleet-update design.
- A `/tmp/%s` path sits adjacent to the dmap strings and is a plausible cache path
  (UNCONFIRMED).

**Mechanism:** confirmed — this is the delivery path that lets operators update what the
fleet recognizes/targets without re-deploying implants, consistent with JDY's rapid CVE
pivoting.

**Record format:** **open.** An early association of certain `mmap` assertions
(`headmap.len == archive_stat.st_size`, `archmapped == &headmap`) with the dmap format was
reversed — those assertions belong to glibc dynamic-loader internals (a libc symbol-lookup
function), not the implant's dmap parser. See the corrections log. Mapping the record format
cleanly requires a **captured archive** (a MIPS-capable detonation against a sinkhole);
fetching one from the live dispatch host is out of scope.

---

## 5. No embedded C2

The binary carries **no hardcoded C2 address** — no IP, no domain, no `.onion`. The only
IP-shaped strings are `1.8.3.9` (the version), `2.2.2.2` (a placeholder adjacent to the
dmap strings), and `1.2.0.4` (a library version). The control host is supplied externally by
the dropper via a `-s <web_ip>` flag.

This is consistent with a deliberately rotatable, expendable relay layer and explains why
the control cluster was enumerated through certificate and service-profile OSINT pivots
rather than extracted from the sample.

---

## 6. Build and version artifacts

| Artifact | Value | Use |
|---|---|---|
| Build path | `/usr/local/openssl/1.0.2u/mips64/` | Compile-time clustering selector (NOVEL) |
| Version string | `1.8.3.9` | Supporting selector |
| Crypto library | statically linked OpenSSL 1.0.2u | Build-environment indicator |

The nested `openssl/<version>/<arch>/` install-prefix shape is the discriminator — public
convention uses the flat/hyphen form `openssl-1.0.2u`. See
[`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md).

---

## 7. Reference anchors

| Component | Anchor |
|---|---|
| Tasking handler | `FUN_10007da0` |
| dmap handler | `FUN_1000e860` |
| SYN packer / probe-enqueue | `FUN_10017df0` (seq write; ISN increment) |
| SYN receive validator | `FUN_10013310` (`ack == seq + 1`) |
| `meth_tunnel` ctor | `FUN_10019fd4` |
| `meth_tunnel` driver | `FUN_1001e2f8` (`EINPROGRESS` / `EAGAIN`) |

---

*AI-assisted analysis; all findings are leads for analyst reproduction. TLP:CLEAR.*
