# Corrections Log

Findings that were reversed during the investigation, with the evidence that overturned them
and the corrected position. This log exists because the methodology treats AI-assisted output
as leads requiring reproduction, and surfaces corrections immediately rather than burying
them. Each entry supersedes any earlier claim to the contrary elsewhere in prior working
material.

**Classification:** TLP:CLEAR · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

---

## Reverse-engineering corrections

### C1 — `meth_tunnel` is a client connect-out, not a SOCKS relay / ORB pivot

**Prior claim.** JDY bots act as SOCKS relays / proxy-pivot (ORB) nodes that obfuscate
operator traffic.

**Corrected finding.** `meth_tunnel` is a **client / connect-out transport**. The bot makes
**outbound** non-blocking `connect()` calls to task-supplied addresses. It does not listen
or accept.

**Evidence.** The transport object holds one socket descriptor (initialized to `-1`); the
driver handles the non-blocking connect idiom (`EINPROGRESS` / `EAGAIN`); the socket is built
with `SOCK_STREAM` + `O_NONBLOCK`. There is **no `listen` and no `accept`** in implant code
(the only `accept` references resolve into libc). The transport is selected by a task
protocol byte (6 = TCP, 17 = UDP), not by the `"tunnel"` string, whose cross-references are
all JSON field uses.

**Tag.** Listening-relay reading = EXCLUDED; client connect-out = CORROBORATED.

---

### C2 — `headmap` / `archmapped` mmap assertions are glibc internals, not the dmap format

**Prior claim.** The dmap archive format is described by the assertions
`headmap.len == archive_stat.st_size` and `archmapped == &headmap` — i.e. a header struct at
offset 0 with a length field equal to the file size.

**Corrected finding.** Those assertions belong to **glibc dynamic-loader internals**, not the
implant's dmap parser. They were associated with dmap only by the shared keyword "mmap."

**Evidence.** The assertion strings are referenced only by a glibc-region function that
performs dlsym-style symbol-hash lookup, which is itself called only by another library
function. Nothing in the implant — and specifically not the dmap handler — reaches that code.

**Tag.** dmap mmap/`headmap` format claim = EXCLUDED. The dmap **mechanism** (digest-gated
download from `/dispatch/v2/dmap/<digest>`) is confirmed; the **record format remains open**,
gated on a captured archive.

---

### C3 — Dispatch backend is Django (DRF), not FastAPI

**Prior claim.** The dispatch backend is Python DRF or FastAPI (ambiguous).

**Corrected finding.** The backend is **Django (Django REST Framework)**. FastAPI is
excluded.

**Evidence.** The live relay's HTTP 500 response body is Django's signature
`Server Error (500)` default HTML; a FastAPI/Starlette backend returns JSON, not that HTML.
A `Vary: Cookie` header is also consistent with Django.

**Tag.** Django (DRF) = CORROBORATED; FastAPI = EXCLUDED.

---

### C4 — ICMP echo sequence is 36765 for this sample, not the published 35765

**Prior position.** Public reporting lists ICMP echo sequence 35765 (`0x8bb5`).

**Corrected finding.** This sample loads **36765 (`0x8f9d`)** at the ICMP sequence field;
`0x8bb5` (35765) is **not present anywhere in the binary**.

**Evidence.** The sequence value is written from the immediate `0x8f9d` at the sequence-field
position, adjacent to the ICMP id `0x4a5d` (19037).

**Resolution.** 36765 is **authoritative for this sample**. The published 35765 differs by
exactly 1,000 and is assessed as a different build/variant or a transcription difference in
reporting — not a binary error and not a reporting error for the actor. Closed.

---

## Infrastructure corrections

### C5 — "nginx/1.20.1" is a single-node fact, not a cluster-wide selector

**Prior risk.** Treating the dispatch web-stack banner `nginx/1.20.1` as a cluster signature.

**Corrected finding.** The live relays run **different** nginx versions — `216.173.65.250`
runs nginx 1.20.1, `194.14.217.88` runs nginx 1.14.1. Their TLS fingerprints (JARM / JA3S)
therefore differ. The web-stack version is a **single-node fact** and must never be used as a
cluster-wide selector. The durable cluster anchor is the **jdyfj certificate**, not the
web stack.

**Tag.** "Stack = nginx/1.20.1" cluster-wide = EXCLUDED; per-node web-stack facts =
CORROBORATED.

---

### C6 — JDY's relationship to CVE-2026-35616 is reconnaissance, not exploitation

**Prior framing.** An implied JDY delivery/exploitation linkage to CVE-2026-35616
(FortiClient EMS), pursued as a dropper-recovery lead.

**Corrected finding.** JDY **scans** for CVE-2026-35616 (Fortinet reconnaissance within hours
of disclosure) but does **not** exploit or deliver through it. The implant is a fingerprinting
scanner with no exploit code. The public CVE-2026-35616 campaign (the EKZ Infostealer,
delivered to Windows hosts) is a **separate criminal actor** on the same CVE — a shared-CVE
coincidence, not shared tooling. There is therefore no JDY delivery chain on this CVE to
recover.

**Tag.** JDY role on CVE-2026-35616 = reconnaissance only (CORROBORATED); EKZ Infostealer
campaign = separate actor (EXCLUDED as JDY).

---

## Standing working norm

Corrections are part of the product, not an embarrassment to hide. A negative finding
demonstrated with primary evidence — or a prior claim cleanly reversed — is stronger
intelligence than an assertion left unchecked. Every reversal above was driven by primary
evidence (binary instruction sites, packet captures, or population counts), and each is
tagged accordingly.

---

*AI-assisted analysis; all findings are leads for analyst reproduction. TLP:CLEAR.*
