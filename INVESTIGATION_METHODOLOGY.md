# Investigation Methodology

How this investigation was conducted, and the discipline that governs every finding in this
repository. The methodology is part of the product: it is what lets a reader trust the tags.

**Classification:** TLP:CLEAR · ICD-203 estimative language

---

## 1. Posture

**Defensive, passive OSINT.** The investigation was conducted as a defensive analysis of an
already-public sample and its publicly observable infrastructure, to build detections and
inform defenders. The working posture is read-only against internet-scan data and the
analyst's own logs.

**One engagement was re-scoped to passive after initial contact; no further active
interaction occurred.** This is recorded as a methodology note in the interest of
transparency.

---

## 2. Epistemic discipline

**AI-assisted output is treated as leads, not fact.** Where analysis was AI-assisted, findings
are reproduced independently (in Ghidra for reverse engineering; against primary scan data for
infrastructure) before they are treated as settled. This repository is explicit about that
provenance throughout.

**Four-tag pipeline, one tag per claim:**

| Tag | Meaning |
|---|---|
| **NOVEL** | Newly discovered in this investigation; not in prior public reporting. NOVEL infrastructure is **NOVEL-UNVALIDATED** until primary reproduction confirms it. |
| **CORROBORATED** | Independently confirmed (binary instruction sites, packet capture, multiple scan platforms). |
| **PUBLISHED** | Established in existing public reporting; carried forward as context. |
| **EXCLUDED** | Ruled out with primary evidence. |

**ICD-203 estimative language.** Assessments use calibrated confidence terms (e.g.
"we assess with moderate confidence") rather than absolutes, and confidence is stated per
assessment.

**Corrections are surfaced immediately and tagged.** Several headline findings were reversed
on the bench; those reversals are documented in [`CORRECTIONS_LOG.md`](CORRECTIONS_LOG.md)
rather than quietly overwritten. A clean reversal backed by primary evidence is stronger
intelligence than an unchecked assertion.

---

## 3. The promotion standard for infrastructure

A candidate host is JDY-relevant **only** if it carries the cluster signature — the jdyfj
cert, or the paired payload-host profile — verified against stored scanner data. Graph
adjacency, a shared provider, or any single common selector is **not** promotion. This
standard is what kept the cluster bounded and the false-positive rate near zero; it is
detailed in [`INFRASTRUCTURE_ENUMERATION.md`](INFRASTRUCTURE_ENUMERATION.md) and
[`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md).

---

## 4. Reverse-engineering method

The implant is MIPS64 big-endian and does not execute in a Windows x86 sandbox, so analysis
was **static-first**:

- **Ghidra** (load `MIPS:BE:64`, default compiler, full auto-analysis with the MIPS
  constant-reference analyzer enabled), cross-checked with **capstone / pyelftools** and
  **`mips-linux-gnu-objdump`**.
- **Network corroboration** from packet captures of the dispatch tier (certificate, backend
  fingerprint) — not from implant execution.
- Every AI-assisted RE finding is reproduced in Ghidra before it is treated as confirmed.

---

## 5. Tooling and scope

**In scope (read-only):** internet-scan and enrichment platforms (Shodan, Censys, FOFA,
Netlas, Silent Push, VirusTotal incl. Intelligence, MalwareBazaar), sandbox report review
(Triage, Joe Sandbox, ANY.RUN), DNS/infra enrichment (SecurityTrails, Robtex, ViewDNS,
Netcraft, HE.net), and local static-analysis tooling.

**Out of scope:** any active interaction with live JDY infrastructure.

---

## 6. Formatting and reporting conventions

Documents are written for working defenders: short paragraphs, bold key terms, clean tables,
practitioner-level language, no decorative formatting. Findings are tagged inline. Reports are
tiered by audience (strategic / operational / tactical) so each reader gets the right altitude.

---

## 7. Known limitations

- **Single primary sample.** The RE is anchored on one MIPS64 BE implant; variant behavior may
  differ (the ICMP-sequence discrepancy is an example of likely cross-variant variation).
- **No captured live tasking blob.** The decryptor is validated by inline-scheme confirmation
  and offline round-trip; a live `probe_task` ciphertext was not captured.
- **dmap record format unmapped.** Requires a captured archive (a MIPS-capable detonation
  against a sinkhole).
- **Victim-layer initial access not characterized.** Largely outside the implant's scope.
- **Infrastructure is bounded, not proven complete.** Absence of a discoverable pivot is not
  proof that no further infrastructure exists; it is the deliberate design of the actor.

---

