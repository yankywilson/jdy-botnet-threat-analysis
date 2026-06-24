# Detections

Deployable detection and clustering content for JDY. Two layers: **Sigma** (log-based
detection for SOC pipelines) and **YARA** (file clustering for sample discovery, plus
network/cert detection notes).

**The one rule that governs all of this:** never alert on a single commodity selector. Every
signal here that is not the **jdyfj certificate** or the **paired payload-host profile** must
be combined with a second discriminator. See
[`../docs/NON_DISCRIMINATING_SELECTORS.md`](../docs/NON_DISCRIMINATING_SELECTORS.md) for the
false-positive populations.

**Classification:** TLP:CLEAR

---

## Sigma rules (`sigma/`)

| Rule | What it detects | Standalone confidence |
|---|---|---|
| `jdy_jdyfj_certificate.yml` | The jdyfj cluster certificate in TLS/Zeek logs | **High** — identity anchor |
| `jdy_dispatch_service_uri.yml` | `/dispatch_service/v2/*` and dmap URIs in proxy logs | **High** — pair for certainty |
| `jdy_cluster_outbound.yml` | Outbound connections to cluster IPs (firewall) | **High** — IPs rotate, treat as leads |
| `jdy_syn_recon_profile.yml` | SYN recon (source port 19000) | **Low alone** — requires the seeded-ISN pairing |

Field names and log sources vary by environment — adjust `logsource` and field names to your
collectors (Zeek, Suricata, proxy vendor, firewall vendor) before deploying.

---

## YARA (`yara/`)

| File | Purpose |
|---|---|
| `jdy_mips64_implant_clustering.yar` | **Clustering** rule for sibling-sample discovery (corpus retrohunt) — gated ELF + MIPS-BE, anchored on the nested build path. **Not** an EDR/deployment rule. |
| `jdy_network_cert_notes.md` | The certificate pivot, JARM/JA3S caveats, behavioral signatures, and the paired payload-host scan queries. |

**Why the cert serial is not in the YARA rule:** the jdyfj certificate is served by the relay
(server side), not embedded in the implant. A YARA condition on it would match nothing. The
cert pivot lives in the network/cert notes and the Sigma cert rule instead.

---

## Deployment guidance

1. **Start with the high-confidence anchors** — the jdyfj cert rule and the dispatch-URI rule.
   These are the safest to run broadly.
2. **Treat IP rules as leads.** Relays rotate; the cluster-IP rule will age. Re-anchor on the
   cert.
3. **Pair the behavioral rules.** The SYN-recon rule is informational alone; promote only when
   the seeded-ISN sequence or the cert co-occurs.
4. **Use the YARA rule for retrohunt, not endpoints.** It is a sample-discovery rule for a
   malware corpus, not a host detection.
5. **Tune to your false-positive tolerance** using the catalog — if a selector returns
   thousands in your environment, it is commodity and needs pairing.

---

*AI-assisted analysis; all content is leads for analyst reproduction. TLP:CLEAR.*
