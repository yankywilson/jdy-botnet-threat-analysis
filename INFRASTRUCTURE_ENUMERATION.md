# Infrastructure Enumeration

The complete control-infrastructure picture for JDY: the enumerated cluster, the pivots that
found it, the exclusions worked with primary evidence, and the standing finding that the
infrastructure is deliberately atomized. Consolidates the infrastructure work across the
investigation.

**Classification:** TLP:CLEAR · ICD-203 estimative language · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

---

## 1. The enumerated cluster (IOC baseline)

| Host | Role | Provider / AS | Status |
|---|---|---|---|
| `216.173.65.250` | Relay | Evoxt / AS149440 | CORROBORATED, live. nginx 1.20.1; serves jdyfj cert; also runs 3X-UI panel :10000; fronted as `h04.zova.cc` |
| `194.14.217.88` | Relay | M247 RO / AS9009 | CORROBORATED, live. nginx 1.14.1 |
| `23.27.120.240` | Relay | Evoxt | CORROBORATED |
| `109.104.154.116` | Relay | BrainStorm NL | CORROBORATED |
| `140.82.23.123` | Historical anchor | Vultr (rotated to Cloudflare) | CORROBORATED, 2023 lineage |
| `149.248.3.38` | Payload / tasking host | Vultr LA | CORROBORATED. Platypus :13339; Acme Co Go-TLS :9960-9964 |

---

## 2. The cluster anchor — the jdyfj certificate

The single durable identity that ties the relays together.

- SHA-256: `2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf`
- Serial: `0xab8f51eb48f363f1` (= 12362189573138375665)
- Subject CN: **jdyfj**; SAN: `1.2.3.4`; RSA-4096; valid to **2033-11-11**
- RDN: C=en, ST=rg, L=df, O=vb, OU=ty, CN=jdyfj (non-standard throwaway fields)

The same 4096-bit keypair is reused across the relay nodes — the decisive intra-cluster
pivot, far more reliable than IP or ASN. It was re-confirmed live on `216.173.65.250` in
packet captures during the investigation.

**It will burn on publication.** Once the cert is publicly tied to JDY, operators can rotate
it. It is a strong present pivot with limited future durability.

---

## 3. Independent identity layers (how the cluster was validated)

The cluster was triple-confirmed across FOFA, Netlas, and Shodan, then validated across
independent layers:

| Layer | Finding | Use |
|---|---|---|
| TLS certificate | jdyfj keypair shared across relays | Primary cluster cohesion |
| SSH host key | `51:d6:bd:be:10:e9:45:a8:c7:cb:79:a7:73:59:93:ef` — **unique per box** (key-blob search returns one result each) | Proves nodes provisioned independently, not cloned |
| Cover-page body hash | Generic nginx noise (63,870 hits) | **Non-discriminating** — never a standalone selector |

The per-node uniqueness of the SSH host keys, and the differing nginx versions across relays,
together show the operators stood each box up **independently** — there is no shared build
artifact tying the relays together except the deliberately reused cert.

---

## 4. The payload / tasking host

`149.248.3.38` (Vultr LA) is distinct from the relays and carries a service profile:

- **Platypus** (a.k.a. its Termite agent) on port **13339** — an open-source Go reverse-shell
  / session manager by a Tsinghua-affiliated developer, part of the 404StarLink collection.
  Commodity tooling; a Chinese-tooling indicator, not standalone attribution.
- **Acme Co Go-TLS listeners** on ports **9960-9964** — "Acme Co" is Go's default self-signed
  test certificate.

**The discriminator is the pairing.** Platypus :13339 alone (313 hosts: proxies / WAF) and
Acme Co + 9960-9964 alone (2,369 hosts: Kubernetes / Envoy mesh) are each commodity. The full
profile — **Platypus :13339 + the Acme Co :9960-9964 block together** — is what is singular to
this host.

---

## 5. Pivots attempted and their outcomes

Across the investigation, every reasonable pivot to expand the cluster was tried. The
convergence of dead ends is itself the finding (Section 7).

| Pivot | Method | Outcome |
|---|---|---|
| TLS cert | jdyfj keypair across scan platforms | Resolves to the known nodes only |
| JARM / JA3S | TLS fingerprint pivot from live relays | **No shared fingerprint** — relays run different nginx, so fingerprints differ per node |
| SSH host key | Key-blob search per node | One result each — independent provisioning, no expansion |
| Management panel | 3X-UI panel on `216.173.65.250:10000` | Commodity — version asset returns 88,452 hosts |
| Fronting domain | `h04.zova.cc` -> `216.173.65.250` | Commodity VPN/proxy reseller; co-tenancy, not tradecraft |
| Sample relations (VT graph) | Contacted IPs, communicating files, ELF filter | Sandbox telemetry / Windows PE / only the known sample — no sibling ELF |
| Dropper recovery | VT relations + CVE delivery angle | Dry — no operator-specific dropper; the CVE campaign is a separate actor |
| Payload-host sweep | Platypus + Acme Co port block | Profile singular to `149.248.3.38` |
| Build-path corpus | `/usr/local/openssl/1.0.2u/mips64/` web/GitHub search | Genuinely unreported; no public sibling surfaced (corpus retrohunt is the remaining untried path) |
| BGP / prefix | AS149440 transit, `216.173.65.0/24` | Commodity Evoxt customer prefix; no routing signal |

---

## 6. Exclusions worked with primary evidence

Things that looked related and were ruled out with evidence — recorded so they are not
re-investigated. Co-tenant noise on shared providers is the dominant trap.

| Item | Why excluded | Tag |
|---|---|---|
| NetSupport RAT MSI on `194.14.217.88` | Commodity co-tenant; resolves to a Russian C2 (`nebodune.com`), Hungarian origin; unrelated to JDY | EXCLUDED |
| Cobalt Strike watermark `987654321` on `140.82.23.123` | Trivial sequential default riding crimeware (multiple families) | EXCLUDED |
| Cloudflare `162.159.36.2`, Brazilian G-Core siblings | Co-hosting fan-out | EXCLUDED |
| `47.239.105.221` | Finstars fintech agent API (confirmed from the host's own JSON) | EXCLUDED |
| Dispatch-URI clearnet search | JDY dispatch is Tor-hidden by design | EXCLUDED (method) |
| GreyNoise port-19000 sweep | 2,821 IPs; 73 residential candidates triaged — all Mirai-class / SSH brute-forcers | EXCLUDED — JDY not separable by behavioral cataloging (quiet SYN recon, not loud brute force) |
| 3X-UI panel / version asset | 88,452 hosts — commodity panel install base | EXCLUDED as selector (host fact NOVEL) |
| zova.cc domain | 500+ auto-generated reseller subdomains; commodity VPN/proxy reseller | EXCLUDED as selector |
| VT contacted IPs (10) | 100% sandbox telemetry (Google/MS/Akamai/multicast) — implant cannot run in x86 sandbox | EXCLUDED |
| 8 peexe + 1 pedll communicating files | Windows PE — architecturally impossible as JDY siblings (implant is MIPS64 BE) | EXCLUDED |
| VT execution parents (6,629) | Generic shared-component correlation, not a bespoke dropper | EXCLUDED |
| `prueba.txt` referrer file | Third-party researcher artifact (Windows CRLF, Spanish name, public submission) | NOT JDY |
| `185.212.44.147` graph edge | MikroTik L2TP VPN — zero cluster overlap | EXCLUDED |
| CVE-2026-35616 delivery linkage | JDY *scans* this CVE; the EKZ Infostealer that *exploits* it is a separate Windows-targeting actor | EXCLUDED as JDY |
| BGP prefix `216.173.65.0/24` | Generic Evoxt customer prefix; no JDY routing signal | EXCLUDED |

---

## 7. The standing finding — deliberate atomization

**Every independent hunt — TLS-cert / JARM, the management panel, the fronting domain, the
sample-relationship graph, the payload-host service profile, and the build-path search — all
bottomed out in commodity infrastructure.**

This convergence is the intelligence product:

> JDY infrastructure is deliberately atomized. Every node — relay and payload host alike — is
> a vanilla rented VPS that shares **nothing discoverable** with its siblings: no common
> certificate across providers beyond the deliberately reused jdyfj cert, no sibling-sample
> cluster on public platforms, no reused service profile, no captured delivery chain. Relays
> are **findable individually** (by design — they are rotatable and expendable), but they are
> **unlinkable to one another** in public data.

This is the operational signature of a mature actor treating infrastructure as throwaway,
consistent with Volt Typhoon prepositioning doctrine. **The absence of a pivotable cluster is
itself the finding** — demonstrated multiple independent ways rather than asserted once.

**Core principle:** relay nodes are intentionally findable because prepositioning stealth
lives **victim-side** (living-off-the-land on the compromised device); the relay layer is
rotatable and expendable. A sophisticated actor can therefore use discoverable relay
infrastructure with no fat thread connecting the nodes.

---

## 8. Promotion rule (for any new candidate host)

A candidate host is JDY-relevant **only** if it carries the cluster signature:

- the **jdyfj cert** (serial `0xab8f51eb48f363f1`), **or**
- the **payload-host profile** (Platypus :13339 **and** Acme Co Go-TLS :9960-9964 together),

verified against **stored scanner data**. Graph adjacency, a shared provider, or a single
common selector is **not** promotion. See
[`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md) for the selectors that
fail this test and their false-positive populations.

---

*AI-assisted analysis; all findings are leads for analyst reproduction. TLP:CLEAR.*
