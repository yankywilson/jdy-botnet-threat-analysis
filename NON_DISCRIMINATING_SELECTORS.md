# Non-Discriminating Selectors Catalog

The selectors that **look** like JDY indicators but are commodity — each with the
false-positive population that proves it. This catalog is a guardrail: any selector here, used
alone, will bury a hunt or a detection in noise. **Pair it, or do not use it.**

**Rule of thumb:** a real JDY selector returns a handful of hosts. A commodity one returns
thousands. If your selector returns thousands, it is non-discriminating by definition.

**Classification:** TLP:CLEAR · findings tagged EXCLUDED (as standalone selectors)

---

## The catalog

| Selector | False-positive population | Why it fails |
|---|---|---|
| Cover-page body hash | **63,870** | Generic nginx default-page noise |
| 3X-UI panel asset `custom.css?0.3.4.4` | **88,452** | Commodity panel install base (widely redistributed build) |
| VT execution parents | **6,629** | Shared-component correlation, not a bespoke dropper |
| Acme Co cert + ports 9960-9964 | **2,369** | Default Kubernetes / Envoy service-mesh nodes |
| Platypus :13339 (bare) | **313** | Open proxies + Alibaba WAF |
| Bare JARM on a common nginx stack | **63,870** | Severe over-collection — always pair |
| Acme Co cert (bare) | (ubiquitous) | Go's default self-signed test certificate |
| Source port 19000 (bare) | (large) | Mirai-class / SSH brute-forcers dominate; JDY's quiet SYN recon is not separable this way |
| BGP prefix `216.173.65.0/24` | (provider-wide) | Generic Evoxt customer prefix; no JDY routing signal |
| Per-node nginx version (e.g. `nginx/1.20.1`) | (single-node) | Relays run different versions; never cluster-wide |

---

## Why pairing works

Each commodity selector overlaps a huge benign population. Two **independent** selectors
overlapping the **same** host collapse that population to near zero, because the benign
populations of two unrelated selectors rarely intersect on the same box.

**Worked examples of valid pairs:**

- **jdyfj cert** (identity) — strong enough to stand alone (a handful of hosts).
- **Platypus :13339 AND Acme Co :9960-9964** — neither alone is JDY; the pair is singular to
  the known payload host.
- **Source port 19000 AND an ascending ISN run seeded at `0x3251d2d`** — port 19000 alone is
  Mirai noise; the seeded, ascending sequence is the discriminator.
- **Nested build path `/usr/local/openssl/1.0.2u/mips64/` AND ELF + MIPS-BE** — "openssl
  1.0.2u" alone returns benign build tutorials; the nested directory shape on a MIPS64 BE ELF
  is distinctive.

---

## The build-path nuance (a discriminator hiding in a commodity string)

Searching "openssl 1.0.2u" broadly returns benign cross-compile tooling, a Darwin/arm64 build
patch, and PHP-build tutorials — all using the **flat/hyphen** form `openssl-1.0.2u`. The JDY
builder used a **nested** install prefix: `/usr/local/openssl/1.0.2u/mips64/`. The
discriminator is therefore the **directory shape**, not the version number. Verified across
web search, GitHub site-search, and direct file reads: **zero** public matches for the nested
form. This is why the build path is a strong clustering selector despite "openssl 1.0.2u"
being commodity.

---

## Additional learnings carried forward

- **SSH host keys are unique per box** — a key-blob search returns one result per node,
  proving the relays were provisioned independently rather than cloned. Useful for confirming
  independence, not for expanding the cluster.
- **JDY bots are not separable by behavioral-scanner cataloging** — JDY runs quiet SYN recon,
  not loud credential attacks, so port-scan catalog services return Mirai-class and
  SSH brute-forcers, not JDY.
- **Behavioral PCAPs from x86 sandboxes are excluded as tasking evidence** — the MIPS64 BE
  implant cannot execute there — though such captures are still useful for certificate and
  backend corroboration.
- **JARM / JA3S differ per relay** because the relays run different nginx versions, so a single
  TLS fingerprint cannot enumerate the cluster.

---

