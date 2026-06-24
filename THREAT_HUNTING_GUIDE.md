# Threat Hunting Guide — JDY Botnet

A hypothesis-driven hunting guide for JDY. Each hunt states a hypothesis, the data you need,
where to look, what a true positive looks like, and the commodity trap to avoid. Written for
hunters who want to find JDY without drowning in the false positives its commodity
infrastructure generates.

**The discipline that makes this work:** JDY lives on ordinary VPS hosting and shares
infrastructure with tens of thousands of benign services. **Hunt paired selectors, never a
single commodity one.** A real JDY selector returns a handful of hosts; a commodity one
returns thousands. The trap populations are catalogued in
[`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md).

**Classification:** TLP:CLEAR · findings tagged NOVEL / CORROBORATED / PUBLISHED / EXCLUDED

> Companion documents: live-incident handling in the [Incident Response Playbook](INCIDENT_RESPONSE_PLAYBOOK.md);
> signals and IOCs in the [Tactical Intelligence Report](TACTICAL_INTELLIGENCE_REPORT.md);
> deployable rules in [`../detections/`](../detections).

---

## 0. Hunting principles for this actor

1. **Pair every selector.** Identity (jdyfj cert) or build-path can stand alone; everything
   else needs a second, independent discriminator.
2. **Hunt your egress, not the internet.** The detectable signal is outbound from your edge
   devices. You are unlikely to enumerate the actor's network from the outside (it is
   atomized by design); you are very likely to catch your own compromised edge device beaconing.
3. **Architecture is a filter.** The implant is MIPS64 big-endian. Windows PE "relations" and
   x86-sandbox "contacted IPs" are noise — discard them early.
4. **Behavior over IPs.** Relay IPs rotate. The SYN-recon profile, the dispatch URI pattern,
   and the cert persist.
5. **Count your false positives.** If a selector returns thousands, it is commodity by
   definition — down-weight before you waste a shift on it.

---

## Hunt 1 — Compromised edge device beaconing to the cluster

**Hypothesis.** An internet-facing device in our estate is beaconing to a JDY relay.

**ATT&CK.** C2: Application Layer Protocol (T1071.001); Proxy / Multi-hop (T1090).

**Data needed.** Perimeter NetFlow / firewall egress; TLS metadata / Zeek `ssl.log`.

**Where to look.**
- Outbound sessions from **edge devices** (routers, firewalls, VPN, IoT) to the cluster IPs.
- Outbound TLS where the **server cert is jdyfj** (SHA-256 `2b640582…432cf` / serial
  `0xab8f51eb48f363f1`), regardless of IP — this catches rotated relays the IP list misses.
- Repeating, low-volume, regular-interval connections (beacon cadence) to a commodity VPS.

**Query pattern (Zeek `ssl.log`, conceptual).**
```
# certificate-anchored: catch the cluster wherever it moves
ssl.log where validation_status indicates self-signed
        and (cert subject CN == "jdyfj" or cert serial == ab8f51eb48f363f1)
join conn.log on uid -> originating internal asset
```

**Query pattern (NetFlow, conceptual).**
```
flows where src in {edge_device_inventory}
        and dst in {216.173.65.250, 194.14.217.88, 23.27.120.240,
                    109.104.154.116, 149.248.3.38}
        and proto = TCP
        group by src, dst -> look for regular-interval, low-byte beacons
```

**True positive looks like:** an edge device making periodic HTTPS to a host that serves the
**jdyfj cert**, ideally with `dispatch_service/v2/*` URIs visible.

**Trap to avoid:** matching the relay IPs alone over a long window will catch unrelated
co-tenants on the same shared VPS providers (Evoxt, M247, Vultr). Anchor on the **cert** and
on **which internal asset** is talking, not the bare IP.

---

## Hunt 2 — The dispatch URI pattern

**Hypothesis.** A device is pulling JDY tasking or reporting results.

**ATT&CK.** C2: Web Protocol (T1071.001); Encrypted Channel: Symmetric (T1573.001).

**Data needed.** Proxy / TLS-inspection logs (if you terminate), Zeek `http.log` for any
cleartext, URI telemetry.

**Where to look.**
- URIs under **`/dispatch_service/v2/`**: `probe_task`, `probe_status`, `test`.
- **`/dispatch/v2/dmap/<digest>`** (fingerprint-DB fetch).
- The backend behavior: `/dispatch_service/v2/test` returning `{"code": 200}`; malformed
  requests returning Django's `Server Error (500)` HTML.

**Query pattern (conceptual).**
```
http/proxy where uri matches "/dispatch_service/v2/(probe_task|probe_status|test)"
                 or uri matches "/dispatch/v2/dmap/"
```

**True positive looks like:** an internal/edge asset requesting these exact paths against a
commodity VPS, especially paired with the jdyfj cert.

**Trap to avoid:** generic `/v2/test` or `/dispatch` substrings exist in countless benign APIs.
Require the full `dispatch_service/v2/` path **and** a second signal.

---

## Hunt 3 — The SYN reconnaissance profile (JDY bot as scanner)

**Hypothesis.** A compromised device in our estate is running JDY's scan engine.

**ATT&CK.** Reconnaissance: Active Scanning (T1595, T1595.002).

**Data needed.** Egress packet capture or flow with TCP flag / sequence visibility; Zeek
`conn.log` with history.

**Where to look.**
- Outbound **SYN** packets with **source port 19000** and **no payload**, **and**
- a **monotonically ascending ISN run seeded at `0x3251d2d`** (≈ 52,696,877) — the batch's
  first SYN carries the seed exactly; subsequent SYNs increment by 1.
- Corroborating **ICMP echo** with id **19037** / sequence **36765** (or 35765 on variants),
  on the port-80 path.

**Query pattern (packet capture, conceptual).**
```
tcp.flags == SYN and tcp.srcport == 19000 and tcp.len == 0
  -> extract tcp.seq per destination
  -> confirm an ascending run starting at/near 0x03251d2d
```

**True positive looks like:** a fan of SYNs from one internal source, source port 19000,
sequence numbers climbing from a fixed low seed, hitting many external destinations with no
established sessions.

**Trap to avoid:** **source port 19000 alone is commodity** — public scanner cataloging on
port 19000 returns Mirai-class and SSH brute-forcers, not JDY. The **seeded, ascending ISN**
is the discriminator. Without the sequence pattern, do not promote.

---

## Hunt 4 — You are hosting a relay

**Hypothesis.** A host we own/operate has been turned into a JDY relay or payload host.

**ATT&CK.** Resource Development: Acquire/Compromise Infrastructure (T1583 / T1584).

**Data needed.** Your own asset inventory, internet-exposure scan of your ranges, cert
inventory.

**Where to look.**
- Any host of yours **serving the jdyfj cert** on 443.
- Any host of yours matching the **paired payload-host profile**: **Platypus :13339** AND
  **Acme Co Go-TLS :9960-9964** together.
- Unexpected **nginx fronting a Django/DRF backend** exposing `dispatch_service/v2/*`.

**True positive looks like:** one of your hosts presenting the jdyfj cert or the full paired
payload-host profile — that is direct evidence of a relay/payload role, not co-tenancy.

**Trap to avoid:** **Acme Co alone** (Go's default self-signed test cert) and **Platypus
:13339 alone** are both commodity (k8s/Envoy mesh; open proxies / WAF). Require the **pair**.

---

## Hunt 5 — Sibling-sample discovery (build-path corpus)

**Hypothesis.** Other JDY samples exist that share the build environment.

**ATT&CK.** (Tooling/clustering — supports attribution and variant tracking.)

**Data needed.** Malware-corpus search (sample-content search / YARA retrohunt on platforms
you have access to).

**Where to look.**
- Samples containing the nested build path **`/usr/local/openssl/1.0.2u/mips64/`** (NOT the
  flat/hyphen `openssl-1.0.2u`, which is commodity).
- Gated on **ELF + MIPS big-endian**; corroborated by version `1.8.3.9` and the seeded-ISN
  byte pattern.
- The clustering YARA rule in [`../detections/yara/`](../detections/yara) encodes this.

**True positive looks like:** a previously unseen MIPS64 BE ELF carrying the nested build
path — a candidate sibling for analysis and IOC expansion.

**Trap to avoid:** searching "openssl 1.0.2u" broadly returns benign cross-compile tooling and
PHP-build tutorials. The discriminator is the **nested `/openssl/<version>/<arch>/` directory
shape**, not the version number.

---

## Hunt 6 — Certificate-transparency / scan-platform tracking

**Hypothesis.** New relays carrying the jdyfj cert have appeared.

**Data needed.** Internet-scan platforms (Shodan / Censys / FOFA / Netlas), certificate
monitoring, passive DNS — read-only.

**Where to look.**
- The **jdyfj cert** (serial `0xab8f51eb48f363f1`, CN=jdyfj) across providers.
- New hosts matching the **paired payload-host profile**.

**Query notes (verify field names in each console).**
```
Shodan   ssl.cert.serial / ssl.cert.subject.CN:"jdyfj"   (verify serial-search support)
Censys   services.tls.certificates.leaf_data.subject.common_name="jdyfj"
FOFA     cert="jdyfj"
```

**True positive looks like:** a new VPS presenting the exact jdyfj keypair — a rotated or
added relay. Verify against stored scan data before promoting.

**Trap to avoid:** do not pivot on the cover-page body hash, a bare JARM on a common nginx
stack, or the per-node nginx version — all commodity (see the catalog). And **JARM/JA3S
differ per relay** (different nginx versions), so a single TLS fingerprint will not enumerate
the cluster.

---

## Reference — hunt-to-ATT&CK map

| Hunt | Primary ATT&CK |
|---|---|
| 1 — Edge beacon to cluster | T1071.001, T1090 |
| 2 — Dispatch URI pattern | T1071.001, T1573.001 |
| 3 — SYN recon profile | T1595, T1595.002 |
| 4 — Hosting a relay | T1583, T1584 |
| 5 — Sibling-sample corpus | tooling / clustering |
| 6 — Cert / scan-platform tracking | infrastructure tracking |

---

## What a true positive looks like vs. what the traps look like

| You matched… | Population if commodity | Promote? |
|---|---|---|
| jdyfj cert (serial `0xab8f51eb48f363f1`) | a handful | **Yes** — identity anchor |
| Nested build path in a MIPS64 BE ELF | ~none public | **Yes** — clustering |
| Platypus :13339 **and** Acme Co :9960-9964 paired | one known host | **Yes** — paired profile |
| Seeded-ISN SYN run (sport 19000 + ascending from `0x3251d2d`) | rare | **Yes** — behavioral |
| Source port 19000 alone | Mirai / SSH brute noise | No |
| "Acme Co" cert alone | Go default test cert everywhere | No |
| Platypus :13339 alone | 313 (proxies / WAF) | No |
| Acme Co + 9960-9964 (as generic mesh) | 2,369 (k8s / Envoy) | No |
| Cover-page body hash | 63,870 (generic nginx) | No |
| 3X-UI panel asset | 88,452 (commodity panel) | No |
| Bare JARM on nginx | 63,870 | No |

---

*AI-assisted analysis; all guidance is leads for analyst reproduction. TLP:CLEAR.*
