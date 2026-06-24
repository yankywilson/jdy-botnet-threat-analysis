# Network / Certificate Detection Notes

The YARA rule in this directory is a **file/host clustering** rule for the implant. Network
and certificate detection for JDY is **not** a YARA-on-files problem — it belongs in TLS
inspection, certificate monitoring, and IDS. This note captures those pivots so they live
alongside the rules.

**Classification:** TLP:CLEAR

---

## 1. The certificate pivot (strongest network identity)

The **jdyfj** self-signed certificate is the durable cluster anchor. Detect it in TLS/Zeek
logs (see the Sigma rule `jdy_jdyfj_certificate.yml`), in certificate-transparency / passive
monitoring, and on internet-scan platforms.

```
SHA-256 : 2b640582bbbffe58c4efb8ab5a0412e95130e70a587fd1e194fbcd4b33d432cf
serial  : 0xab8f51eb48f363f1   (= 12362189573138375665)
subject : CN=jdyfj  (RDN C=en, ST=rg, L=df, O=vb, OU=ty)
SAN     : 1.2.3.4
key     : RSA-4096
valid   : -> 2033-11-11
```

**Why it is not in the file-YARA rule:** the cert is served by the relay (server side); it is
**not embedded in the implant**. A YARA condition on the serial would zero out every implant
match.

**Scan-platform queries (verify field names per console):**
```
Censys   services.tls.certificates.leaf_data.subject.common_name="jdyfj"
FOFA     cert="jdyfj"
Shodan   ssl.cert.subject.CN:"jdyfj"   (verify serial-search support)
```

---

## 2. JARM / JA3S — caveat, do not use bare

A single TLS server fingerprint **cannot** enumerate this cluster, because the relays run
**different** web stacks (one nginx 1.20.1, another nginx 1.14.1), so their JARM/JA3S values
**differ per node**. A bare JARM against a common nginx stack also over-collects massively
(tens of thousands of unrelated hosts).

**Rule:** never pivot on a bare JARM/JA3S for JDY. If used at all, pair with the jdyfj cert or
a cluster IP. The web-stack version is a single-node fact, never cluster-wide.

---

## 3. Behavioral network signatures (IDS / pcap)

These belong in a network IDS (Zeek/Suricata) or packet analysis, not file-YARA:

- **SYN recon profile** — source port 19000, no payload, **plus** an ascending ISN run seeded
  at `0x3251d2d` (the seed is the discriminator; port 19000 alone is Mirai/SSH-brute noise).
- **ICMP markers** — echo id 19037 (`0x4a5d`), sequence 36765 (`0x8f9d`) on the port-80 path
  (35765 on variants).
- **Dispatch URIs** — `/dispatch_service/v2/(probe_task|probe_status|test)` and
  `/dispatch/v2/dmap/<digest>` (see the Sigma proxy rule).

---

## 4. Payload-host service profile (paired)

For internet-scan detection of the payload host, require the **pair**:

```
Platypus on port 13339  AND  Acme Co Go-TLS on ports 9960-9964 (same host)
```

Each alone is commodity (Platypus :13339 = 313 hosts of proxies/WAF; Acme Co + 9960-9964 =
2,369 k8s/Envoy mesh nodes). See `../../docs/NON_DISCRIMINATING_SELECTORS.md`.

```
Shodan   port:13339 ssl.cert.subject.O:"Acme Co"
Censys   services.port:13339 and services.tls.certificates.leaf_data.subject.organization="Acme Co"
FOFA     port="13339" && cert="Acme Co"
```

---

*AI-assisted analysis; all guidance is leads for analyst reproduction. TLP:CLEAR.*
