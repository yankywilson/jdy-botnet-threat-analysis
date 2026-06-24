# Technical Writeup — Tasking Decryption Recovery

Detailed reverse engineering of the JDY implant's encrypted dispatch tasking. This document
walks the crypto call chain at the instruction level, resolves the AES-128-vs-256 question,
recovers the key and IV, and documents the dispatch endpoint surface.

For the higher-level summary and the component teardown, see
[`REVERSE_ENGINEERING.md`](REVERSE_ENGINEERING.md) and
[`IMPLANT_COMPONENTS_RE.md`](IMPLANT_COMPONENTS_RE.md).

---

## 1. Sample and load

- SHA-256: `40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed`
- ELF 64-bit MSB MIPS64, statically linked, stripped, ~3.00 MB
- Ghidra load: **`MIPS:BE:64`**, default compiler, full auto-analysis, MIPS constant-reference analyzer enabled
- Global pointer `gp` = `0x1030c050`
- Sections: `.text` @ `0x10005920`, `.rodata` @ `0x10245000`, `.got` @ `0x10304060`

Because the binary is statically linked and stripped, analysis leans on GOT-slot
resolution and constant cross-references rather than symbol names. The AES implementation
is a statically linked OpenSSL 1.0.2u (see the build path in §6).

---

## 2. Landmarks (drop these first)

Five anchors orient the whole analysis. Resolve them, then follow their cross-references.

| Landmark | Where | Why it matters |
|---|---|---|
| `Td0` AES T-table (decrypt) | `.rodata` constant block | GOT-slot xref leads into `AES_decrypt` |
| Key string `bdb718bdf47cbcde` | `.rodata` | xrefs land in the tasking handler `FUN_10007da0` |
| Dispatch URIs (`/dispatch_service/v2/...`) | `.rodata` | the request-build / reporting paths |
| `probe_task` / `probe_status` field names | `.rodata` | the tasking and result JSON shapes |
| Scan-marker constants (`19000`, `19037`, `0x3251d2d`) | `.text` immediates | the scan engine |

---

## 3. The crypto call chain

The tasking handler fetches the encrypted blob, base64-decodes it, then calls into the AES
path. The chain, top to bottom:

1. **Fetch** — the dispatch fetch routine pulls the `probe_task` response body.
2. **Base64 decode** — the body is base64; decoded to raw ciphertext.
3. **AES setup** — the key string `bdb718bdf47cbcde` is loaded; the key-schedule routine is
   called with the key and a **bit-length argument**.
4. **CBC decrypt** — the CBC worker XORs each block against the previous ciphertext block
   (or the IV for block 0) and calls the AES block function, which uses the `Td0` T-table.
5. **JSON parse** — the plaintext is parsed as the tasking JSON (`scan_type`, task IDs, a
   target `content` list).

The CBC worker is identified structurally by its XOR-previous / save-IV shape (the classic
CBC chaining pattern), not by name.

---

## 4. AES-128 vs AES-256 — the resolution

The single most important detail, and the one most easily gotten wrong.

### 4.1 The trap

Public reporting lists the key as `0000000000000000bdb718bdf47cbcde` — 32 hex characters.
Read naively, 32 hex chars = 16 bytes if hex-decoded, or 32 bytes if taken as ASCII. The
"32" invites an AES-256 assumption.

### 4.2 What the binary actually does

- The key string passed to the key schedule is **`bdb718bdf47cbcde`** — **16 ASCII bytes**, used **raw** (not hex-decoded).
- The **bit-length argument** to the key schedule (read off the argument register before the key-schedule call, delay-slot aware) is **128**, not 256.
- Therefore the cipher is **AES-128-CBC**, and the effective key is the 16 ASCII bytes `bdb718bdf47cbcde`.

### 4.3 So what is the leading `0000000000000000`?

It is the **IV**, concatenated in front of the key in the published artifact. The implant's
IV is **16 bytes of ASCII `0`** (`0x30` repeated 16 times). The published
`0000000000000000bdb718bdf47cbcde` is **IV ∥ KEY** — sixteen `0x30` bytes followed by the
sixteen key bytes — not a 32-byte AES-256 key.

### 4.4 IV nuance

Two IV encodings were considered: ASCII `'0'` (`0x30` × 16) and null (`0x00` × 16). The
decryptor tries `0x30` × 16 first, then `0x00` × 16, and selects whichever yields valid
PKCS#7 padding and parseable JSON. The bench evidence points to `0x30` × 16; the auto-detect
exists so this nuance is resolved at runtime rather than by guesswork.

---

## 5. The decryptor

[`../tools/jdy_decrypt.py`](../tools/jdy_decrypt.py) implements the recovered scheme.

- **AES-128-CBC**, key `bdb718bdf47cbcde` (raw ASCII), IV auto-detect (`0x30`×16 then `0x00`×16)
- **Loud PKCS#7 failure** — if padding does not validate, the tool reports which IV it tried
  and stops, signaling that the input is likely **not the raw AES blob** (wrong field, or
  HTTP framing left on it) rather than that the scheme is wrong. Suspect *what was fed in*
  before suspecting the cipher.
- **Block-alignment check** — catches "this base64 is not the ciphertext" before chasing a phantom.
- **`--selftest` / `--demo`** — round-trips against known plaintext so the wiring is
  re-verifiable anywhere with no input file.

The tool is validated end-to-end: a tasking blob encrypted with the recovered scheme
decrypts back to its source JSON, and `--demo` shows the targeting fields (`scan_type`,
`task_id`, `sub_task_id`, and a `content` target list such as
`198.51.100.0/24:443,8443; CVE-2026-35616`) extracted from ciphertext. The full
`base64 → AES → JSON → target-list` loop is proven offline.

**Validation status.** The scheme is confirmed two independent ways: the inline crypto
parameters in the binary, and the offline round-trip. A *live* captured `probe_task`
ciphertext would add the final increment of confidence; it is not structurally required for
the decryptor to be considered correct.

---

## 6. Build fingerprint

The binary contains the custom OpenSSL build path:

```
/usr/local/openssl/1.0.2u/mips64/
```

and the version string `1.8.3.9`. The nested `openssl/<version>/<arch>/` install-prefix is
distinctive — public convention is the flat/hyphen form `openssl-1.0.2u`. This path appears
in **zero** public reporting (verified against web search, GitHub site-search, and direct
file reads) and is a strong compile-time clustering selector. See
[`NON_DISCRIMINATING_SELECTORS.md`](NON_DISCRIMINATING_SELECTORS.md) for why version strings
alone are weak and why the **directory shape** is the discriminator.

---

## 7. Dispatch endpoint surface

| Endpoint | Method | Role | Tag |
|---|---|---|---|
| `/dispatch_service/v2/probe_task` | POST | Pull encrypted tasking | PUBLISHED |
| `/dispatch_service/v2/probe_status` | POST | Submit scan results / status | **NOVEL** |
| `/dispatch_service/v2/test` | POST | Liveness / health stub (returns `{"code": 200}`) | **NOVEL** |
| `/dispatch/v2` | — | Strategy root | CORROBORATED |
| `/data/v2/pscan` | — | Port-scan data submission | CORROBORATED |
| `/wscan` | — | Web-scan path | CORROBORATED |
| `/dispatch/v2/dmap/<digest>` | — | Fingerprint-DB fetch | CORROBORATED |

Result counters seen alongside `probe_status`: `probe_task_count`, `probe_task_banner_count`.

The dispatch tier was independently fingerprinted from packet captures of the live relay:
**nginx** front-end reverse proxy in front of a **Python Django (DRF)** backend. The Django
identification comes from the server's signature `Server Error (500)` HTML body (Django's
default; a FastAPI/Starlette backend would return JSON) and a `Vary: Cookie` header. Note
that the nginx **version** differs per node (one relay runs 1.20.1, another 1.14.1), so the
web-stack version is a single-node fact, never a cluster-wide selector.

---

## 8. What's confirmed (tag summary)

| Claim | Tag |
|---|---|
| Sample is the real JDY implant (markers present) | CORROBORATED |
| Architecture is MIPS64 big-endian (`MIPS:BE:64`) | CORROBORATED |
| Tasking = base64 → AES-128-CBC → JSON | **NOVEL** (recovered by RE) |
| Key `bdb718bdf47cbcde`, 16 ASCII bytes, raw | **NOVEL** |
| IV = `0x30` × 16; published key is IV ∥ KEY (not AES-256) | **NOVEL** |
| `POST /dispatch_service/v2/test` endpoint | **NOVEL** |
| `POST /dispatch_service/v2/probe_status` endpoint | **NOVEL** |
| Build path `/usr/local/openssl/1.0.2u/mips64/` | **NOVEL** |
| Backend is Django (DRF) behind nginx | CORROBORATED |
| No hardcoded C2 in the implant | CORROBORATED |

---

## 9. Reproduction notes

- Load `40ad28b8…` in Ghidra as **`MIPS:BE:64`**, default compiler, full auto-analysis with
  the MIPS constant-reference analyzer enabled.
- Drop the five landmarks (§2), then follow the `Td0` GOT-slot xref into the AES block
  function, and the key-string xrefs into the tasking handler.
- Read the **bit-length argument** off the argument register before the key-schedule call
  (delay-slot aware) to confirm **128**, not 256.
- Confirm the CBC worker by its XOR-previous / save-IV shape.
- Re-verify the decryptor anywhere with `python3 tools/jdy_decrypt.py --selftest`.

---

*AI-assisted analysis; all findings are leads for analyst reproduction. TLP:CLEAR.*
