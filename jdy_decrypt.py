#!/usr/bin/env python3
"""
jdy_decrypt.py - JDY botnet tasking decryptor

Decrypts JDY dispatch tasking recovered by reverse engineering the MIPS64 implant.

Scheme (recovered at the instruction level):
    base64  ->  AES-128-CBC  ->  JSON

    Key : bdb718bdf47cbcde   (16 ASCII bytes, used RAW - not hex-decoded)
    IV  : 0x30 x 16          (ASCII '0' sixteen times)  [auto-detect falls back to 0x00 x 16]

    NOTE: the published "key" 0000000000000000bdb718bdf47cbcde is IV || KEY,
          NOT a 32-byte AES-256 key. The cipher is AES-128.

Usage:
    python3 jdy_decrypt.py task.b64          # decrypt a captured probe_task/content body
    python3 jdy_decrypt.py --selftest        # round-trip self-test (no input needed)
    python3 jdy_decrypt.py --demo            # show targeting fields extracted from ciphertext
    cat task.b64 | python3 jdy_decrypt.py -  # read base64 from stdin

Requires: pycryptodome  (pip install pycryptodome)

Reference: https://github.com/yankywilson/jdy-tasking-decryption
TLP:CLEAR. AI-assisted; a lead for analyst reproduction.
"""

import sys
import json
import base64
import argparse

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.stderr.write(
        "ERROR: pycryptodome is required.  pip install pycryptodome\n"
    )
    sys.exit(2)

KEY = b"bdb718bdf47cbcde"          # 16 ASCII bytes, raw
IV_CANDIDATES = [b"0" * 16, b"\x00" * 16]   # 0x30 x 16 first, then 0x00 x 16
BLOCK = 16


def _pkcs7_unpad(data: bytes) -> bytes:
    """Validate and strip PKCS#7 padding. Raises ValueError on bad padding."""
    if not data or len(data) % BLOCK != 0:
        raise ValueError("ciphertext is not block-aligned")
    pad = data[-1]
    if pad < 1 or pad > BLOCK:
        raise ValueError("invalid PKCS#7 pad length")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad]


def decrypt_blob(b64_text: str):
    """
    Decrypt a base64 tasking blob. Tries each IV candidate and returns the first
    that yields valid PKCS#7 padding. Returns (plaintext_bytes, iv_used).
    Raises ValueError if no IV validates (input is likely not the raw AES blob).
    """
    raw = base64.b64decode(b64_text.strip(), validate=False)
    if len(raw) == 0:
        raise ValueError("empty input after base64 decode")
    if len(raw) % BLOCK != 0:
        raise ValueError(
            "ciphertext is not a multiple of 16 bytes (%d) - this is probably "
            "not the raw AES blob (HTTP framing left on it, or wrong field captured)"
            % len(raw)
        )

    last_err = None
    for iv in IV_CANDIDATES:
        try:
            pt = AES.new(KEY, AES.MODE_CBC, iv).decrypt(raw)
            pt = _pkcs7_unpad(pt)
            return pt, iv
        except ValueError as e:
            last_err = e
            continue
    raise ValueError(
        "decryption failed PKCS#7 validation with all known IVs (%s). "
        "The input is most likely NOT the raw AES blob - re-extract the exact "
        "response body. The cipher is correct; suspect the input." % last_err
    )


def encrypt_blob(plaintext: bytes, iv: bytes = IV_CANDIDATES[0]) -> str:
    """Encrypt plaintext back to a base64 blob (used by --selftest / --demo)."""
    pad = BLOCK - (len(plaintext) % BLOCK)
    padded = plaintext + bytes([pad]) * pad
    ct = AES.new(KEY, AES.MODE_CBC, iv).encrypt(padded)
    return base64.b64encode(ct).decode("ascii")


def _print_targeting(plaintext: bytes):
    """Pretty-print the tasking JSON and highlight targeting fields."""
    try:
        obj = json.loads(plaintext.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        sys.stdout.write(plaintext.decode("utf-8", "replace") + "\n")
        return
    sys.stdout.write(json.dumps(obj, indent=2) + "\n")
    fields = ("scan_type", "task_id", "sub_task_id", "content")
    present = [f for f in fields if f in obj]
    if present:
        sys.stderr.write("\n[targeting fields] " + ", ".join(present) + "\n")


def selftest() -> int:
    sample = json.dumps({
        "scan_type": "port_scan",
        "task_id": 4711,
        "sub_task_id": 2,
        "content": "198.51.100.0/24:443,8443; CVE-2026-35616",
    }).encode("utf-8")
    blob = encrypt_blob(sample)
    pt, iv = decrypt_blob(blob)
    ok = (pt == sample)
    sys.stdout.write("selftest: %s (IV used: %s)\n" % (
        "PASS" if ok else "FAIL",
        "0x30 x 16" if iv == b"0" * 16 else "0x00 x 16",
    ))
    return 0 if ok else 1


def demo() -> int:
    sample = json.dumps({
        "scan_type": "web_scan",
        "task_id": 90125,
        "sub_task_id": 7,
        "content": "203.0.113.0/24:80,443; 192.0.2.0/24:8080; CVE-2026-35616",
    }).encode("utf-8")
    blob = encrypt_blob(sample)
    sys.stdout.write("ciphertext (base64):\n%s\n\ndecrypted tasking:\n" % blob)
    pt, _ = decrypt_blob(blob)
    _print_targeting(pt)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="JDY tasking decryptor (base64 -> AES-128-CBC -> JSON)")
    ap.add_argument("input", nargs="?", help="file with base64 tasking blob, or - for stdin")
    ap.add_argument("--selftest", action="store_true", help="round-trip self-test, no input")
    ap.add_argument("--demo", action="store_true", help="show targeting fields from a demo blob")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.demo:
        return demo()
    if not args.input:
        ap.print_help()
        return 1

    if args.input == "-":
        b64_text = sys.stdin.read()
    else:
        with open(args.input, "r", encoding="utf-8", errors="replace") as fh:
            b64_text = fh.read()

    try:
        pt, iv = decrypt_blob(b64_text)
    except ValueError as e:
        sys.stderr.write("DECRYPT FAILED: %s\n" % e)
        return 1
    sys.stderr.write("[ok] decrypted with IV %s\n" % (
        "0x30 x 16" if iv == b"0" * 16 else "0x00 x 16"))
    _print_targeting(pt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
