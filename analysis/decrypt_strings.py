#!/usr/bin/env python3
"""
Decrypts every obfuscated string embedded in `libloader`.

Two embedding styles exist in the binary:
  1. "Wrapper" style  - a small function calls sub_7bda0(dst, src, len, key)
                        (call sites recovered in obfstrings.json).
  2. "Inlined" style  - the splitmix64 loop is inlined into the consumer,
                        with src/key/len as immediate constants
                        (sites recovered in inlined_strings.json).

Both JSON databases were produced by capstone-based static scanning of the
__text section (see ANALYSIS.md, "Methodology"). This script only *reads*
the binary; it performs no patching.

Usage:  python3 decrypt_strings.py [path/to/libloader]
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cipher_decrypt import decrypt

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

BINARY = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "libloader")


def main():
    with open(BINARY, "rb") as fh:
        macho = fh.read()

    entries = []

    # Style 1: wrapper call sites  (site, wrapper, src_off, length, key)
    obf = os.path.join(ROOT, "analysis", "obfstrings.json")
    if os.path.exists(obf):
        for site, wf, src, ln, key in json.load(open(obf)):
            entries.append((src, ln, key, f"wrapper call @ {site:#x}"))

    # Style 2: inlined loops  (site, src_off, length, key)
    inl = os.path.join(ROOT, "analysis", "inlined_strings.json")
    if os.path.exists(inl):
        for site, src, ln, key in json.load(open(inl)):
            entries.append((src, ln, key, f"inlined loop @ {site:#x}"))

    seen = set()
    for src, ln, key, where in sorted(entries):
        if (src, ln, key) in seen or ln > 8192:
            continue
        seen.add((src, ln, key))
        plain = decrypt(macho[src:src + ln], key)
        printable = all(32 <= b < 127 or b == 0 for b in plain)
        flag = "" if printable else "   [binary]"
        print(f"{src:#010x}  len={ln:<4d} key={key:#018x}  {where:<28}{flag}  {plain!r}")


if __name__ == "__main__":
    main()
