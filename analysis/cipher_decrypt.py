#!/usr/bin/env python3
"""
Reference decryptor for the string-obfuscation cipher used by `libloader`
("Lynx" iOS mod menu). Reverse-engineered from ARM64 code at 0x4d98/0x4e00/0x4e40
and verified byte-for-byte against Unicorn emulation of those functions
(500/500 random (cipher-byte, key, index) samples matched).

Cipher structure (per byte i of the encrypted blob, with per-string 64-bit key):

    ks  = splitmix64_step(key + i * 0x9E3779B97F4A7C15)
          where splitmix64_step(z) = finalize(z + GOLDEN)  [standard splitmix64 step]
    h   = ks >> 16
    q   = (h // 7) & 0xFFFFFFFF                 # 64-bit division, 32-bit truncation
    r   = ((h & 0xFFFFFFFF) - 7*q) & 0xFFFFFFFF  # compiler's mod-7 idiom (as emitted)
    m   = (ks >> 8) & 0xFFFFFFFF
    t   = (cipher_byte - m) & 0xFFFFFFFF
    a   = (t << (r ^ 7)) & 0xFFFFFFFF
    b   = ((t & 0xFF) >> ((r + 1) & 7)) & 0xFFFFFFFF
    plain_byte = ((a | b) ^ ks) & 0xFF

a|b (mod 256) is equivalent to rotating the low byte of t right by ((r % 7) + 1)
bits, so the scheme is: subtract a keystream byte, byte-rotate by a keystream-
derived amount (1..7), then xor another keystream byte.

This file intentionally implements DECRYPTION only (reading/verifying embedded
strings). It is provided for defensive analysis and research documentation.
"""

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15


def sm64_step(z: int) -> int:
    """One splitmix64 step: state increment + finalizer."""
    z = (z + GOLDEN) & M64
    z ^= z >> 30
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z = (z * 0x94D049BB133111EB) & M64
    z ^= z >> 31
    return z


def keystream(key: int, i: int) -> int:
    return sm64_step((key + i * GOLDEN) & M64)


def dec_byte(c: int, key: int, i: int) -> int:
    ks = keystream(key, i)
    h = ks >> 16
    q = (h // 7) & M32
    r = ((h & M32) - 7 * q) & M32
    m = (ks >> 8) & M32
    t = (c - m) & M32
    a = (t << (r ^ 7)) & M32
    b = ((t & 0xFF) >> ((r + 1) & 7)) & M32
    return ((a | b) ^ ks) & 0xFF


def decrypt(data: bytes, key: int) -> bytes:
    return bytes(dec_byte(c, key, i) for i, c in enumerate(data))


def decrypt_at(blob: bytes, offset: int, length: int, key: int) -> bytes:
    return decrypt(blob[offset:offset + length], key)


if __name__ == "__main__":
    import sys

    # Self-test against the known embedded blob (verified via emulation):
    # 11 bytes at file offset 0x3b6ab4, key 0xa728655957444b25 -> "hw.machine"
    blob = bytes.fromhex("74a1c71ec5461862790b5e")
    assert decrypt(blob, 0xA728655957444B25) == b"hw.machine\x00"
    print("self-test ok")

    if len(sys.argv) == 4:
        data = bytes.fromhex(sys.argv[1])
        key = int(sys.argv[2], 0)
        print(decrypt(data, key))
