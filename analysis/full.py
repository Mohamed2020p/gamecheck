#!/usr/bin/env python3
"""
full.py - self-contained decryptor for every obfuscated string embedded in
`libloader` ("Lynx" iOS mod menu dylib).

This single file merges:
  * analysis/cipher_decrypt.py  - the string-obfuscation cipher, reverse-
    engineered from ARM64 code at 0x4d98/0x4e00/0x4e40 and verified
    byte-for-byte against Unicorn emulation of those functions
    (500/500 random samples matched), and
  * analysis/decrypt_strings.py + its JSON site databases - the table of
    encrypted-string locations recovered by static scanning of __text.

It is completely standalone: no JSON files, no imports beyond the standard
library. It READS the binary only - it never patches or writes anything.

Two embedding styles exist in the binary (style column below):
  wrapper - a small function calls sub_7bda0(dst, src, len, key)
  inlined - the splitmix64 decrypt loop is inlined into the consumer,
            with src/key/len as immediate constants

Cipher (per byte i of the encrypted blob, per-string 64-bit key):

    ks  = splitmix64_step(key + i * 0x9E3779B97F4A7C15)
    h   = ks >> 16
    q   = (h // 7) & 0xFFFFFFFF
    r   = ((h & 0xFFFFFFFF) - 7*q) & 0xFFFFFFFF
    m   = (ks >> 8) & 0xFFFFFFFF
    t   = (cipher_byte - m) & 0xFFFFFFFF
    a   = (t << (r ^ 7)) & 0xFFFFFFFF
    b   = ((t & 0xFF) >> ((r + 1) & 7)) & 0xFFFFFFFF
    plain_byte = ((a | b) ^ ks) & 0xFF

i.e. subtract a keystream byte, byte-rotate right by a keystream-derived
amount (1..7), then xor another keystream byte.

Usage:
    python3 full.py [path/to/libloader]

Binary lookup order:
    1. path given as the first argument
    2. <directory of this script>/libloader
    3. <directory of this script>/../libloader
    4. ./libloader
"""

import os
import sys

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15


def sm64_step(z):
    """One splitmix64 step: state increment + finalizer."""
    z = (z + GOLDEN) & M64
    z ^= z >> 30
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z = (z * 0x94D049BB133111EB) & M64
    z ^= z >> 31
    return z


def keystream(key, i):
    return sm64_step((key + i * GOLDEN) & M64)


def dec_byte(c, key, i):
    ks = keystream(key, i)
    h = ks >> 16
    q = (h // 7) & M32
    r = ((h & M32) - 7 * q) & M32
    m = (ks >> 8) & M32
    t = (c - m) & M32
    a = (t << (r ^ 7)) & M32
    b = ((t & 0xFF) >> ((r + 1) & 7)) & M32
    return ((a | b) ^ ks) & 0xFF


def decrypt(data, key):
    return bytes(dec_byte(c, key, i) for i, c in enumerate(data))


# (file_offset, length, key, style) of every encrypted string, deduplicated
# by (offset, length, key), sorted by offset. 190 sites:
# 13 wrapper + 177 inlined.
SITES = [
    (0x00345e98,  12, 0x169f62cef803bdfd, "inlined"),
    (0x00345f14,  32, 0x2c24e89ad51fa82d, "inlined"),
    (0x00345f34,  14, 0xa9368371e9b14dab, "inlined"),
    (0x00345f58,  13, 0xa870b746d8d773bd, "inlined"),
    (0x00345f65,   3, 0x1f2bb58c3a9966c4, "inlined"),
    (0x00345f68,   6, 0xd82e60d8680edada, "inlined"),
    (0x00345fac,  16, 0x64813d21beb3f896, "inlined"),
    (0x00345fbc,   3, 0xb92ac7ac00000000, "inlined"),
    (0x00345ff0,  31, 0x10e5d684c5e12c09, "inlined"),
    (0x003467d8,   3, 0x963641904f4d2c7b, "inlined"),
    (0x00346e7c,  17, 0x7d32ee07f7bcc73b, "inlined"),
    (0x00346e90,   9, 0x7b8e85ff00000000, "inlined"),
    (0x00346e99,   9, 0x47c21c08cd97fb5f, "inlined"),
    (0x00347474,  12, 0xc049a8acc830ee35, "inlined"),
    (0x00347480,  12, 0x8e37c860f4d66325, "inlined"),
    (0x0034748c,  12, 0xb70b1968a3b082ab, "inlined"),
    (0x00347498,  15, 0x4ebf1f653a1d9d26, "inlined"),
    (0x003474a7,  15, 0xa53206d5d1111e0c, "inlined"),
    (0x003474b6,  11, 0x63a3aab84352db15, "inlined"),
    (0x003474c1,   7, 0x6c293bc3a69d5a6e, "inlined"),
    (0x003474c8,   7, 0x43cd85d9f4a52c97, "inlined"),
    (0x003474f8,  11, 0x107c9fafeb500000, "inlined"),
    (0x00347860,  46, 0x4f0617b9a0fc2b0b, "inlined"),
    (0x00347890,  28, 0x9f1b44c10abf0c46, "inlined"),
    (0x003478ac,  14, 0xb0d41d53bf858699, "inlined"),
    (0x003478ba,  12, 0xbd0a2f982de0f2d3, "inlined"),
    (0x003478c6,  29, 0xdeda5a923636ea19, "inlined"),
    (0x00348176,  12, 0xa8a63724c720098a, "inlined"),
    (0x00348182,   8, 0xade00629d08d7710, "inlined"),
    (0x003481d3,  14, 0x167ad66ca0e8084c, "inlined"),
    (0x003481e1,  23, 0x29af7ef74e9f5b5b, "inlined"),
    (0x0034840e,  33, 0x0b96c4794c6fcbd8, "inlined"),
    (0x00348501,   4, 0xfcf99c1d8ddd4c78, "inlined"),
    (0x0034865a,   5, 0xb0c063939a2a18c4, "inlined"),
    (0x0034865f,   2, 0xa31404943e6e78a6, "inlined"),
    (0x003489ea,  22, 0x4cddf16c9d16224e, "inlined"),
    (0x00348a00,  13, 0x6cc44e3036750fbe, "inlined"),
    (0x00348a0d,   4, 0x9c2bd9506af00427, "inlined"),
    (0x00348a11,  21, 0xc712fb803a203a78, "inlined"),
    (0x00348a26,  32, 0x1cc743e29e2b8440, "inlined"),
    (0x00348a46,  17, 0x80dac0e2bc83a7f3, "inlined"),
    (0x00348a57,  14, 0x7496224ca7e61675, "inlined"),
    (0x00348a65,  20, 0x86d06ecde2503401, "inlined"),
    (0x00348a79,  17, 0xf69ee38d13d87cd2, "inlined"),
    (0x00348b0c,   4, 0xd8a1049463d45d23, "inlined"),
    (0x00348b10,   8, 0xccd447701038cd50, "inlined"),
    (0x00348b18,  16, 0x4ace9899f23dabe1, "inlined"),
    (0x00348b28,  36, 0x3e7c10d26d6157b1, "inlined"),
    (0x00348b4c,   8, 0xd863522f7d40de02, "inlined"),
    (0x00348b54,  10, 0x1ba5d88690178d2c, "inlined"),
    (0x00348b5e,  10, 0x7b6e602e32aeb835, "inlined"),
    (0x00348b68,   8, 0x2aff5701b799945f, "inlined"),
    (0x00348b70,  26, 0xf9d2791736c4811c, "inlined"),
    (0x00348b8a,  15, 0xbdfb9e67048e165f, "inlined"),
    (0x00348b99,   8, 0x5dbe729cd85a73ee, "inlined"),
    (0x00348ba1,   8, 0xc7f742064a58b95e, "inlined"),
    (0x00348ba9,  11, 0xf3f131eb31aa408f, "inlined"),
    (0x00348bb4,  24, 0x5be438e177601b6c, "inlined"),
    (0x00348bcc,   8, 0x7a411d9259cea7e5, "inlined"),
    (0x00348bd4,  21, 0x3e8ddec4a054ac90, "inlined"),
    (0x00348be9,   8, 0xa6fda76936a4b6c4, "inlined"),
    (0x00348bf1,  10, 0x655ec5f6deb0231e, "inlined"),
    (0x00348e50,  19, 0x60376344a2f8357b, "inlined"),
    (0x00349180,  10, 0x91fbe560596dc7cc, "inlined"),
    (0x0034918a,  18, 0x4bae5cf2022bba7c, "inlined"),
    (0x00349334,  21, 0xfd7553e3a22fac36, "inlined"),
    (0x00349349,  29, 0x5b20814add107ea8, "inlined"),
    (0x003493f8, 126, 0x0e444f31b42aae6b, "wrapper"),
    (0x00349476, 166, 0xffbe67c3fa573767, "wrapper"),
    (0x0034951c, 131, 0xc89b6d55ef5eb213, "wrapper"),
    (0x0034959f, 243, 0x67b612e3251c9dda, "wrapper"),
    (0x00349692, 110, 0x43269fdd11ba4566, "wrapper"),
    (0x00349700, 114, 0xa3928d2dea5e5918, "wrapper"),
    (0x00349772,  75, 0x6a1ee802aaf41b54, "wrapper"),
    (0x003497bd,  78, 0x7a7f1e86ecc606ee, "wrapper"),
    (0x0034983f,  15, 0xed4cc3d10bc460e7, "inlined"),
    (0x0034984e,   9, 0x00fceb63e1c77b35, "inlined"),
    (0x00349857,  14, 0x1e02f4ed7a7ea736, "inlined"),
    (0x00349865,  16, 0x7967f569858970a5, "inlined"),
    (0x00349875,  11, 0x0715b32db0a42c29, "inlined"),
    (0x00349880,  13, 0x5862a67774c3c1f2, "inlined"),
    (0x0034988d,  23, 0x55085919ceaaa970, "inlined"),
    (0x003498a4,  10, 0x5504a765b08c5dd0, "inlined"),
    (0x003498ae,  15, 0xaadb6cf6a67386d5, "inlined"),
    (0x003498bd,  17, 0x50518a10d82534be, "inlined"),
    (0x003498ce,  14, 0x14dda1a24a51cc96, "inlined"),
    (0x003498dc,  26, 0x836a5b679f3b92b3, "inlined"),
    (0x003498f6,  13, 0xcedcc294e79dcd52, "inlined"),
    (0x00349903,  13, 0x3c30de151d65515d, "inlined"),
    (0x00349910,   9, 0x949aa229855ea29c, "inlined"),
    (0x00349919,  12, 0x45016180e799a2d4, "inlined"),
    (0x00349925,   6, 0x44613dc908302db4, "inlined"),
    (0x003499d4,  72, 0x1c78e80837aeecd7, "wrapper"),
    (0x00349a1c, 120, 0x0d80f091e9d11db5, "wrapper"),
    (0x00349e7a, 114, 0x675e6f756c9bc9f7, "inlined"),
    (0x00349f05,  19, 0xce287fbb146ca0e8, "inlined"),
    (0x00349f18,  14, 0x3c2251b170cdfd4d, "inlined"),
    (0x00349f26,  27, 0x07881dc5f9b79313, "inlined"),
    (0x00349f41,  19, 0x4b2885a2eb69d7a9, "inlined"),
    (0x00349f54,  19, 0x7c3dec29aa543220, "inlined"),
    (0x00349f67,  19, 0x650c9a70344c4d42, "inlined"),
    (0x00349f7a,  17, 0xfee3711dc49bdfab, "inlined"),
    (0x0034a198,  17, 0x6f6c594e5b6becde, "inlined"),
    (0x0034a1a9,  16, 0xbef4118b32242067, "inlined"),
    (0x0034a1b9,  17, 0xfd5dfaede93f85f6, "inlined"),
    (0x0034a1ca,   7, 0x1286b1e1b7aeba0b, "inlined"),
    (0x0034a1d1,   7, 0x0f134865c4a15239, "inlined"),
    (0x0034a1d8,   7, 0x970e212eed19a099, "inlined"),
    (0x0034a1df,   7, 0xb27cee1e9039e305, "inlined"),
    (0x0034a1e6,   7, 0x5d7f4857be40bc15, "inlined"),
    (0x0034a1ed,  13, 0x3366fe8b75292f0b, "inlined"),
    (0x0034a214,   7, 0x43ebff1d56c89cb4, "inlined"),
    (0x0034a220,  11, 0x90917a5c2ed50e78, "inlined"),
    (0x0034a22b,  12, 0xbd6f1611b80dbc85, "inlined"),
    (0x0034a237,   9, 0x9e3adc95edb4c77f, "inlined"),
    (0x0034a240,   6, 0x1d0d53756b32e40e, "inlined"),
    (0x0034a284,  17, 0xf09a608c4032c474, "inlined"),
    (0x0034a295,   5, 0x4664f1966541f072, "inlined"),
    (0x0034a29a,  12, 0xe25e6d97d1b4ec7b, "inlined"),
    (0x0034a2a6,   2, 0xcd4c92ef01994f3d, "inlined"),
    (0x0034a2a8,   2, 0x159d81a60ee9d47b, "inlined"),
    (0x0034a2aa,   6, 0x66c762427a6cc138, "inlined"),
    (0x0034a2b0,   8, 0x349fccf61a7bea59, "inlined"),
    (0x0034a2b8,   7, 0xf28061d315e5b5f3, "inlined"),
    (0x0034a2cd,   9, 0xc7fb5e66ea9eced6, "inlined"),
    (0x0034a2d6,   9, 0xac66aed127122721, "inlined"),
    (0x0034a2e6,   7, 0xd0826e32bc7ccc7b, "inlined"),
    (0x0034a350,  12, 0xcd431838f4413cfd, "inlined"),
    (0x0034a37c,   7, 0x43cff3c7e5c73715, "inlined"),
    (0x0034a383,   7, 0xfe13fdcbba02197d, "inlined"),
    (0x0034a3a3,  10, 0x6b0401b20810bdcb, "inlined"),
    (0x0034a3ad,  10, 0xeb12ba45b1505f7f, "inlined"),
    (0x0034a3b7,   6, 0xaa483084e3c043b9, "inlined"),
    (0x0034a3bd,  13, 0x2ec0883fcd396266, "inlined"),
    (0x0034a3ca,  14, 0x21b800b1f0007366, "inlined"),
    (0x0034a3d8,  19, 0xba8f455319effe73, "inlined"),
    (0x0034a3fb,   4, 0xc98a6ad21dd0392e, "inlined"),
    (0x0034a3ff,  10, 0xc7699694e09a7c7a, "inlined"),
    (0x0034a409,  10, 0xaba9c73fdac97434, "inlined"),
    (0x0034a413,   2, 0x9dde4077fdf69357, "inlined"),
    (0x0034a440,  10, 0xde223f3ab9a26750, "inlined"),
    (0x0034a478,   4, 0x0d8cae444d55961e, "inlined"),
    (0x0034a53c,  13, 0xa454c29b044917b2, "inlined"),
    (0x0034a549,  12, 0x904bcc6db7ff16d8, "inlined"),
    (0x0034a61e,  20, 0x66fb71ae98614129, "inlined"),
    (0x0034a718,   6, 0x90c32417f0527e71, "inlined"),
    (0x0034a73c,   5, 0xc15a0c4ecf161fcf, "inlined"),
    (0x0034a79c,   8, 0x906b1d935c04badc, "inlined"),
    (0x0034a7a4,   5, 0xb6971fbfa86e62b1, "inlined"),
    (0x0034a7a9,   8, 0xe6f1492a975cd2ae, "inlined"),
    (0x0034a7e8,   7, 0xea22907b9e8e743d, "inlined"),
    (0x0034a7ef,   6, 0x4222e93762823e3c, "inlined"),
    (0x0034a7f5,   6, 0x5051cec2ed3a5a1f, "inlined"),
    (0x0034a7fb,   9, 0x917e73f8a6ed97c8, "inlined"),
    (0x0034a804,  11, 0x4588d4652cf77d0d, "inlined"),
    (0x0034a817,  13, 0x5697f8e5fc34f3fc, "inlined"),
    (0x0034a824,  10, 0x5eb9246de01d1f33, "inlined"),
    (0x0034a82e,  13, 0xac1a349ef50f8b0c, "inlined"),
    (0x0034a848,  12, 0xfda4a4b941a14036, "inlined"),
    (0x0034a899,   7, 0xcbc30a62a2f5526f, "inlined"),
    (0x0034a8a0,   7, 0x9e48fa510d2b178e, "inlined"),
    (0x0034a8a7,  11, 0x1151d707b1239dd9, "inlined"),
    (0x0034aa7c, 182, 0x0664550582ea6848, "inlined"),
    (0x0034abe9,  12, 0x2818f92b8fc7374a, "inlined"),
    (0x0034b0e3,  37, 0x34dfee127bda54df, "inlined"),
    (0x0034b10a,   9, 0x3fa1421bf8201d56, "inlined"),
    (0x0034b113,  20, 0x16ea2ae0229acb4c, "inlined"),
    (0x0034b127,   9, 0x90bc28158b3703a5, "inlined"),
    (0x0034b130,  20, 0xe51581cfaee51502, "inlined"),
    (0x0034b350,  33, 0xf361ab7434760f40, "inlined"),
    (0x0034b788, 132, 0xc969bf6f30c3f658, "wrapper"),
    (0x0034b864,  22, 0x0148d2cd0d6ff926, "inlined"),
    (0x0034b8a4,  23, 0xba7fc8888fc2198b, "inlined"),
    (0x0034b8bc,  87, 0xb1fbc92e32d3b98f, "wrapper"),
    (0x0034b924,  12, 0x2d937b1ba04bd85a, "inlined"),
    (0x0034b958,   9, 0xc7c43cd7ad90fa7d, "inlined"),
    (0x0034b9bc,   9, 0xfc7d235929f1ab2b, "inlined"),
    (0x0034b9c5,   9, 0x216e3a6e8607f0ce, "inlined"),
    (0x003b5d44,   7, 0x74946c56b1403acb, "inlined"),
    (0x003b5d4b,   9, 0x371cb85e9fd57ba7, "inlined"),
    (0x003b5d54,  12, 0x01eb3cddd9b3ebc4, "inlined"),
    (0x003b6128,  15, 0xdf421245f9acbbc1, "inlined"),
    (0x003b6137,  15, 0x003caa4d31149d31, "inlined"),
    (0x003b6157,   5, 0xf2ea37251985ceb2, "inlined"),
    (0x003b615c,  19, 0x8173c17f976191de, "inlined"),
    (0x003b61c8,   7, 0x585f1e2b865079a3, "inlined"),
    (0x003b61e0,  14, 0xa16f56fbf1637b68, "inlined"),
    (0x003b6251,  19, 0x80cb0bbfb9465fdb, "inlined"),
    (0x003b6aaf,   5, 0x18bd0568499d0470, "inlined"),
    (0x003b6ab4,  11, 0xa728655957444b25, "wrapper")
]

# Known-answer tests verified against Unicorn emulation of the original code.
KNOWN_ANSWERS = [
    # blob at file offset 0x3b6ab4, key 0xa728655957444b25 -> "hw.machine"
    (bytes.fromhex("74a1c71ec5461862790b5e"), 0xA728655957444B25, b"hw.machine\x00"),
]


def self_test():
    for blob, key, expect in KNOWN_ANSWERS:
        got = decrypt(blob, key)
        if got != expect:
            sys.stderr.write(
                "self-test FAILED: decrypt(%s, %#x) = %r, expected %r\n"
                % (blob.hex(), key, got, expect)
            )
            raise SystemExit(1)
    return True


def find_binary():
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "libloader"),
        os.path.join(here, os.pardir, "libloader"),
        os.path.join(os.getcwd(), "libloader"),
    ]
    if len(sys.argv) > 1:
        if os.path.isfile(sys.argv[1]):
            return sys.argv[1]
        sys.stderr.write("error: no such file: %s\n" % sys.argv[1])
        raise SystemExit(1)
    for cand in candidates:
        if os.path.isfile(cand):
            return os.path.normpath(cand)
    sys.stderr.write(
        "error: cannot find `libloader` - pass its path as an argument, or\n"
        "place it next to this script, in the parent directory, or in the\n"
        "current working directory.\n"
    )
    raise SystemExit(1)


def main():
    self_test()
    path = find_binary()
    with open(path, "rb") as fh:
        macho = fh.read()
    print("binary: %s  (%d bytes)" % (path, len(macho)))
    print("%-10s  %4s  %18s  %-8s  %s" % ("OFFSET", "LEN", "KEY", "STYLE", "PLAINTEXT"))
    n_text = n_bin = n_oor = 0
    for off, ln, key, style in SITES:
        if off + ln > len(macho):
            n_oor += 1
            print("%-10s  %4d  %18s  %-8s  [out of range]"
                  % ("%#x" % off, ln, "%#x" % key, style))
            continue
        plain = decrypt(macho[off:off + ln], key)
        if all(32 <= b < 127 or b == 0 for b in plain):
            n_text += 1
            print("%-10s  %4d  %18s  %-8s  %r"
                  % ("%#x" % off, ln, "%#x" % key, style, plain))
        else:
            n_bin += 1
            print("%-10s  %4d  %18s  %-8s  <binary data> %s"
                  % ("%#x" % off, ln, "%#x" % key, style, plain.hex()))
    total = len(SITES)
    print("\n%d sites: %d text, %d binary, %d out of range"
          % (total, n_text, n_bin, n_oor))


if __name__ == "__main__":
    main()
