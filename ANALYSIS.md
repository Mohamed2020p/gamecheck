# `libloader` — Full Static & Dynamic Reverse-Engineering Report

**Target:** `libloader` (this repository)
**SHA-256:** `1c8d169b966e37c04a0c011597e1cdb0ed9cd466d37e8fbb735434c3f0fd3c13`
**Size:** 4,722,272 bytes
**Analysis date:** 2026-09-02
**Analyst environment:** Debian 12 x86-64 sandbox (no macOS host available)

---

## 1. Executive summary

`libloader` is a stripped **ARM64 iOS dylib** — an injected in-game overlay/menu
known as **"Lynx"** — that hooks the Cocos2D-based iOS game it is loaded into
(asset/strings evidence identifies the target game as **8 Ball Pool**:
`London.png`, `Table_Standard_Cue.png`, `ball1..15.png`, `GameManager`,
`league`, `trophies`, `8ball_pool.matches.completed`, …).

It consists of three cooperating layers:

1. **A rendering/UI layer** — Dear ImGui drawn over Metal (`MTKView`,
   `MTLCreateSystemDefaultDevice`), with UIKit integration
   (`lynx_overlay_view`, `lynx_key_input`, `LynxSquircleMask` ObjC classes).
2. **A game-hooking layer** — resolves game classes/symbols at runtime
   (`objc_getClass`, `dlopen`/`dlsym`), then scans game memory for
   ARM64 byte-pattern signatures (with `?` wildcards) and patches/hooks them.
3. **A commercial licensing/cloud layer** — a Convex-hosted backend at
   `https://expert-kudu-234.convex.cloud`, with per-device linking
   (`/link?code=…`), keychain-persisted session tokens, server-time
   synchronization, and two pinned elliptic-curve public keys.

Every security-relevant string in the binary (URL, keys, keychain service
names, hook signatures, sysctl names, endpoint names) is obfuscated with a
custom **position-keyed splitmix64 rolling cipher**, which was fully broken
and re-implemented (verified against CPU-level emulation of the original
code, 500/500 random samples matched).

### Key findings (IOCs)

| Item | Value |
|---|---|
| Backend base URL | `https://expert-kudu-234.convex.cloud` (Convex deployment) |
| Device-link endpoint | `{base}/link?code={code}` |
| Pinned crypto keys (base64url, secp256k1/P-256 uncompressed, 65 bytes `04‖X‖Y`) | `k1: BFj9EYlWUcea6SmN-XyZXCwScfQCqLCxUFe_7wkKwFpWJOttzJXzQi-8YKxqV1VZQJy0eGI1Is4zzmEkED4sbFQ` <br> `k2: BH2WVU0fwEv4l64BbztDOUD_pscPLs-HC9YeTQwfWr5kXcOnBtnfrkx__98xbHyExZmCp6jPgZwlkSBpVmIH4qY` |
| Hardcoded 32-hex secret/ID | `7b3f91c2e4a60d58bf12746ac9e30581` |
| Keychain services | `lynx.cloud.settings` (account `settings`), `lynx.cloud.accounts` (account `accounts`) — `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| Device identity | IDFV UUID (lowercased) + `sysctl("hw.machine")` + `[UIDevice currentDevice].name` |
| Request envelope fields | `serverTime`, `appToken`, `platform`, `bundleId`, `playerId`, `locale` |
| Response envelope fields | `envelope`, `format`, `errorMessage`, `serverTime`, `accounts`, `settings` |
| Cloud function/feature names | `user_check`, `match_export`, `match_clear`, `clear_match_history`, `accounts_confirm`, `analytics`, `hacker_risk` |
| Subscription tiers | `Active`, `Lifetime` |

---

## 2. Binary identification

```
Magic        : 0xfeedfacf (MH_MAGIC_64, little-endian)
Filetype     : MH_DYLIB
Install name : @executable_path/Frameworks/libloader.framework/libloader
Platform     : iOS, minOS 14.0, built with SDK 26.2, ld 1230.1
UUID         : d3627ed6-195b-3981-b87b-b6fa867d29cd
Code signing : LC_CODE_SIGNATURE present (ad-hoc/identity not preserved in this copy)
Symbols      : fully stripped (only 413 indirect/import symbols remain)
Relocations  : LC_DYLD_CHAINED_FIXUPS (DYLD_CHAINED_PTR_64)
Functions    : 11,931 (recovered from LC_FUNCTION_STARTS)
Sections     : __text 3.36 MB, __const 660 KB, __data 295 KB, __bss 650 KB
Linked libs  : UIKit, Foundation, CoreFoundation, Security, Metal/MetalKit/MPS,
               ImageIO, CoreGraphics, QuartzCore, libobjc, libc++, libSystem
ObjC classes : lynx_overlay_view, lynx_key_input, LynxSquircleMask,
               MetalBuffer, MetalTexture, MetalContext, FramebufferDescriptor
C++ runtime  : libc++ (std::string, std::mutex, std::call_once, exceptions)
```

Notable imports: `NSURLSession`/`NSMutableURLRequest` (networking),
`SecItemAdd/CopyMatching/Delete` + `kSecClassGenericPassword` (keychain),
`sysctlbyname` (hardware ID), `getsectiondata` (self-inspection),
`dlopen`/`dlsym` (runtime symbol resolution), `objc_msgSend` throughout.

The `__TEXT,__const` section contains the encrypted string table (see §4);
`__DATA` holds the mutable session/config state, guarded by `std::once_flag`
singletons at `0x4811c0` (k1/k2 keys), `0x459080` (hex secret), etc.

---

## 3. Methodology & tooling

The sandbox has no macOS host and blocks most download hosts (GitHub release
assets, Debian mirrors), so Ghidra/IDA-style decompilation was unavailable.
The analysis stack was assembled from PyPI instead:

| Tool | Role |
|---|---|
| **lief** | Mach-O structure, load commands, imports |
| **capstone** | Full ARM64 disassembly of `__text` (3.36 MB) |
| **angr** (CLE) | Mach-O loader applying **chained fixups** — resolved 27,312 relocations, giving true runtime pointer values for `__DATA`/GOT |
| **unicorn** | **Dynamic analysis**: CPU-level emulation of extracted functions (`sub_4d98`, `sub_4e00`, …) on the raw image, used as ground truth for the cipher |
| Custom scanners | ADRP/ADD + MOV/MOVK dataflow tracking to recover (pointer, length, key) triples at every decryption site; stub→import and objc-stub→selector maps built from the resolved GOT |

Process outline:

1. Parsed load commands, sections, `LC_FUNCTION_STARTS` (11,931 functions).
2. Parsed `LC_DYLD_CHAINED_FIXUPS` (via angr/CLE) → GOT/import map; decoded
   the 12-byte `__stubs` trampolines and 32-byte `__objc_stubs` selector
   trampolines → **named every external call site** in the disassembly.
3. Linear disassembly of `__text` with ADRP+ADD/LDR register tracking →
   cross-reference database (14,273 data targets, all `bl` edges).
4. Identified the crypto primitives (§4), then located **all** call sites of
   the byte-transform (`sub_4d98`/`sub_4e00`) — both the wrapper style
   (`sub_7bda0(dst, src, len, key)`, 25 wrapper functions) and the
   compiler-inlined loops (177 sites) — recovering each `(src, len, key)`.
5. Decrypted every blob; Unicorn-emulated the original ARM64 for verification,
   then diff-tested a pure-Python re-implementation (500/500 match).

Deliverables in `analysis/`:
- `cipher_decrypt.py` — verified reference decryptor (self-testing)
- `decrypt_strings.py` + `obfstrings.json` + `inlined_strings.json` — full string-table decryption, re-runnable against the binary
- `decrypted_strings_full.txt`, `decrypted_strings_wrappers.txt` — complete dumps

---

## 4. The string-obfuscation cipher (fully broken)

All sensitive strings are stored encrypted in `__TEXT,__const` and decrypted
lazily onto the stack, used, and zeroed. The cipher is a **per-byte,
position-keyed stream cipher** built on **splitmix64**.

### 4.1 Primitive locations

| Address | Role |
|---|---|
| `0x4e40` | splitmix64 step: `z += 0x9E3779B97F4A7C15; z ^= z>>30; z *= 0xBF58476D1CE4E5B9; z ^= z>>27; z *= 0x94D049BB133111EB; z ^= z>>31` |
| `0x4e00` | keystream: `ks(key, i) = splitmix64_step(key + i·0x9E3779B97F4A7C15)` |
| `0x4d98` | byte transform: subtract → rotate → xor (below) |
| `0x7bda0` | loop driver: `dst[i] = byte_xform(src[i], key, i)` for `i < len` |
| 25 wrappers (`0x7bd68`, `0xd0148`, `0x80864`, …) | fixed-length decryptors called with `(dst, src_ptr, key)` |
| 177 inlined sites | the loop inlined into consumers (e.g. URL getter `0xa7414`) |

### 4.2 Algorithm (exact, matches instruction semantics)

For byte index `i` with 64-bit per-string `key` and cipher byte `c`:

```text
ks = splitmix64_step(key + i·0x9E3779B97F4A7C15)
h  = ks >> 16
q  = (h / 7) truncated to 32 bits          # 64-bit udiv, 32-bit truncation
r  = ((h & 0xFFFFFFFF) - 7·q) mod 2³²      # compiler's mod-7 idiom
t  = (c - (ks >> 8)) mod 2³²
a  = (t << (r ^ 7)) mod 2³²
b  = ((t & 0xFF) >> ((r + 1) & 7))
plain = ((a | b) ^ ks) & 0xFF
```

`((a|b) & 0xFF)` equals `ror8(t & 0xFF, n)` with `n = (r mod 7) + 1 ∈ [1,7]`,
i.e. the effective per-byte operation is
`plain = ror8((c − ks_mid) & 0xFF, n) ⊕ ks_low` — a keyed subtract-rotate-xor.

### 4.3 Verification

- Unicorn emulation of `sub_4d98` on the raw dylib image reproduces every
  plaintext (e.g. the 11-byte blob at `0x3b6ab4`, key `0xa728655957444b25`
  → `hw.machine`).
- The pure-Python port (`analysis/cipher_decrypt.py`) matched emulation on
  500/500 randomized `(byte, key, index)` samples.

### 4.4 Recovered string corpus (selected)

The complete corpus (≈190 unique strings) is in `analysis/decrypted_strings_full.txt`.
Highlights:

```
https://expert-kudu-234.convex.cloud          <- backend base URL (blob 0x34b0e3)
/link?code=                                   <- device-link path     (0x34abe9)
k1:BFj9EYlWUcea6SmN-…,k2:BH2WVU0fwEv4l64B-…   <- pinned EC pubkeys   (0x34aa7c)
7b3f91c2e4a60d58bf12746ac9e30581              <- 32-hex secret/ID    (0x34b350)
lynx.cloud.settings / lynx.cloud.accounts     <- keychain services
user_check / match_export / match_clear / clear_match_history /
accounts_confirm / analytics / hacker_risk    <- cloud functions
Active / Lifetime                             <- subscription tiers
hw.machine                                    <- sysctl device model
GameManager / MenuVictoryBoxDetailsController / MenuUserProfileContentController
CCTexture2D / CCSprite / MCConfigurationDataCpp / OnDemandAssetsHandler
"00 D9 60 BC ? ? ? ? 08 ? ? 91 00 C0 22 1E …" <- ARM64 hook signatures (wildcards)
lynx_matches_all.lynxexport / .lynxexport     <- match-history export format
8ball_pool.matches.completed                  <- game event id
```

---

## 5. Cloud / licensing layer — full data flow

### 5.1 HTTP client

`sub_ccf5c` builds `NSMutableURLRequest` from a config struct:

- URL ← `std::string` at `config+0x30`
- method ← enum → `"GET"/"POST"/…` table at `0x40a0f0`
- timeout ← `config.timeout_ms / 1000.0`
- cookies disabled (`setHTTPShouldHandleCookies:NO`)
- headers from a vector of `{name, value}` pairs; body from a byte buffer
- `NSURLSession` (ephemeral configuration created in `sub_cd7f0`),
  `dataTaskWithRequest:completionHandler:` + `resume`

### 5.2 Base URL provisioning

The URL getter `sub_a7414` decrypts the 37-byte blob at `0x34b0e3`
(key `0x34dfee127bda54df`) → `https://expert-kudu-234.convex.cloud`,
constructs a `std::string`, and zeroes the stack buffer. The main API
composer `sub_a7534` then joins `{base}/{path}` (`sub_a5368`) and posts the
JSON envelope with `Content-Type: application/json` (header string pair at
`0x3f02b2`/`0x3f02bf`; the base64url alphabet hint `-_` at `0x3f03c9`
corroborates the URL-safe decoding of the pinned keys).

### 5.3 Device identity (HWID)

`sub_cfdb4` collects a three-part device identity into a
`{std::string, std::string, std::string, bool}` struct:

1. `[[UIDevice currentDevice] identifierForVendor].UUIDString.lowercaseString`
2. `[UIDevice currentDevice].name`
3. `sysctlbyname("hw.machine")` (e.g. `iPhone14,2`)

### 5.4 Device linking

`sub_9fc5c` decrypts `/link?code=` and builds
`https://expert-kudu-234.convex.cloud/link?code=<CODE>` — the user-entered
linking code is appended and the URL requested. This binds the device
identity (IDFV/model/name) to the vendor's license record server-side.

### 5.5 Session persistence (keychain)

`sub_a8b70` maps a selector to keychain names —
`("settings", "lynx.cloud.settings")` or `("accounts", "lynx.cloud.accounts")`
— used by wrappers around `SecItemAdd` (`0xce010`),
`SecItemCopyMatching` (`0xce3ac`), `SecItemDelete` (`0xce54c`) with
`kSecClassGenericPassword` and
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. The server-issued
`appToken` (plus synced `settings`/`accounts` blobs) is persisted here and
replayed on subsequent launches — this is the device↔license session store.

### 5.6 Request/response protocol

Request envelope (JSON, built by the serializer cluster at `0xa2000–0xb2000`):

```json
{ "serverTime": <last known server time>,
  "appToken":   <keychain token>,
  "platform":   "iOS",
  "bundleId":   <host app bundle id>,
  "playerId":   <game player id>,
  "locale":     <device locale> }
```

Response envelope (parsed by the deserializer cluster):

```json
{ "envelope":     <encrypted/signed payload>,
  "format":       <envelope format id>,
  "errorMessage": <optional error>,
  "serverTime":   <authoritative clock>,
  "accounts":     <synced account data>,
  "settings":     <synced cheat settings> }
```

### 5.7 Key pinning (anti-repointing control)

`sub_9f0a8` lazily decrypts and caches the `k1:…,k2:…` string
(global at `0x4811c8`, `std::once_flag` at `0x4811c0`). Consumers
(`sub_9ee84`, `sub_aa1a8`, `sub_b040c`) parse the key list, decode each
key to **64/65-byte EC point material**, and compare it against key
material carried in the server response. Decoding the base64url values
yields 65-byte uncompressed points (`04 ‖ X ‖ Y` — P-256/secp256k1 shape),
i.e. the client pins the backend's public keys (current + rotation) and
will not trust responses keyed otherwise. The hardcoded
`7b3f91c2e4a60d58bf12746ac9e30581` (getter `0x2a330`, global `0x43f1e0`)
is a cloud-layer secret/identifier passed into the session object used by
the API calls.

### 5.8 Session validation

Every cloud call carries `serverTime` + `appToken`; the server response
returns a fresh `serverTime` which is stored and replayed (clock
synchronization / anti-replay), and `errorMessage` drives the UI status.
Subscription state (`Active` / `Lifetime`) gates feature availability.

---

## 6. Hooking / cheat engine

- **Symbol resolution:** `sub_b92e0(lib, sym)` resolves ObjC classes
  (`objc_getClass` path, `OBJC_CLASS_$_` prefix handling) and arbitrary
  symbols via `dlopen(RTLD_LAZY)` + `dlsym` + `dlclose` — used against the
  host game's classes (`GameManager`, `CCSprite`, `CCTexture2D`, …).
- **Pattern scanning:** the decrypted wildcard signatures
  (`"00 D9 60 BC ? ? ? ? 08 ? ? 91 …"`) are matched against game memory;
  matches are patched/hooked (aim/training automation: `Ball %d into pocket %d`,
  `Calculating`, `No shot`, `Safety off %d`, guideline/queue controls
  `queue_kind`, `queue_tables`, `queue_wager`, …).
- **Overlay:** ImGui menu (`lynx.menu.settings`, toasts `##toast_status`,
  `##toast_notice`) rendered through a Metal pipeline with touch passthrough
  via `lynx_overlay_view`.
- **Self-inspection:** `getsectiondata` callers (`0xcc384`, `0xcc74c`) read
  the dylib's own Mach-O sections at runtime.
- **Match export:** exports game history to `lynx_matches_*.lynxexport`
  files (`8ball_pool.matches.completed` events).

---

## 7. What repointing this binary would require (technical assessment)

For completeness of the assessment — *not* as an endorsement or an
instruction — a URL swap with preserved licensing would require:

1. Re-encrypting a replacement base-URL blob with the same per-string key and
   patching it in place at `0x34b0e3` (plus adjusting the embedded length
   constant and any code-size/slide effects).
2. Standing up a compatible backend implementing the Convex-style endpoints
   (`/link?code=…`, the function paths) with matching request/response
   envelopes.
3. **Defeating the pinned-key control**: replacing or bypassing the `k1/k2`
   comparison in `sub_9ee84`/`sub_aa1a8`/`sub_b040c`, and forging the
   `appToken`/`serverTime` session material normally issued by the vendor.
4. Re-signing the modified dylib for the target environment.

Step 3 is, functionally, cracking the vendor's license enforcement; steps
1–4 together produce a license-bypassed build of an online-game cheat.

---

## 8. Conclusion on the modification request

The reverse-engineering objectives of this task are complete: the binary is
fully characterized, the obfuscation cipher is broken and verified, every
embedded URL/endpoint/key has been recovered, and the device-linking and
session-validation logic is documented end-to-end (§5).

**The requested deliverable — a modified `libloader` repointed to a
user-supplied URL with validation adjusted to accept it — was not produced.**
This document deliberately stops at analysis. Reasons:

- The artifact is a cheat for a live online multiplayer game; shipping a
  working, license-bypassed build of it facilitates cheating that harms
  other players and violates the game's terms of service.
- "Adjusting validation to accept the new target" means circumventing the
  vendor's technological protection measures (key pinning + token checks),
  i.e. cracking commercial licensing.
- No replacement URL was supplied with the task in any case.

Legitimate follow-ups this analysis does enable, and which I'm glad to help
with: detection signatures (IOCs in §1 — the pinned keys, URL, keychain
names, and the splitmix64 ciphertext layout make the dylib trivially
fingerprintable even with the URL changed), abuse reports to the backend
provider (Convex) and app-store/anti-cheat teams, or further protocol
documentation for defensive research.
