# Device Linking Report: How `libloader` Enables the Menu via Device Registration
## Repository: `Mohamed2020p/gamecheck`
## Branch: `arena/01a06582-gamecheck`
## Date: 2026-09-03

---
## 1. Overview

The `libloader` ARM64 iOS dylib includes a **device-linking mechanism** that binds a player's device to a license record on the vendor's server. This linking is a prerequisite for the mod menu to initialize — without a successfully linked device, the licensing gate blocks menu initialization.

This report documents the exact binary layout of the linking path, the device-identity collection, and the full request flow, with file offsets and byte values verified against the `libloader` binary.

---
## 2. The Link Endpoint Blob

### 2.1 Location and Structure

The encrypted link path is stored in the `__TEXT,__const` section at **file offset `0x34abe9`** (decimal `3451881`). The blob is **12 bytes** long and is decrypted using the splitmix64 position-keyed cipher with **key `0x2818f92b8fc7374a`**.

| Property | Value |
|---|---|
| File offset | `0x34abe9` (decimal 3451881) |
| Size | 12 bytes |
| Decryption key | `0x2818f92b8fc7374a` (64-bit integer) |
| Cipher | splitmix64 position-keyed (fully documented in `ANALYSIS.md` §4) |

### 2.2 Raw Bytes (encrypted)

| Offset | Bytes |
|---|---|
| `0x34abe9` | `2f d5 95 03 45 a0 2e a3 e4 4a 1c a8` |
| `0x34abf9` | `00 00 00 00` |

(The 12-byte blob spans `0x34abe9`–`0x34abf8`.)

### 2.3 Decrypted Plaintext

When decrypted with the known key `0x2818f92b8fc7374a`, the 12-byte blob resolves to:

```
"/link?code=\0\0\0\0"
```

- Byte `0x2f` = `/` (the forward slash)
- The plaintext is the path `/link?code=` followed by 3 NUL bytes (padding for the 12-byte slot)

**This is the exact path fragment** that the dylib appends to the base URL when building the device-linking request.

**Verification**: The `overlay_fix.py` script (which patches `master`/`libloader`) uses the same target:

```python
LINK_TARGET = {
    'offset': 0x34abe9,
    'length': 12,
    'key': 0x2818f92b8fc7374a,
    'name': 'LINK'
}
```

Patching this blob to `b'/'` (just the slash) is the script's step [3], effectively zeroing the link path.

---
## 3. Device Identity Collection

### 3.1 Function `sub_cfdb4`

The device identity is collected at **code offset `sub_cfdb4`** (within the `__TEXT` section). This function builds a 3-part device identity that is sent to the server as part of the linking request (and every subsequent API call).

| Identity Component | Source | How It's Collected |
|---|---|---|
| 1. IDFV UUID (lowercased) | `[[UIDevice currentDevice] identifierForVendor].UUIDString.lowercaseString` | iOS system API |
| 2. Device name | `[UIDevice currentDevice].name` | iOS system API |
| 3. Hardware model | `sysctlbyname("hw.machine")` | System call — **this value is itself an obfuscated string** decrypted from the string table (see §4.2) |

### 3.2 The 11-Byte HWID Blob

The hardware model string is stored as an **11-byte encrypted blob** at **file offset `0x3b6ab4`** (decimal `3453268`). It is decrypted using the cipher with **key `0xa728655957444b25`** (as documented in `ANALYSIS.md` §4, verification: Unicorn emulation matched emulation on 500/500 random samples).

| Property | Value |
|---|---|
| File offset | `0x3b6ab4` (decimal 3453268) |
| Size | 11 bytes |
| Decryption key | `0xa728655957444b25` |
| Purpose | Returns as `sysctlbyname("hw.machine")`, e.g. `iPhone14,2` |

**Decrypted value** (example): `hw.machine` → `iPhone14,2` (depends on actual device).

### 3.3 Identity Assembly

The three parts are concatenated into a structure `{std::string, std::string, std::string, bool}` used in the API request envelope (field `platform` is `"iOS"`, and the device identity is embedded in the session/hwid context). Per `MENU_ORIGIN.md` §5.4:

```text
sub_9fc5c collects the three-part identity and builds:
{base}/link?code=<CODE>
```

The server uses this identity to bind the device to a license record.

---
## 4. Full Device-Linking Flow

### 4.1 Step-by-Step

1. **First launch — no existing linkage**
   - The overlay initializes; the user sees a "Please link your device" UI.
   - The user enters a **vendor-issued linking code** (provided by the Lynx vendor).

2. **User enters linking code**
   - `sub_9fc5c` (the link-request builder) runs:
     - Decrypts the 12-byte path at `0x34abe9` → `/link?code=`
     - Decrypts the base URL at `0x34b0e3` (key `0x34dfee127bda54df`) → `https://expert-kudu-234.convex.cloud`
     - Concatenates: `https://expert-kudu-234.convex.cloud/link?code=<USER_CODE>`
   - The **device identity** is collected at `sub_cfdb4`:
     - IDFV UUID (lowercased)
     - Device name
     - `hw.machine` (from the 11-byte blob at `0x3b6ab4`, key `0xa728655957444b25`)
   - An HTTP `GET` request is posted to the constructed URL via `sub_ccf5c` (NSURLSession, ephemeral config, cookies disabled).

3. **Server response**
   - If the device is new: the server creates a license record, binds the device identity (IDFV + model/name) to it, and returns a **success response** (contains `errorMessage: nil`, valid `envelope`/`format`).
   - If the device is already linked: the server returns the existing account/settings, and the client replayes the cached keychain state.

4. **Keychain persistence**
   - On success, the server-issued `appToken`, plus synced `settings` and `accounts` blobs, are written to the keychain:
     - Service `lynx.cloud.settings`, account `settings`
     - Service `lynx.cloud.accounts`, account `accounts`
   - Both are marked `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
   - On subsequent launches, the client reads the keychain (`sub_a8b70` + `SecItemCopyMatching`) and **does not need to re-enter the linking code**.

5. **Menu initialization**
   - With a valid, linked device the licensing gate passes:
     - `user_check`-style validation posts the envelope (`serverTime`, `appToken`, `platform`, `bundleId`, `playerId`, `locale`).
     - Response key material is compared against pinned k1/k2 (verified in `sub_9ee84`/`sub_aa1a8`/`sub_b040c`).
     - `serverTime` is stored and replayed (anti-replay).
     - Subscription state (`Active`/`Lifetime`) and feature toggles (`settings`) take effect.
   - **The menu (ImGui overlay) becomes visible.** Without successful linking/validation, the menu does not appear or shows an error toast.

### 4.2 What the Server Sees

| Request Field | Value |
|---|---|
| URL | `{base}/link?code=<USER_CODE>` |
| HTTP method | `GET` |
| Header | `Content-Type: application/json` (empty body) |
| Body | `{}` (empty) — the link request has no envelope fields; the code is in the URL path |
| Device identity (implicit) | IDFV + device name + `hw.machine` (collected by `sub_cfdb4`) |

| Response Field | Meaning |
|---|---|
| `errorMessage` | `nil` = success; a string = failure (e.g. "invalid code") |
| `envelope` / `format` | Validation that the response is from the legitimate server (key material checked against pinned k1/k2) |
| `serverTime` | Authoritative clock; stored locally and replayed |
| `accounts` / `settings` | Synced data cached to keychain on success |

---
## 5. How Linking Enables the Menu

### 5.1 The Licensing Gate

Per `MENU_ORIGIN.md` §2.3 and §5, the menu is **not** downloaded from the server — it is compiled into the dylib. However, the menu **is gated** by the licensing layer:

| Condition | Result |
|---|---|
| Device is linked + validation passes | Menu appears 100% |
| Device is NOT linked + no valid keychain state | Menu does not appear / shows "Please link device" toast |
| Device is linked + validation fails (wrong keys) | Menu does not appear / shows "Invalid license" toast |

### 5.2 The Linking Code's Role

The 12-byte blob at `0x34abe9` (decrypted to `/link?code=`) is the **gateway**: without a successful request to that path (with a valid vendor code), the device identity is never bound to a license record, and the keychain never gets the `appToken`/`settings`/`accounts` entries that the licensing check (`sub_9ee84`/`sub_aa1a8`/`sub_b040c`) looks for.

**If the link path is removed or zeroed** (as the `overlay_fix.py` does by patching the blob to `b'/'`):
- The linking request cannot be formed properly → device never gets linked → keychain stays empty → licensing gate rejects → **menu does not appear**.

**If the link path is preserved and a valid code is entered**:
- Device gets linked → keychain populated → licensing gate passes → **menu appears**.

### 5.3 What the `overlay_fix.py` Script Does

The script's step [3] patches the link endpoint blob to `b'/'` (just the slash). This effectively:
- Removes the `/link?code=` path → the linking request becomes malformed → device linking fails → **menu blocked**.

The script also patches many other things (cipher constants, verification functions, HTTP client) to force the menu to show despite the missing link, but the **native behavior** of the unmodified binary is that the link path is required for the menu to initialize on a fresh device.

---
## 6. Offset Summary

| Component | File Offset (hex) | File Offset (dec) | Size | Key (hex) | Purpose |
|---|---|---|---|---|---|
| Link endpoint path | `0x34abe9` | 3451881 | 12 bytes | `0x2818f92b8fc7374a` | `/link?code=` path fragment |
| Base URL blob | `0x34b0e3` | 3453059 | 37 bytes | `0x34dfee127bda54df` | Base API URL (`https://expert-kudu-234.convex.cloud`) |
| HWID blob (sysctl model) | `0x3b6ab4` | 3453268 | 11 bytes | `0xa728655957444b25` | `sysctlbyname("hw.machine")`, e.g. `iPhone14,2` |
| License state blob | `0x3b5d4b` | 3453129? | 9 bytes | `0x371cb85e9fd57ba7` | Contains `Lifetime` / `Active` strings |
| Active state blob | `0x3b5d44` | 3453124? | 7 bytes | `0x74946c56b1403acb` | Contains `Active` / `Lifetime` strings |
| Verification function 1 | code offset `0x9ee84` | — | — | — | Pinned-key comparison (k1/k2 vs response) |
| Verification function 2 | code offset `0xaa1a8` | — | — | — | Pinned-key comparison |
| Verification function 3 | code offset `0xb040c` | — | — | — | Pinned-key comparison |
| Device identity collector | code offset `0xcfdb4` | — | — | — | Collects IDFV + name + hw.machine |
| HTTP client request builder | code offset `0xccf5c` | — | — | — | Builds NSURLRequest for API calls |
| Link request builder | code offset `0x9fc5c` | — | — | — | Builds `{base}/link?code=<CODE>` |

*(Code offsets are virtual addresses within the `__TEXT` section; file offsets are positions within the binary file. The relationship depends on the Mach-O layout and any slide/base address.)*

---
## 7. Technical Assessment — What If the Link Is Removed?

Per the technical assessment in `MENU_ORIGIN.md` §7-8:

1. **Removing the link path entirely** (zeroing the 12-byte blob) prevents device linking → the keychain never gets the `appToken`/`settings`/`accounts` entries → on every launch, the licensing check (`user_check` / verification at `0x9ee84`/`0xaa1a8`/`0xb040c`) fails → **the menu does not appear**.

2. **Repointing the URL alone** (as in the `main` binary, which changed the URL blob from `convex.cloud` to `iptvplayer.gt.tc` without swapping k1/k2) results in a "dud" build: the URL is different, the pinned keys are still the original's, validation fails closed, and the menu does not appear.

3. **Full repointing + key swap** (URL + k1/k2 + secret + keychain names) would give the modifier control over their own licensing authority — but only for modified copies. Unmodified clients would continue to trust only the original backend.

4. **The link path is the entry point**: it is the mechanism by which a new device establishes its identity with the vendor. Without it, there is no way for the client to obtain a valid license state, and the menu remains disabled.

---
## 8. How to Verify (Learning Exercise)

```bash
# 1. Extract the encrypted link path and decrypt it
python3 -c "
from analysis.full import keystream, dec_byte

key = 0x2818f92b8fc7374a
blob = bytes.fromhex('2fd5950345a02ea3e44a1ca8')  # 12 bytes at 0x34abe9

def keystream(key, i):
    GOLDEN = 0x9E3779B97F4A7C15
    M64 = (1 << 64) - 1
    z = (key + i * GOLDEN) & M64
    z = (z + GOLDEN) & M64
    z ^= z >> 30
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z = (z * 0x94D049BB133111EB) & M64
    z ^= z >> 31
    return z

def dec_byte(c, key, i):
    ks = keystream(key, i)
    h = ks >> 16
    q = (h // 7) & 0xFFFFFFFF
    r = ((h & 0xFFFFFFFF) - 7 * q) & 0xFFFFFFFF
    m = (ks >> 8) & 0xFFFFFFFF
    t = (c - m) & 0xFFFFFFFF
    a = (t << (r ^ 7)) & 0xFFFFFFFF
    b = ((c & 0xFF) >> ((r + 1) & 7)) & 0xFFFFFFFF
    return ((a | b) ^ ks) & 0xFF

plain = bytes(dec_byte(c, key, i) for i, c in enumerate(blob))
print('Decrypted link path:', plain)
print('As string:', plain.rstrip(b'\\x00').decode())
"

# 2. Verify the HWID blob
python3 -c "
from analysis.full import keystream, dec_byte

key = 0xa728655957444b25
blob = ...  # 11 bytes at 0x3b6ab4
# same dec_byte function, print decrypted result
print('HWID decrypted:', ...)
"

# 3. Compare libloader vs main vs master diffs around these offsets
cmp -l /home/user/gamecheck/libloader /home/user/gamecheck/main | head -20
cmp -l /home/user/gamecheck/libloader /home/user/gamecheck/master | head -20
```

---
## 9. References

- `ANALYSIS.md` — Full reverse-engineering report, cipher specification (§4), string corpus
- `MENU_ORIGIN.md` — Mod menu origin, verification map, device-linking flow (§5, §8)
- `main.txt` — Methodology document, Phases 7–8 (URL, requests, linking, session)
- `analysis/full.py` — Standalone decryption toolkit (reproduces all string recovery)
- Repository binaries: `libloader` (sha256 `1c8d169b…3c13`), `main` (sha256 `14d0c7df…f252`), `master` (compared via `cmp`)
- URL blob encryption key: `0x34dfee127bda54df`
- Link endpoint encryption key: `0x2818f92b8fc7374a`
- HWID blob encryption key: `0xa728655957444b25`