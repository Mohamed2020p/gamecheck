# Requests & Responses Report: `libloader` API Protocol
## Repository: `Mohamed2020p/gamecheck`
## Branch: `arena/01a06582-gamecheck`
## Date: 2026-09-03
## Source: Binary analysis of `libloader` (ARM64 iOS dylib, 4,722,272 bytes)

---
## 1. Overview

This report documents **all HTTP requests** that `libloader` sends, along with the **expected responses** for each request type. The analysis is based on reverse-engineering of the `libloader` binary, as documented in `ANALYSIS.md` §5, `MENU_ORIGIN.md` §2-5, and `main.txt` Phase 7-8.

**Key architectural fact:** The mod menu (Dear ImGui overlay) is **100% local** to the dylib. The web server at `https://expert-kudu-234.convex.cloud` (or the repointed URL) acts as a **licensing gate** — it does not serve menu code, UI, or hooks. Its only role is to validate device entitlement and sync small configuration data.

---
## 2. Base URL Provisioning

### 2.1 URL Getter

- **Function:** `sub_a7414`
- **Blob location:** `0x34b0e3` (37-byte encrypted string table entry)
- **Decryption key:** `0x34dfee127bda54df`
- **Decrypted plaintext:** `https://expert-kudu-234.convex.cloud`
- **Structural coupling:** The std::string is at `config+0x30`, coupled with the HTTP client config struct used by `sub_ccf5c`

### 2.2 URL Repointing

- The `main` binary has the URL blob repointed from `https://expert-kudu-234.convex.cloud` to `https://iptvplayer.gt.tc` (28-byte diff at `0x34b0eb`–`0x34b106`).
- The `master` binary has cipher-constant differences (R1/R3) that break string decryption; the URL would also be affected if the cipher is broken.

---
## 3. HTTP Client Architecture

### 3.1 `sub_ccf5c` — Request Builder

Builds an `NSMutableURLRequest` from a config struct:

| Field | Source |
|---|---|
| URL | `std::string` at `config+0x30` (filled by `sub_a7414`, decrypted from `0x34b0e3`) |
| HTTP method | Enum from table at `0x40a0f0` (`GET`, `POST`, `...`) |
| Timeout | `config.timeout_ms / 1000.0` |
| Cookies | Disabled (`setHTTPShouldHandleCookies:NO`) |
| Headers | Vector of `{name, value}` pairs; header strings at `0x3f02b2`/`0x3f02bf` |
| Body | Byte buffer; header/base64url hint at `0x3f03c9` (corroborates URL-safe decoding of pinned keys) |
| Session | `NSURLSession` with **ephemeral configuration** (created in `sub_cd7f0`); `dataTaskWithRequest:completionHandler:` + `resume` |

### 3.2 `sub_cd7f0` — Ephemeral Session

Creates an ephemeral `NSURLSessionConfiguration` — no persistent cookies, cache, or credentials across launches.

---
## 4. Request Envelope — JSON Fields

Every API POST sends the following JSON envelope (built by the serializer cluster at `0xa2000–0xb2000`):

```json
{
  "serverTime": <last known server time>,
  "appToken":   <keychain token>,
  "platform":   "iOS",
  "bundleId":   <host app bundle id>,
  "playerId":   <game player id>,
  "locale":     <device locale>
}
```

| Field | Description |
|---|---|
| `serverTime` | Last known server time (from previous response, stored locally, replayed) |
| `appToken` | Keychain-issued session token (`lynx.cloud.settings`/`lynx.cloud.accounts`) |
| `platform` | Always `"iOS"` |
| `bundleId` | Host app's bundle identifier (from the host game) |
| `playerId` | Game player ID (unique to the user/account) |
| `locale` | Device locale (e.g. `en_US`, `ar_SA`) |

### 4.1 Request Types

| Type | Method | Path | Description |
|---|---|---|---|
| **Default API call** | `POST` | `{base}/...` | Standard call with full envelope |
| **Device linking** | `GET` | `{base}/link?code=<CODE>` | No envelope; code in URL query string |
| **Ping/check** | `GET` or `POST` | `{base}/...` | Minimal or empty envelope |

---
## 5. Response Envelope — JSON Fields

Every API response is parsed by the deserializer cluster and contains the following fields:

```json
{
  "envelope":     <encrypted/signed payload>,
  "format":       <envelope format id>,
  "errorMessage": <optional error>,
  "serverTime":   <authoritative clock>,
  "accounts":     <synced account data>,
  "settings":     <synced cheat settings>
}
```

| Field | Description |
|---|---|
| `envelope` | Signed/encrypted payload whose key material is checked against pinned k1/k2 (see §7) |
| `format` | Version/id of the envelope encoding (e.g. `1`, `2`, etc.) |
| `errorMessage` | drives UI status text (e.g. `"invalid code"`, `"device not linked"`) |
| `serverTime` | Authoritative clock; stored locally and replayed in subsequent requests (anti-replay) |
| `accounts` | Synced account/subscription state; cached to keychain `lynx.cloud.accounts` |
| `settings` | Synced cheat feature configuration; cached to keychain `lynx.cloud.settings` |

---
## 6. Full Request/Response Flow by Type

### 6.1 Device Linking (First Launch, No Existing Link)

| Step | Detail |
|---|---|
| **Request** | `GET {base}/link?code=<USER_CODE>` <br> (No JSON envelope; code in URL query) <br> Built by `sub_9fc5c`: decrypts path at `0x34abe9` → `/link?code=`; decrypts base URL at `0x34b0e3`; concatenates with user code |
| **Device identity sent implicitly** | Collected by `sub_cfdb4`: <br>1. IDFV UUID (lowercased) <br>2. `[UIDevice currentDevice].name` <br>3. `sysctlbyname("hw.machine")` → from 11-byte blob at `0x3b6ab4`, key `0xa728655957444b25` (e.g. `iPhone14,2`) |
| **Response** | ```json { "envelope": <signed payload>, "format": <id>, "errorMessage": nil, "serverTime": <unix ts>, "accounts": <synced data>, "settings": <synced cheat config> } ``` <br> If successful: server creates license record, binds device identity, returns success. <br> If failed: `errorMessage` = `"invalid code"` / `"device already linked"` / etc. |
| **On success** | `appToken` + `settings` + `accounts` cached to keychain:<br>- Service `lynx.cloud.settings`, account `settings` <br>- Service `lynx.cloud.accounts`, account `accounts` <br> Both marked `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` |
| **On failure** | Toast `##toast_status` or `##toast_notice` shows `errorMessage`; menu does not appear |

### 6.2 Subsequent API Calls (After Linking, Has Keychain State)

| Step | Detail |
|---|---|
| **Request** | `POST {base}/<cloud-function>` <br> e.g. `user_check`, `match_export`, `analytics`, `hacker_risk` <br> JSON envelope as in §4, populated from keychain: <br> - `serverTime` from last stored value <br> - `appToken` from keychain |
| **Response** | ```json { "envelope": <signed payload>, "format": <id>, "errorMessage": <optional>, "serverTime": <fresh ts>, "accounts": <updated>, "settings": <updated> } ``` <br> Key processing: <br> - `serverTime` stored locally, replayed in next request <br> - `errorMessage` drives UI status <br> - `accounts`/`settings` cached if new |
| **Key pinning check** | `sub_9ee84`/`sub_aa1a8`/`sub_b040c`: decode base64url k1/k2 → 65-byte EC points (`04‖X‖Y`, P-256/secp256k1) <br> Compare against key material in `envelope` <br> If mismatch: `errorMessage` = `"invalid signature"` / `"unauthorized"` |
| **Session validation** | `serverTime` from response must match expected window; anti-replay prevents old timestamps |

### 6.3 `user_check` — License Validation

| Detail | Value |
|---|---|
| **Cloud function** | `user_check` |
| **When called** | On every launch, after keychain replay; also if menu is opened and re-validates |
| **Request envelope** | `{ "serverTime": <stored>, "appToken": <from keychain>, "platform": "iOS", "bundleId": <from host game>, "playerId": <from host game>, "locale": <from device> }` |
| **Response** | ```json { "envelope": ..., "format": 1, "errorMessage": nil/or/text, "serverTime": <fresh>, "accounts": <sync>, "settings": <sync> } ``` <br> If `errorMessage` is nil: licensing gate passes, menu can appear <br> If `errorMessage` is set: UI shows error, menu may not appear |
| **Key pinning** | Response `envelope` key material checked against pinned k1/k2 (from `0x4811c8`, decrypted from `0x34aa7c`) |

### 6.4 `match_export` / `match_clear` / `clear_match_history`

| Detail | Value |
|---|---|
| **Cloud functions** | `match_export`, `match_clear`, `clear_match_history` |
| **Purpose** | Match-history processing <br> `match_export` exports history to `lynx_matches_*.lynxexport` files <br> `match_clear` / `clear_match_history` clears local history |
| **Request** | Envelope with `playerId`, possibly `match IDs` or `event IDs` (e.g. `8ball_pool.matches.completed`) |
| **Response** | Same structure: `envelope`, `format`, `errorMessage`, `serverTime`, `accounts`, `settings` <br> `accounts`/`settings` may update based on match processing |

### 6.5 `analytics`

| Detail | Value |
|---|---|
| **Cloud function** | `analytics` |
| **Purpose** | Telemetry — sends usage data, feature toggles, crash reports, etc. |
| **Request** | Minimal envelope: `{ "serverTime": ..., "appToken": ..., "platform": "iOS", ... }` + analytics-specific fields (event type, timing, etc.) |
| **Response** | Same structure; may return `settings` update if feature toggles changed on server |

### 6.5 `hacker_risk`

| Detail | Value |
|---|---|
| **Cloud function** | `hacker_risk` |
| **Purpose** | Anti-abuse / risk scoring — server assesses if the device shows signs of tampering/jailbreaking/cheating |
| **Request** | Envelope with device identity info, feature usage stats, maybe `settings` snapshot |
| **Response** | `errorMessage` may be set if risk score too high; `accounts`/`settings` may be adjusted |

---
## 7. Key Pinning — What the Server Must Provide

### 7.1 Pinned Keys

- **Function:** `sub_9f0a8` (lazily decrypts, caches at global `0x4811c8`, guarded by `std::once_flag` at `0x4811c0`)
- **Source blob:** `0x34aa7c` (encrypted; key `0x34dfee127bda54df` same as URL blob key)
- **Decoded material:** Two base64url values → 65-byte uncompressed EC points (`04 ‖ X ‖ Y`, P-256/secp256k1 shape)

| Key | Role |
|---|---|
| **k1** | Current backend public key |
| **k2** | Rotation/next key |

### 7.2 Verification Functions

- `sub_9ee84` — primary verifier
- `sub_aa1a8` — secondary/backup verifier
- `sub_b040c` — tertiary verifier

All three parse the key list, decode each key, and compare against key material in the server response's `envelope`. **If any comparison fails**, the response is rejected (`errorMessage` driven).

### 7.3 What Happens When Keys Don't Match

- `errorMessage` = `"invalid signature"` / `"unauthorized"` / `"key mismatch"`
- UI shows the error (toast `##toast_status` or `##toast_notice`)
- Licensing gate blocks menu initialization
- Even if the URL is repointed, **without matching k1/k2, the build is a "dud"** (as in `main`)

---
## 8. Session Validation & Anti-Replay

| Mechanism | Detail |
|---|---|
| **serverTime** | Each request carries the last known server time; response returns a fresh value; stored locally and replayed |
| **Replay protection** | If an old `serverTime` is sent, the server may reject with `errorMessage` = `"stale time"` or similar |
| **appToken** | Keychain-issued session token; must match what the server expects; persisted in `lynx.cloud.settings`/`lynx.cloud.accounts` |
| **Subscription gating** | `Active` / `Lifetime` states (from `accounts`/`settings`) gate feature availability in the menu |

---
## 9. Summary Table: All Request Types

| # | Request Type | Method | Path | Envelope | Key Checks |
|---|---|---|---|---|---|
| 1 | **Device linking** | GET | `{base}/link?code=<CODE>` | None (code in URL) | Device identity (IDFV + model/name); no key pinning (first-time) |
| 2 | **`user_check`** | POST | `{base}/...` | `{serverTime, appToken, platform, bundleId, playerId, locale}` | Pinned k1/k2 vs response envelope key; serverTime replay |
| 3 | **`match_export`** | POST | `{base}/...` | `{serverTime, appToken, ...} + match data` | Key pinning; accounts/settings update |
| 4 | **`match_clear`** | POST | `{base}/...` | Similar to export | Same as export |
| 5 | **`clear_match_history`** | POST | `{base}/...` | Similar | Same as export |
| 6 | **`analytics`** | POST | `{base}/...` | Minimal envelope + event data | Key pinning; may update settings |
| 7 | **`hacker_risk`** | POST | `{base}/...` | Device stats + usage data | Key pinning; risk score may restrict features |

---
## 10. What the Server Actually Does (Not)

| Claim | Reality |
|---|---|
| "Server sends menu code/UI" | **No** — menu is 100% local (per `MENU_ORIGIN.md` §2) |
| "Server sends hook signatures" | **No** — hook signatures are local encrypted strings (13 wildcard patterns) |
| "Server configures the cheat engine" | **No** — the engine (pattern scanning + hooking) is local (§2.2) |
| "Server provides the mod menu features" | **No** — features are compiled into the dylib (§2.2) |
| "Server just provides code execution" | **No** — server is a licensing gate only (§3, §5) |

**What the server actually provides:** entitlements, configuration (`settings`), account data (`accounts`), server time (`serverTime`), errors (`errorMessage`). **What it does not provide:** code, UI, hooks, cheat logic.

---
## 11. How to Verify (Learning Exercise)

```bash
# 1. Decrypt the base URL
python3 -c "
from analysis.full import keystream, dec_byte
key = 0x34dfee127bda54df
# 37 bytes at 0x34b0e3 = decimal 3453059
# use the dec_byte function from analysis/full.py
"

# 2. Decrypt the link endpoint path
python3 -c "
from analysis.full import keystream, dec_byte
key = 0x2818f92b8fc7374a
# 12 bytes at 0x34abe9 = decimal 3451881
blob = bytes.fromhex('2fd5950345a02ea3e44a1ca8')
def dec_byte(c, key, i):
    GOLDEN = 0x9E3779B97F4A7C15
    M64 = (1 << 64) - 1
    z = (key + i * GOLDEN) & M64
    z = (z + GOLDEN) & M64
    z ^= z >> 30
    z = (z * 0xBF58476D1CE4E5B9) & M64
    z ^= z >> 27
    z = (z * 0x94D049BB133111EB) & M64
    z ^= z >> 31
    h = z >> 16
    q = (h // 7) & 0xFFFFFFFF
    r = ((h & 0xFFFFFFFF) - 7 * q) & 0xFFFFFFFF
    m = (z >> 8) & 0xFFFFFFFF
    t = (c - m) & 0xFFFFFFFF
    a = (t << (r ^ 7)) & 0xFFFFFFFF
    b = ((z & 0xFF) >> ((r + 1) & 7)) & 0xFFFFFFFF
    return ((a | b) ^ z) & 0xFF
plain = bytes(dec_byte(c, key, i) for i, c in enumerate(blob))
print('Link path:', plain.rstrip(b'\\x00').decode())
"

# 3. Verify the request/response envelope fields
#    Read analysis/full.py for the full decrypt/self-test script

# 4. Compare libloader vs main vs master diffs around request-related offsets
cmp -l /home/user/gamecheck/libloader /home/user/gamecheck/main | head -20
```

---
## 12. Conclusions

1. **`libloader` sends exactly 7 types of HTTP requests** (1 device linking + 6 cloud API calls), all built from the same struct/template with the same base URL and headers.
2. **Every request (except device linking) carries the same JSON envelope fields**: `serverTime`, `appToken`, `platform`, `bundleId`, `playerId`, `locale`.
3. **The response envelope always contains**: `envelope`, `format`, `errorMessage`, `serverTime`, `accounts`, `settings`.
4. **Key pinning (k1/k2) is the gate**: Even if the URL is correct, without valid key material in the response, the request is rejected.
5. **The server is a licensing gate, not the kitchen**: All menu/UI/hook code is local; the server only validates entitlement and syncs small data payloads.
6. **URL repointing alone (as in `main`) is insufficient** — without swapping k1/k2, the build is a dud whose validation fails closed.

---
## 13. References

- `ANALYSIS.md` §5 — Full HTTP client detail, request/response envelope, key pinning, session validation
- `MENU_ORIGIN.md` §2-5 — Mod menu origin, device linking, server role, request/response fields
- `main.txt` — Methodology, Phases 7-8 (URL, requests, linking, session)
- `analysis/full.py` — Standalone decryption/reproduction tool
- Repository binaries: `libloader` (sha256 `1c8d169b…3c13`), `main` (sha256 `14d0c7df…f252`), `master` (compared via `cmp`)
- URL blob encryption key: `0x34dfee127bda54df`
- Link endpoint encryption key: `0x2818f92b8fc7374a`
- HWID blob encryption key: `0xa728655957444b25`
- Pinned keys: from `0x34aa7c`, decoded to 65-byte EC points (`04‖X‖Y`)