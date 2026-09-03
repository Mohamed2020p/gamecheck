# Where Does the Menu Come From?

**Client/Server split of the Lynx loader (`libloader`) — menu origin, verification map, and what the web server actually does**

**Companion documents:** `ANALYSIS.md` (full reverse-engineering report) · `analysis/full.py` (standalone analysis toolkit) · `main.txt` (methodology)
**Binaries examined:** `libloader` — sha256 `1c8d169b966e37c04a0c011597e1cdb0ed9cd466d37e8fbb735434c3f0fd3c13` · `main` — sha256 `14d0c7df1cd01cecb9ed8febb035f59202ed2f92da28fb7370555d6669e4f252` (URL-repointed copy, §8)
**Date:** 2026-09-03 · **Scope:** analysis and documentation only — no modification instructions.

---

## 1. Executive summary

**The menu is not downloaded. The menu is not configured into existence by the server. The menu is compiled into the dylib.**

`libloader` is a single self-contained ARM64 iOS dylib. Everything the user perceives as "the cheat" —
the on-screen menu, the overlay, the aim/training automation, the match-history exporter, the game
hooks — is machine code and data **inside the 4.7 MB binary**. The web server at
`https://expert-kudu-234.convex.cloud` never ships code, UI, signatures, or updates. Its entire role
is to act as a **licensing gate**: it answers "is this device/player allowed to use what is already
on the device?", and it syncs small pieces of *data* (account state, cheat settings, server time).

> **The server is a bouncer, not the kitchen.** The kitchen — menu, engine, everything — is local.

This split is the single most important architectural fact about this loader, and every section
below proves it point by point:

| Question | Answer | Where proven |
|---|---|---|
| Where is the menu UI? | 100% inside the dylib (ImGui + Metal + UIKit) | §2.1 |
| Where is the cheat engine? | 100% inside the dylib (pattern scan + hook) | §2.2 |
| What does the server send? | Entitlement data only: accounts, settings, server time, errors | §3 |
| Where does verification happen? | 100% client-side, at known addresses | §4 |
| What persists locally? | appToken + settings + accounts in the iOS keychain | §6 |
| Can the gate be moved or removed? | Architecturally yes (client-side trust = speed bump, not wall) | §7 |

---

## 2. Proof that the menu is local — the three layers inside the dylib

The binary contains three cooperating layers. All three live in the same file; none is fetched at
runtime.

### 2.1 The rendering/UI layer — the menu itself

| Evidence | Location in binary |
|---|---|
| Dear ImGui rendering pipeline drawn over Metal (`MTKView`, `MTLCreateSystemDefaultDevice`) | `__text` code + imports (Metal/MetalKit/MPS linked at load time) |
| UIKit integration classes: `lynx_overlay_view` (touch passthrough), `lynx_key_input`, `LynxSquircleMask` | embedded Objective-C classes |
| Metal glue classes: `MetalBuffer`, `MetalTexture`, `MetalContext`, `FramebufferDescriptor` | embedded Objective-C classes |
| Menu chrome strings (decrypted corpus): `lynx`, `lynx_portrait_tab_`, `lynx.menu.settings`, toast IDs `##toast_status` / `##toast_notice` | encrypted string table (`__TEXT,__const`), decrypted lazily at runtime |
| Menu/player-facing game strings: `GameManager`, `MenuVictoryBoxDetailsController`, `MenuUserProfileContentController`, `achievementList`, `chatMessages`, `baseTableList`, `league`, `trophies` | encrypted string table |

The menu you see on screen is this layer: local code, local strings, local rendering. **Nothing in
the server's response vocabulary (§3) contains UI.**

### 2.2 The game-hooking layer — the cheat engine

This is the layer that actually manipulates the game (identified as **8 Ball Pool** from asset and
event names: `London.png`, `ball1..15.png`, `8ball_pool.matches.completed`, …):

| Capability | Local evidence |
|---|---|
| Runtime symbol/class resolution against the host game: `objc_getClass`, `dlopen`/`dlsym`/`dlclose` (`sub_b92e0`) | imported symbols + `__text` code |
| **13 decrypted ARM64 byte-pattern signatures with `?` wildcards** (e.g. `00 D9 60 BC ? ? ? ? 08 ? ? 91 …` at blob `0x3493f8`) — scanned against game memory, matches are patched/hooked | encrypted string table; wildcards included |
| Aim/training automation strings: `Ball %d into pocket %d`, `Calculating`, `No shot`, `Safety off %d`, guideline/queue controls `queue_kind`, `queue_tables`, `queue_wager` | encrypted string table |
| Match-history export to `lynx_matches_*.lynxexport` files | encrypted string table + local file I/O code |
| Self-inspection of the dylib's own Mach-O sections at runtime (`getsectiondata`, callers `0xcc384` / `0xcc74c`) | `__text` code |

Every one of the 190 decrypted strings in the corpus (see `analysis/decrypted_strings_full.txt`,
reproducible via `analysis/full.py`) is **stored inside the binary**. The hook signatures — the
"knowledge" of where to patch the game — are local data, not a server download.

### 2.3 The licensing/cloud layer — the gate

The third layer is the only part that talks to the network:

- an HTTP client (`sub_ccf5c`, NSURLSession),
- a base-URL getter (`sub_a7414`, decrypting the 37-byte blob at `0x34b0e3` →
  `https://expert-kudu-234.convex.cloud`),
- a device-linking request builder (`sub_9fc5c` → `/link?code=<CODE>`),
- pinned-key verification (`sub_9f0a8` / `sub_9ee84` / `sub_aa1a8` / `sub_b040c`),
- keychain persistence (`sub_a8b70` + `SecItem` wrappers).

It gates the *other two layers*; it does not implement them. Full detail in §4.

---

## 3. What actually comes from the web server

### 3.1 What the client sends (request envelope)

Built by the local serializer cluster and posted as JSON (`Content-Type: application/json`, header
strings at `0x3f02b2`/`0x3f02bf`):

```json
{ "serverTime": <last known server time>,
  "appToken":   <keychain-issued session token>,
  "platform":   "iOS",
  "bundleId":   <host game bundle id>,
  "playerId":   <game player id>,
  "locale":     <device locale> }
```

Plus, for device linking, the user-entered code is appended to the URL itself:
`{base}/link?code=<CODE>` — binding the device identity (§4.6) to the vendor's license record
server-side.

### 3.2 What the server returns (response envelope)

```json
{ "envelope":     <signed/encrypted payload>,
  "format":       <envelope format id>,
  "errorMessage": <optional error>,
  "serverTime":   <authoritative clock>,
  "accounts":     <synced account data>,
  "settings":     <synced cheat settings> }
```

Field by field:

| Field | What it is | What it is NOT |
|---|---|---|
| `envelope` | Signed/encrypted payload whose key material is checked against the pinned k1/k2 (§4.4) | Not code, not UI |
| `format` | Version/id of the envelope encoding | — |
| `errorMessage` | Drives the UI status text (e.g. invalid code) | — |
| `serverTime` | Authoritative clock; stored locally and replayed (anti-replay / clock sync) | — |
| `accounts` | Synced account/subscription state; cached in keychain service `lynx.cloud.accounts` | Not the menu |
| `settings` | Synced cheat **configuration** (feature toggles); cached in `lynx.cloud.settings` | **Data that configures local code — not the features themselves** |

The crucial nuance is `settings`: the server can *toggle* features, but the features it toggles are
already compiled into the dylib (§2.2). The server decides **who is allowed in** and **what
configuration applies** — never **what the software is**.

### 3.3 The server-side API surface (recovered function names)

The corpus contains the names of the cloud functions the client calls, which map out the backend's
entire role:

| Cloud function | Inferred role |
|---|---|
| `user_check` | License/entitlement validation (the "is this device allowed" call) |
| `accounts_confirm` | Confirm/refresh account state |
| `match_export` / `match_clear` / `clear_match_history` | Match-history processing services |
| `analytics` | Telemetry |
| `hacker_risk` | Anti-abuse / risk scoring |

Subscription tiers (`Active`, `Lifetime`) appear in the corpus as the states that gate feature
availability.

**Complete inventory of what the server provides:** entitlements, configuration, server time,
errors, account data. **Complete inventory of what it does not provide:** the menu, the overlay, the
hooks, the signatures, the cheat logic, any code at all.

---

## 4. Where verification lives — the full address map

Every check in this licensing design executes **on the client**, inside the dylib, at known
locations. This is the definitive map:

| # | Check / step | Where | Detail |
|---|---|---|---|
| 1 | Base URL provisioning | `sub_a7414` ← blob `0x34b0e3`, key `0x34dfee127bda54df` | Decrypts `https://expert-kudu-234.convex.cloud` lazily, uses it, zeroes the stack buffer |
| 2 | URL composition | `sub_a7534` (join via `sub_a5368`) | Builds `{base}/{path}` for each API call |
| 3 | Device-link request | `sub_9fc5c` ← blob `0x34abe9` | Builds `{base}/link?code=<user code>` |
| 4 | HTTP client | `sub_ccf5c` (ephemeral session in `sub_cd7f0`) | `NSMutableURLRequest` from config struct: URL at `config+0x30`, method enum → `GET/POST/…` table at `0x40a0f0`, cookies disabled, header vector, byte-buffer body, `dataTaskWithRequest:` + `resume` |
| 5 | **Pinned-key materialization** | `sub_9f0a8` ← blob `0x34aa7c` | Lazily decrypts `k1:<base64url>,k2:<base64url>`, caches at global `0x4811c8`, guarded by `std::once_flag` at `0x4811c0` |
| 6 | **Pinned-key verification** | `sub_9ee84`, `sub_aa1a8`, `sub_b040c` | Parse the key list, base64url-decode each to 65-byte uncompressed EC points (`04‖X‖Y`, P-256/secp256k1 shape), compare against key material carried in the server response. k1 = current key, k2 = rotation key |
| 7 | Shared secret | getter `0x2a330` → global `0x43f1e0` → consumed by session ctor `0xa31a4` | The 32-hex secret `7b3f91c2e4a60d58bf12746ac9e30581` (blob `0x34b350`) is passed into the session object used by API calls |
| 8 | Device identity (HWID) | `sub_cfdb4` | Builds 3-part identity: IDFV UUID (lowercased) + `[UIDevice currentDevice].name` + `sysctl("hw.machine")` (blob `0x3b6ab4`) |
| 9 | Session persistence | `sub_a8b70` + SecItem wrappers: `SecItemAdd 0xce010`, `SecItemCopyMatching 0xce3ac`, `SecItemDelete 0xce54c` | `kSecClassGenericPassword`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, services `lynx.cloud.settings` / `lynx.cloud.accounts` |
| 10 | String obfuscation itself | cipher at `0x4d98`/`0x4e00`/`0x4e40`, driver `sub_7bda0` | The splitmix64 position-keyed cipher hiding all of the above (fully documented in `ANALYSIS.md` §4) |

**The key architectural fact:** steps 1–10 are all *inside the dylib*. The server's only job in the
trust chain is to **hold the private keys matching k1/k2** and sign correct responses. The *decision*
to trust those responses is made by code running on the player's device.

---

## 5. Full lifecycle: from injection to menu on screen

1. **Injection** — the dylib is loaded into the host game process (`@executable_path/Frameworks/libloader.framework/libloader`).
2. **Local bootstrap** — Objective-C classes register; the Metal/ImGui overlay layer initializes
   (`MTKView`, `MTLCreateSystemDefaultDevice`, `lynx_overlay_view` for touch passthrough).
3. **Lazy decryption** — each encrypted string (URL, keys, keychain names, hook signatures) is
   decrypted on demand onto the stack, used, and zeroed (`sub_9f0a8` for the pinned keys, etc.).
4. **Session restore** — keychain is read (`SecItemCopyMatching` via `sub_a8b70`): previously
   issued `appToken`, cached `settings` and `accounts` are replayed. A returning, already-linked
   device does not need to re-enter a code.
5. **Device linking (first run)** — user enters their vendor-issued code; client requests
   `{base}/link?code=<CODE>`, binding IDFV + device name + hardware model to the license record.
6. **Validation calls** — `user_check`-style calls post the envelope (`serverTime`, `appToken`,
   `platform`, `bundleId`, `playerId`, `locale`).
7. **Response verification (client-side)** — response key material is compared against pinned
   k1/k2 (`sub_9ee84` and siblings); `serverTime` is stored and replayed (anti-replay);
   `errorMessage` surfaces in the UI if something is wrong.
8. **Entitlement applied** — `accounts` / `settings` are cached to the keychain; subscription state
   (`Active` / `Lifetime`) and feature toggles take effect.
9. **The menu runs** — the ImGui overlay renders (local code), the hook engine resolves game
   classes (`sub_b92e0`), scans game memory with the 13 local wildcard signatures, and patches
   matches. Aim/training features operate entirely in-process. Match history exports to local
   `.lynxexport` files; cloud functions (`match_export`, `analytics`, `hacker_risk`, …) are called
   for server-side bookkeeping.

Steps 1–3, 8–9 contain **zero network dependence**. Steps 4–7 are the gate.

---

## 6. What persists locally (and what that means)

The keychain is the client's local memory of the gate's decisions:

| Keychain service | Account | Contents |
|---|---|---|
| `lynx.cloud.settings` | `settings` | Server-synced cheat settings (feature configuration) |
| `lynx.cloud.accounts` | `accounts` | Server-synced account/subscription state |

Both are written with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` — device-bound,
after-first-unlock accessible. The `appToken` (session token) rides along with these structures and
is replayed on every launch. Consequence: **after a successful validation, the client can operate
from its local cache**; the network is a refresh/check-in mechanism, not a per-frame dependency.
The menu, hooks, and cheat features keep running from local code and local cached configuration.

---

## 7. Architectural assessment — the four questions

Stated as a technical assessment only (consistent with `ANALYSIS.md` §7 — not an endorsement, not
instructions):

### 7.1 "The menu doesn't come from the server" — correct
Proven in §2: UI layer, hook engine, all 190 strings (including the 13 hook signatures) are
compiled into the dylib. The server's entire vocabulary is entitlement data (§3).

### 7.2 The server controls the gate, not the engine — correct
The response is `{envelope, format, errorMessage, serverTime, accounts, settings}`. The strongest
lever the server holds is *configuration* (`settings` can toggle features) and *entitlement*
(`accounts`/tiers decide what's allowed). The engine those levers control is local.

### 7.3 Could the device-identity collection be removed? — architecturally yes
`sub_cfdb4` (IDFV + device.name + hw.machine) is client-side code. Anything client-side can, in
principle, be altered by whoever controls the binary. Practically, removing it means patching code
such that the request builder still produces a request the rest of the client (and any server
watching) accepts — "amputation" tends to break the surrounding logic. No how-to is provided here.

### 7.4 Could the requests be removed entirely (offline)? — architecturally yes, with caveats
Any license check that runs on the client can be bypassed on the client; the check's verdict ends
up as local state (keychain entries, in-memory flags) that a sufficiently skilled reverse engineer
can, in principle, satisfy locally. Two honest caveats: (a) the client logic *consumes* the
settings/accounts structures, so the gates must be **satisfied, not deleted** — naive removal of the
network code breaks the menu's own data expectations; and (b) this is real per-build reverse-
engineering work that must be redone on every update.

### 7.5 Bottom line
The functionality is 100% local; the server decides *who is allowed in*. Because the trust decision
executes on a machine the user controls, this design is a **speed bump, not a wall**. The same
applies to the pinned keys (§4, steps 5–6): pinning keys client-side stops *repointing the URL
alone* (see §8), but it cannot stop someone from repinning keys in a binary they fully control —
it can only stop them from forging responses that *unmodified* clients accept.

---

## 8. Case study: the `main` sample (URL-repointed build)

A second binary, `main`, was added to this repository and analyzed with the same toolkit
(`analysis/full.py`). Results:

| Property | `libloader` (original) | `main` (repointed) |
|---|---|---|
| sha256 | `1c8d169b…3c13` | `14d0c7df…f252` |
| Size | 4,722,272 bytes | 4,722,272 bytes (identical) |
| Bytes differing | — | **28 of 4,722,272**, all in range `0x34b0eb`–`0x34b106` |
| Base URL | `https://expert-kudu-234.convex.cloud` | **`https://iptvplayer.gt.tc`** (NUL-padded into the original 37-byte slot) |
| Decryption key for URL blob | `0x34dfee127bda54df` | unchanged |
| k1/k2 pinned keys | original values | **unchanged** |
| 32-hex secret, keychain names, endpoint, hook signatures, all 190 strings | original values | **unchanged** (full-report diff shows only the URL row differs) |

Interpretation — this is §7.5 made concrete:

- Only the URL was repointed. The pinned keys were **not** swapped, so this build still only trusts
  responses signed with the **original operator's private keys**.
- Therefore the new endpoint (`iptvplayer.gt.tc` — a subdomain on `gt.tc`, a free InfinityFree
  subdomain-hosting domain widely abused for phishing/scam campaigns) only works if it is operated
  by **the same Lynx vendor** (host migration off Convex), or the build is a **dud** whose
  validation fails closed.
- Had *all* pinned values been swapped (URL + k1/k2 + secret + keychain names), the modifier would
  control their own licensing authority — **for their modified copy only**. They would never obtain
  the original operator's private keys, and unmodified clients would continue to trust only the
  original backend.

This is exactly the "client-side trust is soft" conclusion of §7.5, observed in the wild.

---

## 9. Quick-reference tables

### 9.1 Who owns what

| Component | Owner | Location |
|---|---|---|
| Menu UI (ImGui/Metal/UIKit) | local | dylib `__text` + ObjC classes |
| Cheat engine (13 hook signatures, patching) | local | dylib + encrypted string table |
| Game knowledge (classes, events, assets) | local | encrypted string table |
| Feature configuration (`settings`) | **server-synced**, cached locally | keychain `lynx.cloud.settings` |
| Account/subscription state (`accounts`) | **server-synced**, cached locally | keychain `lynx.cloud.accounts` |
| Session token (`appToken`) | **server-issued**, cached locally | keychain |
| Clock authority (`serverTime`) | server | replayed in requests |
| Signature private keys | server only (never in the binary) | — |
| Signature **verification** | local | `sub_9ee84` / `sub_aa1a8` / `sub_b040c` vs pinned k1/k2 |

### 9.2 One-line answers

- **Where does the menu come from?** The dylib — compiled in at build time; the server cannot add,
  remove, or redraw a single menu element.
- **Where is "the verify"?** Entirely client-side: `sub_9f0a8` (key materialization) →
  `sub_9ee84`/`sub_aa1a8`/`sub_b040c` (pinned-key comparison) → keychain replay (`sub_a8b70`).
- **What does the web server give?** Entitlements, settings, accounts, server time, errors — data,
  never code.
- **What happens without the server?** The engine is all local; the gate's cached verdicts live in
  the keychain. Architecturally, a client-side gate can be defeated client-side — which is why this
  design is a speed bump, not a wall.

---

*All findings above are reproducible: `python3 analysis/full.py [binary] [report.txt]` regenerates
the full decrypted corpus, pinned-key decode, network-layer extraction, and hook-signature listing
for any of the binaries in this repository.*
