# ShareSlots APK — Deep Security Analysis

**Target:** `shareslots_YAZGC3JD46R.apk`
**SHA/MD5:** `62aa898d77bd8c9a55d0be4316b56282` · 35,846,164 bytes
**Package:** `com.shareslots.games.fun` · versionName `1.1.7` · versionCode `117`
**minSdk** 21 · **targetSdk** 35 · Cocos Creator 2.x (JS) game
**Scale:** 544 project script modules · 245 hot-update game packs · 835 scenes

---

## 0. How this analysis was done (and verified)

The repo contained **only the APK** — no source. Everything below came from reversing the APK.

1. Extracted the APK. The game logic is 9 `.jsc` files — **XXTEA-encrypted, then gzip-compressed** JavaScript.
2. Located the key statically: `jsb_set_xxtea_key` is exported at `0x6e74ec`; its single caller is `0x3330c0` (via PLT stub `0x313100`), which loads a string literal from `.rodata` at `0x112cb05`:

   ```
   0x3330a8  adrp x1, #0x112c000
   0x3330b0  add  x1, x1, #0xb05     ; -> 0x112cb05
   0x3330b8  bl   #0x3204b0          ; std::string ctor
   0x3330c0  bl   #0x313100          ; jsb_set_xxtea_key(...)
   ```
   `.rodata` at that address: `Cocos Game\0` `b32a2160-0c63-41\0` `jsb-adapter/jsb-builtin.js\0`
3. Re-implemented XXTEA by transcribing the actual decrypt core at `0x70b834` (two details that differ from textbook XXTEA: the `y` register is initialised **once** before the round loop, and the `p == 0` step uses `z = v[n-1]`, not `z = v[0]`; the trailing length word must lie in `[n-7, n-4]`).
4. **Verification — passed:** re-encrypting the decrypted gzip stream reproduces **all 9 original `.jsc` files byte-for-byte**.

   ```
   XXTEA key: b32a2160-0c63-41
   md5.min.jsc    re-encrypt byte-identical: True
   sha512.min.jsc re-encrypt byte-identical: True
   qrcode.jsc     re-encrypt byte-identical: True
   async.min.jsc  re-encrypt byte-identical: True
   runtime.jsc    re-encrypt byte-identical: True
   cocos2d-jsb.jsc re-encrypt byte-identical: True
   physics.jsc    re-encrypt byte-identical: True
   project.jsc    re-encrypt byte-identical: True   (2,983,995 bytes of JS)
   settings.jsc   re-encrypt byte-identical: True
   ```
5. Decompiled `AndroidManifest.xml` with androguard; decoded the app's own string-obfuscation and round-trip-verified it (all 7 constants re-encode to the exact shipped strings).

**Bottom line up front:** the app's cryptography is *correctly implemented but structurally useless* — every key is static and embedded in the APK, the main transport is plaintext HTTP, and the code-delivery channel is unauthenticated HTTP. A determined attacker gets full remote code execution and can read/forge wallet traffic.

---

## 1. Severity summary

| # | Finding | Severity |
|---|---|---|
| 1 | Hot-update ships **executable JS over plaintext HTTP** with self-referential integrity | **Critical** (RCE) |
| 2 | Hot-update `verifyCallback` **skips MD5** for `compressed` assets and all `.manifest` files | **Critical** |
| 3 | Static AES-256 + HMAC keys embedded in the APK; "obfuscation" is a trivial delta cipher | **Critical** |
| 4 | Response encryption is **optional** — unencrypted responses are accepted unchecked | **Critical** |
| 5 | **Payment PIN + security answers sent in plaintext** to `draw/setpasswd` | **High** |
| 6 | WebSocket protocol has **no MAC / no encryption** — 2-byte CRC-16 only | **High** |
| 7 | Login anti-replay token = `md5(timestamp + "hero888")` — hardcoded salt | **High** |
| 8 | `usesCleartextTraffic=true` + network-security-config `cleartextTrafficPermitted="true"` for **all** domains | **High** |
| 9 | `allowBackup="true"` — tokens extractable via `adb backup` | **High** |
| 10 | Guest account token generated client-side from `Math.random()` | **High** |
| 11 | Referral attribution fully client-controlled (`itcode` query param / install referrer) | **High** (fraud) |
| 12 | FileProvider exposes **all of external storage** (`external-path path="."`) | **Medium** |
| 13 | Exported `BROWSABLE` deep link `shareslots://shareslots.com` | **Medium** |
| 14 | HMAC signature: no field separator, non-constant-time compare, no nonce | **Medium** |
| 15 | Key material, IVs, signature prefixes and **plaintext samples** logged to logcat | **Medium** |
| 16 | No request signing / no idempotency keys on wallet endpoints | **Medium** |
| 17 | Hot-update `versionComHandle` always returns "local is older" | **Medium** (bug) |
| 18 | `Http` never URL-encodes values → base64 image uploads corrupt | **Medium** (bug) |
| 19 | `invit_uid` overwritten with boolean `true` → referral analytics corruption | **Medium** (bug) |
| 20 | Null-deref crashes in `refer_myrewards` / `SetCoin` | **Low** (bug) |

---

## 2. Encryption analysis

### 2.1 What the app actually does

| Layer | Algorithm | Verdict |
|---|---|---|
| Script protection | XXTEA + gzip | Broken — key in `.rodata` |
| Config obfuscation | delta-chain + `escape()` | Broken — no key at all |
| HTTP response | AES-256-GCM + HMAC-SHA256 | Sound primitives, broken key management |
| WebSocket | **none** | Broken |
| Payment PIN | **none** | Broken |
| Local storage | same delta-chain as config | Broken |

### 2.2 Recovered secrets

Extracted from `GlobalVar` (`project.js:33734-33745`) and decoded via the app's own `Global.uncompile`:

```js
h.compile = function (e) {           // project.js:32558
  for (var t = String.fromCharCode(e.charCodeAt(0) + e.length), i = 1; i < e.length; i++)
    t += String.fromCharCode(e.charCodeAt(i) + e.charCodeAt(i-1));
  return t = escape(t);
};
```

This is a **keyless** running-delta cipher. It is not encryption — it is a one-line de-obfuscation away.

| Constant | Decoded value |
|---|---|
| `P_K` (HMAC-SHA256 key) | `rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z` |
| `P_AK` (AES-256-GCM key) | `j39qexkacw7gtnzrnnlwuibjnd494xhw` |
| `apiUrl` | `http://ifs.wfvbu98d.com` ← **plaintext HTTP** |
| `loginServerAddress` | `lo.wfvbu98d.com` |
| `haoUrl` | `https://ifs.wfvbu98d.com/hao.html` |
| `otpurl` | `https://service.fewhu37a1.com/sms/dosend` |
| `downloadurl` | `https://www.shareslots.app` |
| XXTEA script key | `b32a2160-0c63-41` |

Both `P_K` and `P_AK` are 32 ASCII chars → 256-bit keys, but they are **the same for every install of the app, forever**. Anyone who unpacks one APK can decrypt and forge every wallet response for every user. Rotating them requires shipping a new APK.

### 2.3 The AES-GCM code itself is good — the key management is not

`response-decrypt.js` + `aes-gcm-decrypt.js` are genuinely competent:

- `aesDecrypt` uses WebCrypto `AES-GCM` when available, with a hand-rolled CryptoJS fallback.
- I audited the fallback GCM: `H = AES_ECB(0^128)` ✓, `J0 = IV || 0x00000001` ✓, CTR starts at `J0+1` ✓, GHASH uses the correct `0xE1000000` reduction constant ✓, length block is `len(AAD)=0 || len(C)*8` ✓, and the tag compare `L |= E[T] ^ s[T]` is **constant-time** ✓.
- 12-byte IV required and enforced ✓.

**The design fails in four ways regardless:**

**a) The envelope is opt-out.** `sendPayServer` (`project.js:80226-80262`):

```js
if (t && cc.vv.UserManager.responseDecryptClient && u(n)) {   // u = isEncryptedResponse
    n = await cc.vv.UserManager.responseDecryptClient.decryptResponse(n);
}
i(t, n);   // <-- if u(n) is false, raw JSON goes straight to business logic
```

`isEncryptedResponse` only returns true when the body has `data:string`, `timestamp:number`, `signature:string`. A man-in-the-middle simply **omits the envelope** and returns plain JSON — no signature is checked, ever. Combined with `apiUrl` being `http://`, the entire response-authentication layer can be bypassed by deleting three fields.

**b) Signature canonicalisation is ambiguous** (`response-decrypt.js`):

```js
n = e + t;                      // data + timestamp, NO separator
o = await this.hmacSha256(n, this.k);
s = i === o;                    // non-constant-time compare
```

`{data:"abc", timestamp:123}` and `{data:"abc1", timestamp:23}` produce the identical signed string. Any HMAC-valid payload can be re-split. Use a canonical encoding (`JSON.stringify({data, timestamp, nonce})`) and a constant-time compare.

**c) No nonce, 5-minute replay window.** `timestampTtl: 300`. A captured response is replayable for 5 minutes — long enough to re-trigger a "withdrawal approved" or "bonus credited" UI state repeatedly.

**d) Requests are never signed.** Only responses are. There is no request MAC, no anti-replay, and no idempotency key on `draw/*`, `user/balance`, `user/feedback`, or `index/uploadFile`. Auth is just `uid` + `token` as ordinary request parameters (`project.js:80224-80225`).

### 2.4 Secrets logged to logcat

Both crypto modules have verbose debug logging that ships enabled:

```js
i("decrypt.enter", "keyLen=" + (e && e.length), "ivLen=" + (t && t.length), ...);
a("validateSignature", { ok: s, sigPrefix: i && i.substring(0,16), expectPrefix: o && o.substring(0,16) });
a("aesDecrypt.native.success", { textSample: new TextDecoder().decode(c).substring(0,32) });
```

The **expected signature prefix** and a **32-char plaintext sample** of every decrypted wallet response are written to the system log. On any rooted device, or via `adb logcat` on a debuggable build, that leaks live wallet data.

---

## 3. Referral system analysis

**Modules:** `refer_makemoney`, `refer_myreferrals`, `refer_myrewards`, `refer_rule`, `refer_Leadboard_Claim`, `referlink_feedback`, `yd_rank_referrals`, `ReferRewardDetail(Item)`, `ReferAddTips`, `InviteCode`, `InviteBonus`, `PBInviteFriends`, `PBPopupInvite`.

**How it works:** the server issues a `sharelink`; the user shares it via WhatsApp / Facebook / Telegram / system share / copy. Rewards are bucketed into `reg` (registration), `buy` (deposit), `bet` (rake), `tax`, and settled into `cash` + `bonus`, claimed with `MsgId.REF_CLAIM_REWARD`.

### What is done right
- Reward amounts are computed server-side. `onClickClaim` sends `{c: MsgId.REF_CLAIM_REWARD}` with **no amount** — the client cannot inflate its own payout.
- Balances come from `REF_MY_REWARDS` responses, not local state.
- `referlink_feedback` validates the phone against `Global.Phonecheck = /^\d{10}$/` before submitting.

### 3.1 Attribution is entirely client-controlled (fraud)

The invite code is bound in `bindCode()` (`project.js:30356`):

```js
bindCode: function () {
  if (!cc.vv.UserManager.invit_uid) {
    var e = cc.vv.PlatformApiMgr.GetChannelStr() || Global.ItCode;
    if (e) { var t = { c: MsgId.EVENT_FB_INVITE_BIND_CODE }; t.code = e; t.vid = "-1"; ... }
```

Two sources, both attacker-influenceable:

- **Web build** — `Global.ItCode = this.getQueryVariable("itcode")` (`project.js:29266`). Any URL `?itcode=VICTIM` sets the inviter. Trivially scriptable for mass self-referral farming.
- **Native build** — `GetChannelStr()` → Java `getChannelstr()`, i.e. the Play **install referrer**. The app even declares `com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE`. The referrer string is supplied by whoever initiates the Play Store install (`referrer=…`), so an affiliate can force arbitrary attribution.

Because `vid` is hardcoded `"-1"`, the server receives no independent device/vendor identity to cross-check. Combined with §4.3 (predictable guest tokens), the referral economy is exploitable end-to-end: mint guest accounts → bind them all to one code → harvest `reg` rewards.

**Fix:** bind the inviter server-side from a signed, single-use, server-issued token; never trust a client-supplied code alone. Tie credit to verified events (KYC'd deposit) rather than registration.

### 3.2 `invit_uid` is overwritten with a boolean (attribution corruption)

```js
// project.js:29635  — login: correct, stores the real id
cc.vv.UserManager.invit_uid = e.playerInfo.invit_uid;

// project.js:30093  — after binding an invite code: WRONG, stores `true`
OnRcvNetBindInviteCode: function (e) {
  if (200 == e.code) {
    cc.vv.UserManager.invit_uid = !0;        // <-- boolean, not the uid
```

That same field is then reported as analytics (`project.js:24379`):

```js
StatisticsMgr.reqReport(StatisticsMgr.REQ_ENTER_HALL, JSON.stringify({
  chcode: cc.vv.PlatformApiMgr.GetChannelStr(),
  ivtuid: cc.vv.UserManager.invit_uid        // reports `true` instead of the inviter id
}));
```

So for every user who binds a code in-session, your referral attribution pipeline records `ivtuid: true`. Your referral ROI numbers are wrong for exactly the cohort that matters. Separately, `if (!invit_uid)` overloads the field as a boolean flag — a legitimate inviter id of `0` or `""` would be treated as "not invited" and allow re-binding.

**Fix:** use two fields: `invit_uid` (the real id, never overwritten) and `invit_bound` (boolean).

### 3.3 Referral share text is not integrity-protected
`_getShareContent()` / `REFER_LINK_UPDATE` accept a server-supplied `sharelink` and hand it to `openURL` / `WebWhatsApp`. If the server (or a MITM on the unencrypted channel) returns a malicious link, the app will happily deep-link users to it and label it as the official referral link.

---

## 4. Coin / wallet system analysis

### 4.1 Server-authoritative balances — good
```js
MONEY_CHANGED: function (e) { if (200 === e.code) {
  void 0 != e.bankcoin && cc.vv.UserManager.setBankCoin(e.bankcoin);
  void 0 != e.coin     && cc.vv.UserManager.SetCoin(e.coin, !0);
  void 0 != e.diamond  && cc.vv.UserManager.setDiamond(e.diamond, !0);
}},
SetCoin: function (e, t) { this.coin = Number(e.toFixed(2)); t && Global.dispatchEvent(EventId.UPATE_COINS); }
```
`coin` is display state only; withdrawal eligibility is re-checked server-side via `PreReqDrawAlltypes` → `draw/alltypes`. That is the right architecture.

**But** — see §5. Because the WebSocket carries no MAC, an on-path attacker can inject a forged `SYNC_COIN` frame and make the client display any balance. Real funds are unaffected, but it is a potent social-engineering / support-scam primitive ("the app said I had ₹50,000").

### 4.2 Payment PIN sent in plaintext
`safecenter_setPIN.js:396/412/467`:

```js
var v = {};
v.passwd  = p;              // the 6-digit Payment PIN, raw
v.question = this._ques;
v.answer   = this._ans;     // security-question answers, raw
cc.vv.UserManager.sendPayServer("draw/setpasswd", v, ..., "POST");
```

No hashing, no client-side encryption, no envelope on the **request**. This is the withdrawal PIN for a real-money app.

### 4.3 Client-side PIN-recovery lockout
```js
this._maxErrorCount = Global.localVersion ? 2 : 5;
...
if (n.data && void 0 !== n.data.remaining_attempts) a = n.data.remaining_attempts;
else { t._questionErrorCount = (t._questionErrorCount||0) + 1; a = t._maxErrorCount - t._questionErrorCount; }
if (t._questionErrorCount >= t._maxErrorCount) { /* lock out */ }
```
When the server does not return `remaining_attempts`, the lockout lives **entirely in the client**. A patched APK removes it, leaving a 10⁶-keyspace 6-digit PIN. I could not test the server, so I flag it as: *ensure the server enforces its own counter and ignores the client's.*

### 4.4 Guest identity is forgeable
`autoTravellerLogin` (`project.js:30722-30728`):
```js
o = new Date().getTime() + "_" + Global.random(1, 99999999);
n[t] = { token: o };
Global.saveLocal(Global.SAVE_PLAYER_TOKEN, JSON.stringify(n));
```
`Global.random` is `Math.floor(Math.random() * (t-e+1) + e)` — a non-cryptographic PRNG with ~26 bits of entropy plus a millisecond timestamp the attacker already knows. If the server treats this token as account identity, guest accounts are enumerable/collidable. Guest is the default onboarding path, so this is high-impact.

### 4.5 Credentials at rest
Tokens land in `localStorage` via `Global.saveLocal` → `compile()` (the keyless delta cipher) → `cc.sys.localStorage.setItem`. Stored: `SAVE_PLAYER_TOKEN`, `localtoken`, `recent_uid`, `SAVE_KEY_REQ_LOGIN` (the full login request including device id), `phNum` (phone number).

With `android:allowBackup="true"`, all of it is retrievable with `adb backup` on a USB-debugging-enabled device.

### 4.6 Wallet endpoints are not idempotent
`draw/*`, `charge/*`, `user/balance`, `index/uploadFile` are called with plain `uid`+`token` params and no request signature or idempotency key. A captured withdrawal request is replayable until the token expires.

---

## 5. Transport & hot-update (the most serious issue)

### 5.1 Executable code over HTTP

From the shipped `Manifest/Main/project.manifest` (uuid `aaa4f37b-49ac-4725-b535-4c9c724ebfd6`):

```json
{
  "version": "1.1.5.4",
  "name": "Main",
  "packageUrl":       "http://ifs.vfwhi09sj.com/GameX/1.1.5.4/Main",
  "remoteVersionUrl": "http://ifs.vfwhi09sj.com/GameX/Main/version.manifest",
  "remoteManifestUrl":"http://ifs.vfwhi09sj.com/GameX/Main/project.manifest",
  "assets": {
    "src/project.jsc":     { "size": 694148,  "md5": "d69248b897fac3f12408816a22b7a0bf" },
    "src/cocos2d-jsb.jsc": { "size": 395868,  "md5": "deb782ee4183055b9e1433eed4d55bf9" },
    ...
```

The hot-updater downloads **`src/project.jsc` — the entire 3 MB of game and wallet JavaScript — over plaintext HTTP.** The only integrity check is an MD5 that comes from `project.manifest`, fetched from the *same HTTP origin*. That is self-referential and provides **zero** security.

Anyone on the same Wi-Fi, a rogue AP, a compromised router, or a DNS-spoofing position serves their own `project.jsc` and the app executes it. Full RCE in the app's context: read the stored token, read the Payment PIN as it is typed, rewrite withdrawal destinations, silently drain referral rewards.

### 5.2 The verify callback is bypassable by the attacker

`hotupdate.js`:
```js
verifyCallback: function (e, t) {
  var i = t.compressed, a = (t.md5, t.path), o = t.size;
  if (i) { AppLog.log("Verification passed : " + a); return !0; }   // (1) manifest says "compressed" -> NO CHECK
  if (Global.APPID.TestCashHero == Global.appId) return !0;          // (2) test build -> NO CHECK
  if (".manifest" == cc.path.extname(a)) return !0;                  // (3) manifests -> NO CHECK
  var s = jsb.fileUtils.getWritablePath() + "remote-asset_temp/" + a;
  if (jsb.fileUtils.isFileExist(s)) return n(jsb.fileUtils.getDataFromFile(s)) === t.md5;
  return !1;
}
```
`compressed` is a field **in the remote manifest**. The attacker who controls the manifest controls the flag. Marking every asset `compressed: true` disables verification completely.

### 5.3 Broken version comparator (functional bug + downgrade enabler)

```js
versionComHandle: function (e, t) {          // e = local, t = remote
  for (var i = e.split("."), n = t.split("."), a = 0; a < i.length; ++a) {
    if (parseInt(i[a]) !== parseInt(n[a])) return -1;    // ALWAYS "local older"
  }
  return n.length > i.length ? -1 : 0;
}
```
It never returns `+1`. Any difference — including the local version being **newer** — reports "local is older". Also, when the remote has fewer segments, `parseInt(n[a])` is `NaN`, so `1.1.5.4` vs `1.1.5` → `-1`. Consequences: update loops that never settle, and a MITM can **downgrade** a client to an older, vulnerable bundle without the comparator noticing.

### 5.4 WebSocket protocol: no authentication, no integrity

`NetProtocol.js` frame layout:

```
[2 bytes: payload length][2 bytes: srcSum][payload: msgpack(JSON)][4 bytes: timestamp]
```

`srcSum` is a CRC-16-style checksum (poly `0x70D1`), not a MAC — and it is computed over only the **first `min(len, 128)` bytes**:
```js
function o(e, t) {
  var i; i = t < 128 ? Global.srcSum(e, t) : Global.srcSum(e, 128);   // <-- truncated
  return Global.jsToCByShort(i);
}
```
Any frame over 128 bytes has most of its payload uncovered even by the checksum.

Inbound handling (`NetManager.handleResponeData`):
```js
var n = new Uint8Array(e.byteLength - 8);       // strip 8-byte header
var o = t._msgPack.decode(n);
t._doHandleMsg(o);                              // -> JSON.parse -> handleMsg
```
No signature, no decryption, no origin check. Outbound (`NetManager.send`):
```js
e.c_ts = new Date().getTime();
e.c == MsgId.LOGIN && (e.x = md5(e.c_ts.toString() + this.getSalt()));
...
getSalt: function () { return "hero888"; },
```
**The login anti-replay token is `md5(timestamp + "hero888")`** — a hardcoded 7-char salt. Anyone can mint valid login tokens offline. All non-login messages carry no integrity tag at all, just a client-supplied `e.uid = Global.playerData.uid`.

`ws://` vs `wss://` is decided by `isUserWSS`, which merely checks for a `:` in the host:
```js
h.isUserWSS = function (e) { var t = !1, i = cc.vv.UserManager.parseUrl(Global.loginServerAddress);
  e && (i = e); -1 === i.indexOf(":") && (t = !0); return t; };
```
`lo.wfvbu98d.com` has no colon, so WSS is used today — but the decision is a string heuristic, not a policy, and there is no HSTS or pinning enforcement in JS (the Android path passes `resources/common/cert.pem`, iOS does not).

### 5.5 HTTP client weaknesses
`Http.js`:
```js
_url: "192.168.0.158:80",                     // hardcoded dev LAN default
...
var h = "";
for (var _ in t) { "" != h && (h += "&"); h += _ + "=" + t[_]; }   // NO encodeURIComponent
if ("GET" == o) (u += "?" + encodeURI(h));
r && d.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
if ("POST" == o) d.send(h);
...
if (e.status >= 200 && e.status < 400) {      // 3xx treated as success
```
- **Values are never percent-encoded.** `encodeURI` does not escape `&`, `=`, `+`, `#`, so any value containing them can inject extra parameters.
- `referlink_feedback` and the charge modules POST base64 images (`data:image/png;base64,...`) as a form field. Base64 contains `+`, which `application/x-www-form-urlencoded` decodes as a **space** → silent image corruption and upload failures.
- Accepting `3xx` as success means a redirect returns an empty body, `JSON.parse` throws, and the caller gets a generic error.

### 5.6 Verbose logging in production
`Global.localVersion` gates: `console.log("#######request url:" + u + " => " + JSON.stringify(t))` and `console.log("http res(" + e.responseText.length + "): " + e.responseText)`. `localVersion` is `false` in the shipped `GlobalVar`, so this is currently off — but it is one flag away from dumping every request and response.

---

## 6. Android platform configuration

Decoded from `AndroidManifest.xml` and `res/8G.xml`:

```xml
<application android:allowBackup="true"
             android:usesCleartextTraffic="true"
             android:networkSecurityConfig="@xml/network_security_config"
             android:extractNativeLibs="true"
             android:requestLegacyExternalStorage="true" ...>
```
```xml
<!-- res/8G.xml -->
<network-security-config>
  <base-config cleartextTrafficPermitted="true"/>
</network-security-config>
```
```xml
<!-- res/8m.xml  (myFileProvider paths) -->
<paths>
  <external-cache-path name="shared_images" path="."/>
  <external-path       name="external_files" path="."/>   <!-- ALL of external storage -->
  <cache-path          name="internal_cache" path="."/>
</paths>
```
```xml
<activity android:name="org.cocos2dx.javascript.AppActivity">
  <intent-filter>
    <action   android:name="android.intent.action.MAIN"/>
    <action   android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.LAUNCHER"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="shareslots" android:host="shareslots.com"/>
  </intent-filter>
</activity>
```

Issues:
- **`cleartextTrafficPermitted="true"` in `base-config`** — HTTP allowed to every domain, with no `domain-config` restrictions and no custom `trust-anchors`. This is what makes §5.1 and §5.4 practically exploitable rather than merely theoretical.
- **`allowBackup="true"`** — combined with §4.5, tokens/phone/uid are recoverable via `adb backup`.
- **FileProvider `external-path path="."`** — exposes the whole of external storage to any app granted one of these URIs. Scope it to a dedicated subdirectory.
- **Exported `BROWSABLE` deep link** — `shareslots://shareslots.com` can be invoked by any app or web page. Whatever it routes into is reachable without user intent.
- **`requestLegacyExternalStorage="true"`** — legacy scoped-storage bypass on API 29.
- Permissions are otherwise reasonable (INTERNET, ACCESS_NETWORK_STATE, WAKE_LOCK, VIBRATE, POST_NOTIFICATIONS, AD_ID, C2DM_RECEIVE, BIND_GET_INSTALL_REFERRER_SERVICE). No READ_SMS, no contacts, no location — good.

**Signing certificate:**
```
issuer == subject:  CN=lamislot, OU=lamislot, O=lamislot, L=ls, ST=ls, C=65
serial: 1850588837   valid: 2020-04-27 → 2045-04-21   rsassa_pkcs1v15
v1: yes   v2: yes   v3: no
```
Self-signed, and the identity says **`lamislot`**, not `shareslots` — this is a white-label build signed with another product's key. The country code `65` is not a valid ISO-3166 alpha-2 code. Worth confirming you control this keystore: it is the only thing preventing anyone from shipping an "update" to your users. There is no v3 signing block, so no key-rotation capability.

---

## 7. Concrete bugs (non-security)

| Location | Bug |
|---|---|
| `refer_myrewards._showRewads` (L99-101) | `var i = this._serverData.today \|\| null;` then `1 == e ? i = this._serverData.total \|\| null : ...` — if `total` is missing, `i` stays `null` and the next line does `i.cash` → **TypeError, panel crashes**. |
| `refer_myrewards._showCanRecvInfo` | `this._serverData.cash + this._serverData.bonus` → `NaN` when either is absent; the claim button then stays disabled with no explanation. |
| `UserManager.SetCoin` | `Number(e.toFixed(2))` throws if the server ever sends `coin` as a string or omits it. |
| `refer_myreferrals` (L121) | `total_page = Math.ceil(e.total / e.limit)` → `Infinity`/`NaN` if `limit` is 0 or absent. |
| `refer_myreferrals.onClickPageNext` | Reads `this._servData.total_page` with no null guard — crashes if tapped before the first response. |
| `Http.sendReq` | No `encodeURIComponent` on values; base64 `+` corrupts uploads (§5.5). |
| `hotupdate.versionComHandle` | Never returns `+1`; `NaN` comparison when segment counts differ (§5.3). |
| `GameManager` L30093 | `invit_uid = !0` overwrites the real inviter id (§3.2). |
| `getQueryVariable` | Never `decodeURIComponent`s the value — encoded chars arrive raw. |
| `Http._url` | Hardcoded `"192.168.0.158:80"` fallback. |

---

## 8. Remediation, in priority order

### P0 — do this week
1. **Move hot-update to HTTPS** and **sign the manifest**. Ship an RSA/Ed25519 public key in the APK; sign `project.manifest` server-side; verify the signature before applying. MD5-of-itself is not integrity.
2. **Fix `verifyCallback`** — never skip verification for `compressed` assets or `.manifest` files. Remove the `TestCashHero` short-circuit from release builds.
3. **Set `cleartextTrafficPermitted="false"`** and add explicit `domain-config` entries. Set `usesCleartextTraffic="false"`.
4. **Rotate `P_K`, `P_AK` and the XXTEA key**, and stop shipping long-lived static keys. Derive a per-session key via ECDH at login; keep the static value only for the handshake.
5. **Make response encryption mandatory.** Reject any wallet response that lacks the envelope, rather than silently passing it through.
6. **Hash the Payment PIN** client-side (SRP, or at minimum `scrypt(PIN, per-user-salt)`) and send only a verifier. Never send `answer[]` in the clear.
7. **Set `android:allowBackup="false"`.**

### P1 — this sprint
8. **Sign the WebSocket.** Wrap each frame in HMAC-SHA256 (or better, run the socket over TLS end-to-end and add a per-message MAC). Cover the *entire* payload, not the first 128 bytes.
9. **Replace `"hero888"`** with a per-session key negotiated at connect.
10. **Issue guest tokens server-side** from a CSPRNG with ≥128 bits; never derive identity from `Math.random()`.
11. **Fix referral attribution** — server-issued, signed, single-use invite tokens; don't trust `itcode` / install referrer alone; separate `invit_uid` from `invit_bound`.
12. **Add request signing + idempotency keys** to all `draw/*` and `charge/*` calls.
13. **Add a nonce** to the response envelope and shrink the TTL; use a canonical signing payload and constant-time comparison.
14. **Scope the FileProvider** paths to a dedicated subdirectory.
15. **Strip the debug logging** from `response-decrypt.js` / `aes-gcm-decrypt.js` (no plaintext samples, no signature prefixes, no key lengths).

### P2 — hygiene
16. `encodeURIComponent` every request value; fix the base64 upload path (send as `multipart/form-data` or a JSON body).
17. Fix `versionComHandle` to return `+1` / `0` / `-1` correctly and handle unequal segment counts.
18. Add the null guards listed in §7.
19. Remove the `192.168.0.158:80` default and the `TestCashHero` bypass from release builds.
20. Add APK Signature Scheme **v3** so you can rotate the signing key; confirm you control the `lamislot` keystore.
21. Consider ProGuard/R8 + a real JS obfuscator. Be clear-eyed: with keys in the binary this only raises cost, it does not create security.

### The structural point
Items 1-6 are not independent. Today a single MITM position yields: arbitrary code execution (§5.1) → which yields the stored token (§4.5) → which yields wallet API access with no request signing (§2.3d) → over a channel whose authentication can be switched off by omitting three JSON fields (§2.3a). **Fixing the transport is the precondition for everything else mattering.**

---

## Appendix A — reproducing the decryption

```bash
# key recovered from libcocos2djs.so .rodata @ 0x112cb05, referenced by the
# only caller of jsb_set_xxtea_key (call site 0x3330c0 via PLT 0x313100)
KEY='b32a2160-0c63-41'

# each .jsc is: XXTEA_encrypt( gzip( javascript ) )
# trailing 4-byte little-endian length word must satisfy  n*4-7 <= len <= n*4-4
```

Two non-obvious details in this build's XXTEA (transcribed from `0x70b834`):
- `y` is initialised to `v[0]` **once**, before the round loop, and then carries across rounds.
- The `p == 0` step uses `z = v[n-1]`, not the carried `z = v[0]` that textbook XXTEA implies.
- `sum` initialises to `(6 + 52/n) * DELTA` (the compiler emits this as `(52/n)*0x9e3779b9 + 0xb54cda56`).

## Appendix B — recovered constants

| Key | Value |
|---|---|
| XXTEA script key | `b32a2160-0c63-41` |
| `P_K` (HMAC-SHA256) | `rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z` |
| `P_AK` (AES-256-GCM) | `j39qexkacw7gtnzrnnlwuibjnd494xhw` |
| `apiUrl` | `http://ifs.wfvbu98d.com` |
| `loginServerAddress` | `lo.wfvbu98d.com` |
| `haoUrl` | `https://ifs.wfvbu98d.com/hao.html` |
| `otpurl` | `https://service.fewhu37a1.com/sms/dosend` |
| `downloadurl` | `https://www.shareslots.app` |
| hot-update `packageUrl` | `http://ifs.vfwhi09sj.com/GameX/1.1.5.4/Main` |
| WebSocket salt | `hero888` |
| HTTP dev fallback | `192.168.0.158:80` |
| signing cert CN | `lamislot` (self-signed, serial 1850588837) |

**These are now public.** Treat every one as compromised and rotate.
