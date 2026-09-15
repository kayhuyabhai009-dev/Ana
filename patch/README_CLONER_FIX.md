# Why the SSL-bypass APK says "Share Slots can not run at this mode!" — and the fix

## Root cause (verified)

The launcher shows that dialog when `_isClonerAPP()` returns true
(`work/dec/project.js:29230-29237`):

```js
_isClonerAPP: function() {
  if (Global.isAndroid()) {
    var e = cc.vv.PlatformApiMgr.GetChannelStr();
    if (cc.vv.PlatformApiMgr.IsCloner() || !e && 11 == Global.cAppid) return !0;
  }
},
```

For this build `Global.cAppid` is **211**, so the `11 == cAppid` clause is always false.
The **only** trigger is `IsCloner()` — the native signature check.

`ProjUtil.isCloner(Context)` calls `checksignture(Context)`, which does:

```
base64( SHA1( signing-cert.toByteArray() ) ) == "3jMaDJlNnNJSjitwqDprP53dyxc="
```

(recovered verbatim from `classes.dex`). Any tool that re-signs the APK — including
`APKPatcher.jar`, which must re-sign after applying the SSL bypass — produces a cert whose
SHA-1/base64 no longer equals that constant, so `checksignture` → false → `isCloner` → true →
the dialog.

**So the error is the app's own anti-repackaging check firing on your patched APK. It is not a
bug in your SSL bypass.**

## The fix — neutralise three methods

| Class | Method | New body |
|---|---|---|
| `org/cocos2dx/javascript/ProjUtil` | `isCloner(Landroid/content/Context;)Z` | `const/4 v0,0; return v0` |
| `org/cocos2dx/javascript/ProjUtil` | `checksignture(Landroid/content/Context;)Z` | `const/4 v0,1; return v0` |
| `org/cocos2dx/javascript/PlatformAndroidApi` | `isCloner()I` | `const/4 v0,0; return v0` |

Two ways to apply it (identical result):

1. **Byte-level (already applied here).** `classes.dex.patched` has these three code items
   overwritten (`12 00 0f 00` / `12 10 0f 00`) and the DEX header SHA-1 + Adler32 recomputed.
   Verified: the patched dex re-parses with androguard and each method disassembles to
   `const/4 v0,…; return v0`.

2. **apktool.** Replace the three methods with the files in [`smali/`](smali/), then rebuild.

## Producing the final APK

`ShareSlots_clonerfix_unsigned.apk` in this folder = the original APK with `classes.dex`
replaced by `classes.dex.patched` and the stale `META-INF/{CERT.SF,CERT.RSA,MANIFEST.MF}`
removed. It is **unsigned** — feed it to your existing `APKPatcher.jar` (which applies the SSL
bypass and re-signs), or sign it yourself:

```bash
apksigner sign --ks my.keystore --out final.apk patch/ShareSlots_clonerfix_unsigned.apk
# or:  java -jar uber-apk-signer.jar -a patch/ShareSlots_clonerfix_unsigned.apk
```

Because the cloner check is now neutralised in the DEX, the re-signed result will boot past the
"can not run at this mode!" screen. The SSL bypass is unchanged from whatever your patcher does.

### Optional: keep the SSL bypass after re-sign (for apktool users)

The manifest already sets `usesCleartextTraffic="true"` with a base cleartext policy. To also
trust a MITM user CA over HTTPS/`wss`, add to `res/xml/network_security_config.xml`:

```xml
<base-config cleartextTrafficPermitted="true">
    <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>
    </trust-anchors>
</base-config>
```

## Part 2 — "disconnect from network, please reconnect" when capture is ON

**Root cause (verified).** With the cloner check fixed, the next blocker when you turn a capture
proxy (HttpCanary / Charles / Burp) on is TLS **certificate pinning** on the login WebSocket.
`NetManager.connect` (`project.js:51278`) pins a bundled cert on Android:

```js
Global.isAndroid() && a
  ? this._ws = new WebSocket(n + this._address + "/ws", [], cc.url.raw("resources/common/cert.pem"))
  : this._ws = new WebSocket(n + this._address + "/ws");
```

When capture is on, the proxy presents its own CA, which does not match the pinned `cert.pem`
(`assets/res/raw-assets/85/85de80f7-….pem`), so the `wss://` handshake fails → socket error →
heartbeat times out → "Your network has been disconnected, please reconnect" (`:38890`).
There is **no explicit proxy/VPN detection** in the DEX — the "proxy" strings are all okhttp
internals.

**Fix (applied in `project.jsc.patched`).** I decrypted the bundled `assets/src/project.jsc`
with the recovered XXTEA key, made two text edits, re-gzipped and re-encrypted:

1. **Remove the pin** — the pinned branch is replaced by the unpinned one, keeping `wss://`:
   `this._ws = new WebSocket(n + this._address + "/ws");`
   Now the socket uses default trust. With capture off the real cert validates via system CAs;
   with capture on your MITM CA validates (provided your patcher's `network_security_config`
   trusts `user` CAs).
2. **Disable hot-update** (`openUpdate: !0` → `!1`) so the server cannot push the original,
   still-pinned `project.jsc` over the patched one after launch.

Verified: the new `project.jsc` decrypts + gunzips cleanly and contains the unpinned connect and
`openUpdate: !1`, with `cert.pem` gone from the connect call.

**`ShareSlots_capturefix_unsigned.apk`** = original APK with BOTH the patched `classes.dex`
(Part 1) and patched `assets/src/project.jsc` (Part 2), stale signature removed. Sign it with
your `APKPatcher.jar` / `apksigner` as in Part 1. It boots past the cloner screen **and** stays
connected while capture is on.

### Trade-off to know

Disabling hot-update means the app will run the bundled script version and will not pull script
updates from the server. For traffic-analysis this is what you want (it also keeps the pin off);
just be aware the in-app version string stays at the bundled build.

---

## What I verified / did not verify

- Verified: the string, the check logic, the hardcoded cert hash, the three code offsets; the
  patched dex re-parses cleanly and disassembles to the intended constants; the re-zipped APK
  contains the patched dex (sha256 match) and no stale signature.
- Verified (capture fix): the bundled `project.jsc` decrypts with the recovered key, the pinned
  connect branch and `openUpdate` are edited, and the re-encrypted jsc round-trips (decrypt +
  gunzip) with `cert.pem` removed and `openUpdate: !1`; the final APK contains it (sha256 match).
- Not verified: installation on a real device / emulator (none here). This sandbox has no Java,
  apktool, apksigner or a reachable Debian mirror, so I could not build+sign a final APK myself.
  Signing must be done by your tool as above.
