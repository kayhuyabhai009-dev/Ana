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

## What I verified / did not verify

- Verified: the string, the check logic, the hardcoded cert hash, the three code offsets; the
  patched dex re-parses cleanly and disassembles to the intended constants; the re-zipped APK
  contains the patched dex (sha256 match) and no stale signature.
- Not verified: installation on a real device / emulator (none here). This sandbox has no Java,
  apktool, apksigner or a reachable Debian mirror, so I could not build+sign a final APK myself.
  Signing must be done by your tool as above.
