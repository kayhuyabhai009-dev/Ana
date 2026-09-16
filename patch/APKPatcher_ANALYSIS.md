# APKPatcher.jar — analysis (Techno India "APK Patcher")

`APKPatcher.jar` (7.1 MB, `Main-Class: com.apkpatcher.Main`) is a self-contained APK
patcher/hooker/signer. It bundles everything needed, so it runs on a PC with just a JRE:

| Bundled lib | Purpose |
|---|---|
| `com.android.tools.smali.dexlib2` | smali/baksmali — disassemble & re-assemble dex |
| `com.android.apksig` | APK signing (v1–v4) |
| `com.reandroid.apk` / `arsc` | APK + manifest + resources editor |
| `assets/AES.dex` | crypto/URL **logging** payload (`com.algorithm.hook.{CipherHook,SecretKeySpec,IvParameterSpec,URL}`) |
| `assets/PINE.dex` + `assets/Pine/{arm64-v8a,armeabi-v7a}/libpine.so` + `Pine/config.json` | **Pine** hook framework — runtime Java hooking **without root** |
| `assets/TG.dex` | Telegram/Plus patch |
| `assets/testkey.pk8` + `testkey.x509.pem` | the key it signs the output with |

`com.apkpatcher.dex.hook.DexHook` injects `AES.dex` / `PINE.dex` / `TG.dex` into the target APK
based on the flags; `com.apkpatcher.dex.patch.*` are the byte-level dex patches.

## Flags (from `com.apkpatcher.cli.help` / `Args`)

| Flag | What it does (verified in the patch classes) |
|---|---|
| `-i <apk>` | input APK / apks / apkm / xapk |
| `-m <apk>` | merge split APKs |
| `-ssl` | **cert pinning / SSL bypass** — patches `X509TrustManager.checkServerTrusted/checkClientTrusted` (the correct layer; on by default) |
| `-c <CA.pem\|0>` | use **your** CA certificate (for mitmproxy/HttpCanary) |
| `-v` | **VPN detection bypass** — patches `NetworkCapabilities.hasTransport(VPN)` / `NetworkInterface` |
| `-pkg` | **package / cloner detection spoof** — fakes `DETECTION_CLASSES`/`DETECTION_PACKAGES`, Xposed-style hooks |
| `-fix` | fix install — patches `PackageManager.getInstallerPackageName` |
| `-a` | **Algorithm Logs Inject** — injects `AES.dex` hooks on Cipher/SecretKeySpec/IvParameterSpec/URL → runtime crypto/URL logging |
| `-pine` / `-pine2` | inject **Pine** hook framework (`libpine.so`+`PINE.dex`) → runtime hooking without root |
| `-l <path>` | path to Xposed/LSP module (with pine) |
| `-id` | hook Android ID (one-device login bypass) |
| `-rmads` / `-rmss` / `-rmusb` | bypass ads / screenshot restriction / USB-debugging restriction |
| `-paid` | purchase-status (view paid course) |
| `-tg` | Telegram/Plus patcher |
| `-u` | keep the output **unsigned** |
| `-h` | help |

It signs the result with the bundled `testkey` unless `-u`.

## Recommended command (everything asked for, hot-update stays ON)

```
java -jar APKPatcher.jar -i "Share Slots after hot update.apk" -ssl -v -pkg -fix -a -pine -c <yourCA.pem>
```

- `-ssl -c <CA>` → SSL/pinning bypass with your capture CA
- `-v` → VPN detection removed
- `-pkg -fix` → cloner/package + installer detection removed
- `-a -pine` → runtime crypto/URL logging + hook framework (no root)
- none of these touch `openUpdate`, so **hot-update stays ON** (add-bank/events keep working)
- output is auto-signed with the bundled testkey

Read runtime logs with `adb logcat` (no root needed). If the app's own signature/cloner screen
still shows after patching, the cloner-fix smali in `patch/smali/` can be applied on top.

## Why the hand-patched `ShareSlots_full_unsigned.apk` crashed

That build patched OkHttp `CertificatePinner.check` / `OkHostnameVerifier.verify`. The app's `wss`
pin is enforced at the **TrustManager** layer, and OkHttp is also used by the cleartext pay API —
so patching OkHttp was both the wrong layer for the pin and risky for normal traffic. APKPatcher's
`-ssl` patches the TrustManager directly, which is the correct, safer approach.
