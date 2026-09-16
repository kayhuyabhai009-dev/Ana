# ShareSlots_logger_unsigned.apk — runtime logging build

An unsigned APK that logs **all runtime traffic** to logcat, so you can analyse requests,
responses and the (decrypted) WebSocket protocol **without root and without storage permission**.
You sign it yourself (e.g. `java -jar APKPatcher.jar -i ShareSlots_logger_unsigned.apk` or apksigner).

## What's inside (vs. the original APK)

| Change | Layer | Why |
|---|---|---|
| Cloner/signature checks disabled | `classes.dex` (3 methods → constants) | so the repack runs |
| `console.log("[RT-WS-RECV] …")` | jsc, `handleResponeData` | logs every **incoming** WS frame (decrypted plaintext) |
| `console.log("[RT-WS-SEND] …")` | jsc, `send` | logs every **outgoing** WS message (JSON) |
| `console.log("[RT-HTTP-REQ] …")` | jsc, `Http.sendReq` | logs every HTTP request (method, url, body) |
| `console.log("[RT-HTTP-RES] …")` | jsc, `onReadyStateChanged` | logs every HTTP response (status + body) |
| `wss` cert pin removed | jsc, `connect` | so a MITM CA is accepted if you also capture |
| `openUpdate: !1` (hot-update OFF) | jsc | **required** — the logging lives in the script that hot-update would otherwise replace |

Trade-off: because the logging is in the bundled script, **hot-update is OFF in this build**
(add-bank/events driven by hot-update won't appear). For a hot-update-ON build with logging you
need APKPatcher's `-a -pine` (it injects hooks at the dex/native layer instead).

## Use it

1. Sign:
   ```
   java -jar APKPatcher.jar -i ShareSlots_logger_unsigned.apk
   ```
   (or `apksigner sign --ks my.keystore ShareSlots_logger_unsigned.apk`)
2. Install: `adb install -r ShareSlots_logger_unsigned.apk`
3. Capture logs (no root, no storage permission needed):
   ```
   adb logcat -c && adb logcat | grep "\[RT-" > runtime.log
   ```
   Then use the app. `runtime.log` fills with `[RT-WS-RECV]`, `[RT-WS-SEND]`, `[RT-HTTP-REQ]`,
   `[RT-HTTP-RES]` lines.

## Reading the logs

- `[RT-HTTP-REQ/RES]` are plain JSON/text — the pay API (`ifs.wfvbu98d.com`): withdraw, kyc/bind,
  banks, user info.
- `[RT-WS-RECV/SEND]` are the game/referral protocol **after** msgpack decode (the `[RT-WS-RECV]`
  line is the decoded object). Referral messages are `c=370..377` (see
  `harness/referral_capture/decode_hcy.py` for the id map). Open **My Referrals / My Rewards** to
  see `c=373`/`c=371`.

## Verified / not verified

- jsc round-trips: re-decrypt+gunzip shows all four `[RT-*]` tags, `openUpdate:!1`, no `cert.pem`.
- `classes.dex` re-parses with androguard; the three cloner methods disassemble to the intended
  constants.
- **Not** install/run-tested (no device or signer in this sandbox).
