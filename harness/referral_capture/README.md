# ShareSlots — referral data capture

Goal: capture the app's referral / bank / withdraw traffic **without repacking the APK**
(repacking + patching OkHttp was crashing the app). Instead use the **original APK on a rooted
device with Frida** to bypass TLS pinning, and mitmproxy to record the traffic. Hot-update stays
ON, so add-bank/events keep working, and nothing crashes.

## Non-rooted phone (important)

This app targets **SDK 35** and pins its `wss` certificate. The referral data itself rides the
**WebSocket** (`refer_myreferrals`/`refer_myrewards`/`refer_makemoney`/`yd_rank_referrals` use WS
messages, zero HTTP calls — verified in the decrypted `project.js`). So to read referral data you
must decrypt `wss`, and on a **non-rooted** phone:

- Android (targetSdk ≥ 24) does **not** trust a user-installed CA, so a mitmproxy CA added in
  Settings is ignored for TLS.
- The `wss` socket is also certificate-pinned.

Result: **you cannot capture the referral `wss` traffic on a non-rooted stock phone** without
repacking the app to trust your CA / drop the pin. The repack that does this (`ShareSlots_full_
unsigned.apk`, OkHttp trust-all) crashed on your device, and I can't debug it without the device.

What DOES work on non-rooted, no repack: the **cleartext `http`** pay-server calls (withdraw
`draw/order`, `kyc/bind`, `user/banks` via `sendPayServer`) — just point the phone's Wi-Fi proxy at
`mitmdump -s mitm_referral.py`. No CA needed (plaintext). But that is **not** the referral list /
counts — those are on the `wss`.

### Practical routes to capture the referral `wss`

1. **Android emulator (recommended, free).** An AVD (Android Studio) or Genymotion is rootable /
   has a writable system. Install the mitmproxy CA into the **system** store, run `frida-server`
   or `objection … android sslpinning disable`, then `mitmdump -s mitm_referral.py`. No repack,
   no crash, full referral capture.
2. **Rooted device / second rooted phone.** Same as the emulator route.
3. **Repack with trust-all.** Possible but it crashed for you. If you want this, send me
   `adb logcat` from the crash and I'll fix the patch.

## Files

| File | What it does |
|---|---|
| `frida_capture.js` | Frida script: disables cert pinning (OkHttp `CertificatePinner`, hostname verifier, trust-all `HttpsURLConnection`) and logs referral/bank/withdraw HTTP calls to the console and `/data/local/tmp/referral_capture.log`. |
| `mitm_referral.py` | mitmproxy addon: writes every matching call to `referral_flows.jsonl` (full bodies) and a `referral_summary.csv` (uid, phone, referid, invit_uid, sharelink, count, total, today, code…). |

## Setup (rooted device)

1. **frida-server** on the device (match your Frida version), running as root:
   `adb push frida-server /data/local/tmp/ && adb shell su -c '/data/local/tmp/frida-server &'`
2. **mitmproxy** on the PC: `mitmdump -s mitm_referral.py` (note the printed CA).
3. Point the device's Wi-Fi proxy at the PC, and trust the mitmproxy CA
   (system store on root: `adb push mitmproxy-ca-cert.pem /system/etc/security/cacerts/…`).
4. Capture:
   ```
   frida -U -f com.shareslots.games.fun -l frida_capture.js
   ```
   Then use the app (referrals page, withdraw, add bank). Matching calls land in
   `referral_flows.jsonl` + `referral_summary.csv` next to mitmdump, and also in
   `/data/local/tmp/referral_capture.log`.

If you prefer objection over the script: `objection -g com.shareslots.games.fun explore` →
`android sslpinning disable`, then just run mitmdump with the addon.

## What to look for

Referral/attribution flows through the HTTP APIs (not the WebSocket):
`user/info`, `sharelink`/`REFER_LINK_UPDATE`, `refer_*`, `user/banks`, `kyc/bind`, `draw/order`.
The CSV pulls the fields that matter for referral counts: `referid`, `invit_uid`, `agent_uid`,
`count/total/today`, and the bound `phone`/`uid`.

## Notes / honesty

- This does **not** need the repacked APK. The earlier `ShareSlots_full_unsigned.apk` patched
  OkHttp inside the DEX and can crash — prefer this Frida path.
- `frida_capture.js` and `mitm_referral.py` are syntax-checked (`node --check`, `py_compile`).
  They are not run end-to-end here (no rooted device in this sandbox), so treat the exact
  hook targets as a starting point — if a hook misses, tell me the log line and I'll adjust.
- OTP: the mobile-verify screen does have an OTP field; the earlier report over-stated
  "no OTP". The precise client weakness is that `kyc/bind cat:"mobile"` submit does not require
  the OTP to be non-empty — server-side enforcement is the real control.
