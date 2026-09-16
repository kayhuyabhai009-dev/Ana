# ShareSlots — deep protocol & crypto analysis (informs frida_full.js)

Source: decrypted `assets/src/project.jsc` (XXTEA key `b32a2160-0c63-41` → gunzip → 2.98 MB JS).
The "Share Slots after hot update.apk" on the repo has the **same bundled jsc** (hot-update writes
to device storage, not the APK) and a dex that differs only by the 3 cloner-fix byte patches
(offsets 951360 / 954780 / 955018). So this analysis applies to both APKs.

## 1. Transport / protocol

| Channel | Host | Encoding | Encrypted? |
|---|---|---|---|
| Game + referral WebSocket | `wss://ga4.wfvbu98d.com/ws` (login addr `lo.wfvbu98d.com`, no port → `isUserWSS`=true → wss + cert pin) | `[8-byte header][msgpack]` | **No** — body is plaintext msgpack (`_msgPack = require("msgpack.min")`) |
| Pay / KYC / withdraw HTTP | `http://ifs.wfvbu98d.com` (cleartext) | query (GET) / form (POST) | request params plaintext; **responses** optionally AES-GCM (see §3) |
| OTP | `https://service.fewhu37a1.com/sms/dosend` | — | TLS |

- WS receive (`handleResponeData`): `DataView`, **skip 8 bytes**, `Uint8Array(len-8)` → `_msgPack.decode` → `_doHandleMsg`. The 8-byte header is discarded (no checksum/length/ts validation).
- WS send (`send`): builds `{c:<MsgId>, …}`, sets `c_ts`, `c_idx`, `uid`; for `MsgId.LOGIN` adds `x = md5(c_ts + getSalt())` where **salt = `hero888`**.
- HTTP (`sendPayServer` → `requestHttp` → `Cocos2dxHttpURLConnection`): GET puts params in the query; POST sends a form body. Adds `uid`, `token`, `lang`.

## 2. Keys / secrets (all static, `uncompile`-decoded)

| Secret | Value | Use |
|---|---|---|
| jsc XXTEA key | `b32a2160-0c63-41` | decrypts `project.jsc` (and the other 8 `.jsc`) |
| `P_K` | `rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z` | `ResponseDecryptClient.k` (HTTP response AES-GCM) |
| `P_AK` | `j39qexkacw7gtnzrnnlwuibjnd494xhw` | `ResponseDecryptClient.ak` |
| WS salt | `hero888` | login `x = md5(ts + salt)` |
| response TTL | `300` s | replay window declared (but `validateTimestamp` is dead code) |

`responseDecryptClient = new ResponseDecryptClient({ k: uncompile(P_K), ak: uncompile(P_AK), timestampTtl: 300 })`
(`./charge/response-decrypt`, using `aes-gcm-decrypt`). All crypto is **JS-level** (CryptoJS /
browserify AES-GCM / HMAC), not `javax.crypto` — so it does not appear in Java crypto hooks; the
keys above are the runtime secrets.

## 3. When are HTTP responses encrypted?

`sendPayServer` prefixes the pay api with `v1/` and decrypts via `responseDecryptClient.decryptResponse`
**only when `UserManager.responseDecryptClient` is set** (it is, at init). So `…/v1/<endpoint>`
responses are AES-GCM ciphertext; non-`v1` responses are plaintext JSON. The WebSocket is never
encrypted at the application layer (plaintext msgpack over TLS).

## 4. MsgId map (WS `c` field) — referral block (confirmed against a live capture)

| c | name | payload |
|---|---|---|
| 254 / 267 | REFER_INFO / REFER_BROADCAST_INFO | agent info / broadcast |
| 370 | REF_RULE_CFG | commission config (bet/recharge/invite ratios, tax) |
| 371 | REF_MY_REWARDS | `{total{bet,tax,reg,buy,bonus,cash}, today{…}, bonus, cash, data[]}` |
| 373 | REF_MY_REFERRALS | `{total, today, data[]}` — **the referral list/counts** (rtype 1 = my refs, 2 = friends) |
| 374 | REF_MY_REFERRALS_DETAIL | per-referee detail |
| 375 | REF_CLAIM_REWARD | `{rewards[]}` (`spcode 339` = nothing to claim) |
| 376 | REF_BOARDCAST | live feed of others' referral earnings |
| 377 | REF_LEADERBOARD_RWARDS | leaderboard |

(Full 547-id enum saved during analysis; numbers collide across enums, so use the WS-protocol
names above, which were verified against real `c=370/371/373/375/376` frames.)

## 5. The no-OTP bank/phone bind (referral-count abuse path)

| Endpoint | Payload | OTP |
|---|---|---|
| `kyc/bind` `cat:"mobile"` | `{mobile, passwd, code, name}` | `code` sent but client never requires it non-empty → empty OTP accepted |
| `kyc/bind` `cat:"bank"` | `{account, ifsc, branch, pic, cnic, bank_code}` | none |
| `user/editCard` (withdraw verify, code 601) | `{id, cardnum, cnic, bank_code?}` | none, no password |

So a number/bank can be bound from the withdrawal flow without OTP — the control that referral
counting relies on. `frida_full.js` flags this with `[RT][BIND] otp_code_EMPTY=true`.

## 6. What frida_full.js captures vs. this analysis

- `[RT][WS]` → the plaintext msgpack frames (referral `c=370..377`, game, auth) — decode with
  `harness/referral_capture/decode_hcy.py`.
- `[RT][HTTP]` → `Cocos2dxHttpURLConnection` request URL/body + response. Requests are plaintext
  (so `kyc/bind`, `draw/order`, `user/editCard` params are visible). `v1/` responses are AES-GCM —
  decrypt offline with `P_K`/`P_AK` if needed.
- `[RT][CRYPTO]` → any `javax.crypto` use (the app's crypto is JS, so this is a safety net).
- Keys are static (§2) — no runtime extraction needed.
