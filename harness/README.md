# Attack harness — proves the findings against the APK's own code

This is not a re-implementation. The modules under test are **extracted byte-for-byte from
`shareslots_YAZGC3JD46R.apk`**, and the two suites execute them in Node 22 against
attacker-forged traffic.

The forgers deliberately use **independent implementations** (pycryptodome for the crypto,
hand-built parameter objects for the HTTP) so that agreement between the two stacks means
something rather than a shared bug.

## Run it

```bash
# prerequisites
python3 -m pip install --user --break-system-packages pycryptodome   # for forge.py

# the APK-derived modules are git-ignored; regenerate them first
python3 harness/extract.py work/dec/project.js work/dec/cocos2d-jsb.js

node harness/attack.js        # -> 12 passed, 0 failed
node harness/otp_attack.js    # -> 16 passed, 0 failed
```

`extract.py` is idempotent and safe to re-run; both suites pass from a clean regeneration.

---

## `attack.js` — the response-crypto suite (12 assertions)

Loads the APK's `response-decrypt.js` + `aes-gcm-decrypt.js` + bundled `crypto-js.min.js`.

| # | Assertion | Finding |
|---|---|---|
| 0 | `this.validateTimestamp(` appears **0** times | the 300 s TTL is **dead code** |
| 1 | envelope forged with the recovered APK keys | verifies **and** decrypts → full response forgery |
| 2 | `HMAC("abc",123) === HMAC("abc1",23)` | signature canonicalisation is ambiguous |
| 3 | plain JSON with no envelope | passes through with **zero** verification |
| 4 | identical envelope replayed 1 s later | replay works, unbounded |
| 5a | flipped byte + original signature | HMAC layer rejects ✓ |
| 5b | flipped byte + **re-signed** with the stolen key | GCM tag rejects ✓ |
| 5c | — | the primitives are sound; the defect is key management |
| 6 | forged envelope with `crypto.subtle` deleted | the CryptoJS fallback is equally forgeable |

5a/5b are included on purpose: they show the crypto is competently implemented, which is why
"the keys ship in the APK" is the single defect that matters.

## `otp_attack.js` — the HTTP transport suite (16 assertions)

Loads the APK's `Http` module with a stubbed XHR and captures the URL it actually builds.

| # | Assertion | Finding |
|---|---|---|
| 1 | `draw/order` is sent as **GET** | payment PIN, SMS OTP, phone, uid and session token all land in the query string; nothing in the body |
| 2 | `sms/index` is sent as **GET** | phone in the URL; no uid-scoped nonce or HMAC |
| 3 | `encodeURI`, not `encodeURIComponent` | `&admin=1` injected into a value survives as a real parameter |
| 4 | `onReadyStateChanged` | every response body is written to `console.log` |
| 5 | regex against the extracted module | the request log **is** gated by `Global.localVersion`; the response log is **not** |

---

## Files

| File | Origin |
|---|---|
| `attack.js` | authored — response-crypto suite |
| `otp_attack.js` | authored — HTTP transport suite |
| `forge.py` | authored — attacker-side envelope builder (pycryptodome) |
| `loader.js` | authored — minimal browserify module loader + Cocos shim |
| `extract.py` | authored — regenerates the six files below from the decrypted JS |
| `response-decrypt.js` | **extracted from the APK** (git-ignored) |
| `aes-gcm-decrypt.js` | **extracted from the APK** (git-ignored) |
| `crypto-js.min.js`, `crypto-js.js` | **extracted from the APK** (git-ignored) |
| `http.js` | **extracted from the APK** (git-ignored) |
| `tslib.js` | **extracted from the APK's `cocos2d-jsb.js`** (git-ignored) |

### Loader notes

`loader.js` wires the browserify parameter names as exactly `e, t, i`, because that is what the
shipped module bodies reference — any other naming makes every `e("dep")` / `t.exports`
reference undefined. It stubs `cc._RF.push/pop`, shims `require('crypto')` for CryptoJS's UMD
probe, and pulls `__awaiter` / `__generator` from the engine bundle.

`otp_attack.js` stubs its own `cc` because `Http` is a `cc.Class({statics: …})` rather than a
plain module — it needs `cc.Class`, `cc.Component`, `cc.loader.getXMLHttpRequest` and `cc._RF`.
