# Attack harness — proves the encryption findings against the APK's own code

This is not a re-implementation. `response-decrypt.js`, `aes-gcm-decrypt.js` and
`crypto-js.min.js` are the **byte-for-byte modules extracted from
`shareslots_YAZGC3JD46R.apk`**, and `attack.js` executes them in Node 22 against
attacker-forged traffic.

`forge.py` deliberately uses **pycryptodome** — an independent crypto stack — so that
agreement between the two implementations means something.

## Run it

```bash
# prerequisites
python3 -m pip install --user --break-system-packages pycryptodome   # for forge.py

# the APK-derived modules are git-ignored; regenerate them first
python3 harness/extract.py work/dec/project.js work/dec/cocos2d-jsb.js

node harness/attack.js
```

Expected output: `12 passed, 0 failed`.

## What each assertion proves

| # | Assertion | Finding |
|---|---|---|
| 0 | `this.validateTimestamp(` appears 0 times | the 300 s TTL is **dead code** |
| 1 | forged envelope verifies + decrypts | static keys in the APK ⇒ full response forgery |
| 2 | `HMAC("abc",123) === HMAC("abc1",23)` | signature canonicalisation is ambiguous |
| 3 | plain JSON passes through untouched | encryption is **opt-out** |
| 4 | identical envelope accepted 1 s later | replay works, unbounded |
| 5a | flipped byte + old signature → HMAC rejects | integrity layer 1 works |
| 5b | flipped byte + re-signed → GCM tag rejects | integrity layer 2 works |
| 5c | — | the cipher is sound; the defect is key management |
| 6 | forged envelope accepted with `crypto.subtle` removed | the CryptoJS fallback is equally forgeable |

Tests 5a/5b are included on purpose: they show the crypto is competently implemented,
which is why "the keys ship in the APK" is the single defect that matters.

## Files

| File | Origin |
|---|---|
| `attack.js` | authored — the test suite |
| `forge.py` | authored — attacker-side envelope builder (pycryptodome) |
| `loader.js` | authored — minimal browserify module loader |
| `extract.py` | authored — regenerates the four files below from the decrypted JS |
| `response-decrypt.js` | **extracted from the APK** (git-ignored) |
| `aes-gcm-decrypt.js` | **extracted from the APK** (git-ignored) |
| `crypto-js.min.js`, `crypto-js.js` | **extracted from the APK** (git-ignored) |
| `tslib.js` | **extracted from the APK's `cocos2d-jsb.js`** (git-ignored) |

`loader.js` wires the browserify parameter names as exactly `e, t, i` because that is
what the shipped module bodies reference, and shims `require('crypto')` for CryptoJS's
UMD probe.
