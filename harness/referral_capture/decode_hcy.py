#!/usr/bin/env python3
"""
decode_hcy.py — decode an HttpCanary WebSocket export of ShareSlots into readable JSON.

HttpCanary exports a captured wss session as a folder of N.bin files (one per WS frame)
plus websocket.json. Each ShareSlots WS frame is:  [8-byte header][msgpack body].
This strips the header and msgpack-decodes the body, labels the command id (`c`) with the
referral MsgId names, and pulls out the player's referral identity.

Usage:
    python3 decode_hcy.py path/to/cap            # a folder containing session subfolders
    python3 decode_hcy.py path/to/cap/2          # a single session folder of *.bin

Writes decoded_frames.json next to the input and prints a summary + all referral frames.
"""
import sys
import os
import glob
import json

try:
    import msgpack
except ImportError:
    sys.exit("need msgpack:  pip install --user --break-system-packages msgpack")

# Referral / agent command ids (from project.js MsgIdDef)
REF_IDS = {
    254: "REFER_INFO", 267: "REFER_BROADCAST_INFO",
    370: "REF_RULE_CFG", 371: "REF_MY_REWARDS", 372: "REF_MY_REWARDS_DETAIL",
    373: "REF_MY_REFERRALS", 374: "REF_MY_REFERRALS_DETAIL", 375: "REF_CLAIM_REWARD",
    376: "REF_BOARDCAST", 377: "REF_LEADERBOARD_RWARDS",
}
HEADER = 8  # bytes of binary header before the msgpack body


def decode_frame(path):
    b = open(path, "rb").read()
    if len(b) <= HEADER:
        return None
    try:
        return msgpack.unpackb(b[HEADER:], raw=False, strict_map_key=False)
    except Exception as e:
        return {"_decode_error": str(e), "_hex": b[:32].hex()}


def session_dirs(root):
    # a session dir is one that directly contains *.bin
    if glob.glob(os.path.join(root, "*.bin")):
        return [root]
    out = []
    for d in sorted(glob.glob(os.path.join(root, "*"))):
        if os.path.isdir(d) and glob.glob(os.path.join(d, "*.bin")):
            out.append(d)
    return out or [root]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    root = sys.argv[1]
    frames = []
    for sd in session_dirs(root):
        meta = {}
        mj = os.path.join(sd, "websocket.json")
        if os.path.exists(mj):
            try:
                meta = json.load(open(mj))
            except Exception:
                pass
        bins = sorted(glob.glob(os.path.join(sd, "*.bin")),
                      key=lambda p: int(os.path.basename(p).split(".")[0])
                      if os.path.basename(p).split(".")[0].isdigit() else 0)
        for bp in bins:
            o = decode_frame(bp)
            if o is None:
                continue
            c = o.get("c") if isinstance(o, dict) else None
            frames.append({
                "file": os.path.relpath(bp, root),
                "c": c,
                "name": REF_IDS.get(c, ""),
                "body": o,
            })

    out = os.path.join(root, "decoded_frames.json")
    with open(out, "w") as f:
        json.dump(frames, f, ensure_ascii=False, indent=1, default=str)

    # ---- summary ----
    print(f"decoded {len(frames)} frames -> {out}")
    ident = None
    for fr in frames:
        b = fr["body"]
        if isinstance(b, dict) and isinstance(b.get("playerInfo"), dict):
            pi = b["playerInfo"]
            ident = {k: pi.get(k) for k in
                     ("uid", "playername", "code", "invit_uid", "isbindphone", "kyc", "fbrewards")}
    if ident:
        print("\nYour referral identity (from login response c=2):")
        print("  " + json.dumps(ident, ensure_ascii=False))

    ref = [fr for fr in frames if fr["c"] in REF_IDS]
    print(f"\nReferral frames found: {len(ref)}")
    if not ref:
        print("  (none) — open the My Referrals / My Rewards page while capturing to get "
              "c=373 REF_MY_REFERRALS and c=371 REF_MY_REWARDS")
    for fr in ref:
        print(f"\n== {fr['file']}  c={fr['c']} {fr['name']} ==")
        print(json.dumps(fr["body"], ensure_ascii=False, default=str)[:1500])

    # ---- referral list -> CSV rollup (c=371/373/374/376 carry lists of referees/earnings) ----
    rows = []
    LIST_IDS = {371, 372, 373, 374, 376, 267}
    for fr in frames:
        if fr["c"] not in LIST_IDS or not isinstance(fr["body"], dict):
            continue
        for v in fr["body"].values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                for item in v:
                    row = {"_c": fr["c"], "_name": fr["name"]}
                    row.update({k: val for k, val in item.items()
                                if not isinstance(val, (dict, list))})
                    rows.append(row)
    if rows:
        import csv
        cols = []
        for r in rows:
            for k in r:
                if k not in cols:
                    cols.append(k)
        csvp = os.path.join(root, "referral_data.csv")
        with open(csvp, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {len(rows)} referral rows -> {csvp}  (cols: {cols})")


if __name__ == "__main__":
    main()
