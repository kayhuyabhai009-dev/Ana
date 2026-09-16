"""
mitm_referral.py — mitmproxy addon that captures ShareSlots referral / bank / withdraw
traffic into a JSONL log and a CSV summary you can open in a spreadsheet.

Run:
    mitmdump -s mitm_referral.py --set block_global=false
(With the app on a rooted device whose proxy points at this mitmproxy, and TLS pinning
bypassed via frida_capture.js.)

Outputs (in the current dir):
    referral_flows.jsonl   every matching request+response, full body
    referral_summary.csv   one row per matching call with the fields we care about
"""
import json
import csv
import os
import time

from mitmproxy import http

# Endpoints of interest (substring match on the URL)
KEYS = (
    "refer", "invite", "sharelink", "draw", "user/banks", "kyc",
    "user/info", "share", "agent", "bonus", "commission", "order",
)

JSONL = "referral_flows.jsonl"
CSV = "referral_summary.csv"
FIELDS = [
    "ts", "method", "path", "status",
    "uid", "phone", "referid", "invit_uid", "sharelink",
    "agent_uid", "agent_name", "count", "total", "today", "code",
]

_wrote_header = os.path.exists(CSV)


def _interesting(url: str) -> bool:
    u = url.lower()
    return any(k in u for k in KEYS)


def _dig(obj, *keys):
    """Return the first present key from a (possibly nested) dict."""
    if not isinstance(obj, dict):
        return ""
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    # one level of nesting (data/detail/result)
    for wrap in ("data", "detail", "result"):
        sub = obj.get(wrap)
        if isinstance(sub, dict):
            for k in keys:
                if k in sub and sub[k] not in (None, ""):
                    return sub[k]
    return ""


def response(flow: http.HTTPFlow):
    url = flow.request.pretty_url
    if not _interesting(url):
        return

    req_body = flow.request.get_text(strict=False) or ""
    resp_body = flow.response.get_text(strict=False) or "" if flow.response else ""

    parsed = {}
    try:
        parsed = json.loads(resp_body)
    except Exception:
        pass

    rec = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "method": flow.request.method,
        "url": url,
        "status": flow.response.status_code if flow.response else "",
        "req": req_body[:4000],
        "resp": resp_body[:20000],
    }
    with open(JSONL, "a") as f:
        f.write(json.dumps(rec) + "\n")

    # CSV summary — query params + parsed JSON fields
    q = {k: v[0] for k, v in flow.request.query.items(multi=True)} if hasattr(flow.request.query, "items") else {}
    src = {**q, **(parsed if isinstance(parsed, dict) else {})}

    global _wrote_header
    with open(CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        if not _wrote_header:
            w.writeheader()
            _wrote_header = True
        w.writerow({
            "ts": rec["ts"],
            "method": rec["method"],
            "path": flow.request.path.split("?")[0],
            "status": rec["status"],
            "uid": _dig(src, "uid", "userId", "user_id"),
            "phone": _dig(src, "phone", "mobile"),
            "referid": _dig(src, "referid", "refer_id", "invite_code"),
            "invit_uid": _dig(src, "invit_uid"),
            "sharelink": _dig(src, "sharelink", "share_link", "link"),
            "agent_uid": _dig(src, "agent_uid", "parent_uid"),
            "agent_name": _dig(src, "agent_name", "username", "name"),
            "count": _dig(src, "count", "num", "list_count"),
            "total": _dig(src, "total", "total_bonus"),
            "today": _dig(src, "today", "today_bonus"),
            "code": _dig(src, "code"),
        })
