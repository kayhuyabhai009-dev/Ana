# ShareSlots — Deep Dive: Referral System & Encryption

Companion to `SECURITY_ANALYSIS.md`. Everything here is from the decrypted `project.js`
(2,983,995 bytes, recovered with XXTEA key `b32a2160-0c63-41`, verified by byte-exact
re-encryption of all 9 `.jsc` files).

**New in this pass — empirically proven, not just read:**
> I loaded the APK's **actual** `response-decrypt.js` + `aes-gcm-decrypt.js` + bundled
> `crypto-js.min.js` into Node 22 and ran them against attacker-forged traffic.
> **12 / 12 assertions pass.** See §B5.

---

# PART A — THE REFERRAL SYSTEM

## A1. Complete component inventory

The referral feature is 14 Cocos components plus 5 message handlers in `UserManagerEx`:

| Module | MsgIds it registers | MsgIds it sends |
|---|---|---|
| `refer_makemoney` | `REFER_LINK_UPDATE` 364, `REQ_BING_TG_BOT` 392 | `REQ_BING_TG_BOT` 392 |
| `refer_rule` | `REF_RULE_CFG` 370, `REF_BOARDCAST` 376 | both (via `sendAndCache`) |
| `refer_myreferrals` | `REF_MY_REFERRALS` 373, `REF_MY_REFERRALS_DETAIL` 374 | both |
| `refer_myreferrals_item` | — | `REF_MY_REFERRALS_DETAIL` 374 |
| `refer_myrewards` | `REF_MY_REWARDS` 371, `REF_MY_REWARDS_DETAIL` 372, `REF_CLAIM_REWARD` 375, `REF_REWARDS_LASTDAY` 379 | all four |
| `refer_myrewards_item` | — | `REF_MY_REWARDS_DETAIL` 372 |
| `refer_Leadboard_Claim` | `REFER_LINK_UPDATE` 364, `REF_LEADERBOARD_CLAIM` 378 | 378 |
| `yd_rank_referrals` | `EVENT_GET_RANK_INFO`, `REF_LEADERBOARD_RWARDS` 377, `REF_LEADBOARD_LASTWEEK` 214 | all three |
| `yd_rank_Leadboard_Claim` | — | `REF_LEADERBOARD_CLAIM` 378 |
| `ReferRewardDetail` / `ReferRewardDetailItem` | — | — |
| `ReferAddTips`, `common_sharefriends` | — | — |
| `GameManagerEx` | `EVENT_FB_INVITE_BIND_CODE` 257 | 257 |
| `UserManagerEx` | `GAME_SHARE_REWARD` 191 | — |

**Message-ID namespace is a mess.** `MsgIdDef.js` + `MsgIdConfig.js` define **638 names over
515 numeric IDs — 117 collisions.** Most are dead names left over from merged white-label
codebases (`CashHero`, `BalootClient`, `YD_Pro`, `PH_`, `LM` prefixes all coexist). Filtering
to IDs where **both** names are actually referenced in code leaves **4 live collisions**:

| id | name A | name B |
|---|---|---|
| 169 | `EVENT_FEEDBACK` | `USER_FEEDBAKC` *(sic)* |
| 270 | `FRIEND_LIST` | `REQ_FRIENDS_LIST` |
| 273 | `SOCIAL_FRIEND_HANDLE_ADD` | `REQ_ADD_FRIENDS` |
| **1070** | **`CHANGE_BONUS_LIST`** | **`TASK_COMPLETE_NOTIFY`** |

### A1.1 The 1070 collision directly corrupts the referral bonus pool

Both are registered in `UserManagerEx.init`:

```js
L79315:  cc.vv.NetManager.registerMsg(MsgId.CHANGE_BONUS_LIST,    this.CHANGE_BONUS_LIST,    this);
L79325:  cc.vv.NetManager.registerMsg(MsgId.TASK_COMPLETE_NOTIFY, this.TASK_COMPLETE_NOTIFY, this);
```

`handleMsg` dispatches to **every** handler in the bucket — the loop only breaks if a handler
returns exactly `1`, and neither does:

```js
var o = this._handlers[i];
for (a = o.length - 1; a >= 0; a--) {
  if ((s = o[a])._tgt) { if (1 == s._fn.bind(s._tgt)(Global.copy(e))) break; }
  ...
}
```

Consequences, both live:

- Server sends **`TASK_COMPLETE_NOTIFY`** → `CHANGE_BONUS_LIST(e)` also runs:
  ```js
  CHANGE_BONUS_LIST: function(e) {
    if (200 == e.code) { cc.vv.UserManager.bonusList = e.bonuslist;   // undefined
                         Global.dispatchEvent("BONUS_CHANGE"); } }
  ```
  `bonusList` is wiped to `undefined` and `BONUS_CHANGE` fires → the bonus UI re-renders empty.
  **`bonus` is one of the two referral payout buckets** (`cash` + `bonus`), so this corrupts the
  referral rewards panel every time a task completes.
- Server sends **`CHANGE_BONUS_LIST`** → `TASK_COMPLETE_NOTIFY(e)` also runs, which loads the
  `TaskCompleteHint` prefab and calls `.run(e)` with a bonus-list payload.

**Fix:** renumber. Add a build-time assertion that no two `MsgId.*` names share a value.

## A2. The commission model, extracted in full

`refer_rule.showRebetCfg()` renders the server's `REF_RULE_CFG` payload, which fully documents
your economics. Anyone who unpacks the APK learns the whole program:

```
cfg.invite.coin         fixed reward per referral
cfg.invite.rtype        1 -> "reg_actype2"   3 -> "reg_actype1"   else "Registration"
cfg.invite.prop[0..1]   split between Cash Balance / Cash Bonus (as ratios)
cfg.recharge[0..2].ratio    tier A / B / C commission on referral deposits
cfg.bet[0..2].ratio         tier A / B / C commission on referral wager (rake rebate)
cfg.tax[0..2].ratio         tier A / B / C commission on referral tax/rake
cfg.recharge_needpay        minimum deposit before commission accrues
cfg.tips                    free-text
```

Three tiers (A/B/C) × four revenue events (register / deposit / bet / tax), each with an
independent cash-vs-bonus split. Reward detail records carry `action ∈ {1=Registration,
2=Deposit, 3=Bet, 4=Tax}`, `cash`, `bonus`, `date` (`YYYYMMDD` as a number), `uid`.

## A3. Attribution chain — every client-controlled input

```
                    ┌─ web:    ?itcode=<ANYTHING>          project.js:29266
invite code source ─┤
                    └─ native: Play install-referrer channel string
                               (GetChannelStr -> Java getChannelstr())
                                        │
                                        ▼
        bindCode()  project.js:30356
          if (!cc.vv.UserManager.invit_uid) {
            var e = GetChannelStr() || Global.ItCode;
            if (e) send({ c: 257, code: e, vid: "-1" });      // vid hardcoded
          }
                                        │
                                        ▼
                        OnRcvNetBindInviteCode (257)
                          cc.vv.UserManager.invit_uid = !0;   // <-- boolean, see A3.2
```

Every input on this path is attacker-supplied. There is no server-issued, signed, single-use
invite token anywhere in the client.

### A3.1 `vid` is hardcoded to `"-1"`
The bind request carries no independent device or vendor identity for the server to
cross-check. Combined with §A7 (client-asserted shares) and predictable guest tokens
(`Date.now() + "_" + Math.random(1, 99999999)`), the referral economy is farmable end-to-end.

### A3.2 `invit_uid` is clobbered with a boolean
```js
project.js:29635   cc.vv.UserManager.invit_uid = e.playerInfo.invit_uid;  // real id  ✓
project.js:30093   cc.vv.UserManager.invit_uid = !0;                      // boolean  ✗
```
The same field is then reported as attribution:
```js
project.js:24379   ivtuid: cc.vv.UserManager.invit_uid     // -> "ivtuid": true
```
**Your referral attribution records `ivtuid: true` for every user who binds a code in-session** —
precisely the converting cohort. The field is also overloaded as a boolean gate
(`if (!invit_uid)`), so a legitimate inviter id of `0` or `""` reads as "not invited" and
permits re-binding.

**Fix:** split into `invit_uid` (never overwritten) and `invit_bound` (boolean).

### A3.3 Attribution token is client-controlled on web
```js
Global.aftoken = this.getQueryVariable("aftoken");
...
getADTrackId: ... cc.sys.isBrowser ? Global.aftoken || "" : ...
getKoTrackUUID: ... cc.sys.isBrowser ? Global.aftoken || "" : ...
```
`?aftoken=<anything>` sets the AppsFlyer attribution token. `getQueryVariable` also never
`decodeURIComponent`s, so encoded values arrive still-encoded.

## A4. The reward-claim path has no idempotency guard — anywhere

`Global.onClick` and `Global.btnClickEvent` are raw event wiring with **zero debounce**:
```js
Global.onClick = function(e, t, i, n) { var a = cc.find(e, t); a && a.on("click", i, n); };

h.btnClickEvent = function(e, t, i, n) {
  var a = t.bind(i);
  e.on("click", function(t) { ...play sound...; a(t); });   // no throttle
};
```
A `Global.delayInteractable(node, 0.5)` helper **exists** but none of the claim handlers use it.
I audited every `onClickClaim` in the app — **6 of 6 are unguarded**:

| Module | Sends | Guard? |
|---|---|---|
| `refer_myrewards` | `{c: REF_CLAIM_REWARD}` | none |
| `refer_Leadboard_Claim` | `{c: 378, id}` | none |
| `yd_rank_Leadboard_Claim` | `{c: 378, id, tag:"claim"}` | none |
| `PromoCode_Item` | `{c: PROMO_CODE_USE, id}` | none |
| `return_rewards` | `{c: REQ_RETURN_REWARDS_CLAIM}` | none |
| `yd_bonus_task` | `{c: EVENT_BIG_TASK_REWARD, taskid}` | none |

A fast double-tap fires two requests before the first response lands. `refer_myrewards` is the
worst case because it claims the **entire** `cash + bonus` balance in one call and then
optimistically zeroes the local value only in the response handler:
```js
onClickClaim: function() {
  cc.vv.RedHitManager.setKeyVal("agent_reward", 0);
  cc.vv.NetManager.send({ c: MsgId.REF_CLAIM_REWARD });
}
REF_CLAIM_REWARD: function(e) {
  if (200 == e.code && e.rewards) { ...; this._serverData.cash = 0; this._serverData.bonus = 0; ... }
}
```
Note also that `yd_rank_Leadboard_Claim` sends `tag:"claim"` while `refer_Leadboard_Claim` sends
no `tag` for the same MsgId 378 — the server must be inferring intent from an optional field.

**Fix:** disable the button on first tap, set an `_inFlight` flag, and — the part that actually
matters — make the server claims idempotent on a client-generated request id.

### A4.1 Client sends which record to claim / whose detail to read
```js
refer_myreferrals_item:  sendAndCache({ c: REF_MY_REFERRALS_DETAIL, referid: this.data.uid });
refer_myrewards_item:    sendAndCache({ c: REF_MY_REWARDS_DETAIL,  date:    this.data.date });
refer_Leadboard_Claim:   send({ c: 378, id: this._sData.id });
```
`referid` is a **user id chosen by the client**. If the backend does not verify that `referid`
is one of the caller's own referrals, this is an IDOR that enumerates the whole user base's
referral earnings. I cannot test the server from here — flagging as an open question that must
be confirmed server-side.

## A5. The response cache is never invalidated — proven

`NetManager.sendAndCache` is used by nearly every referral screen. `cacheList` has exactly
three touch points in the entire codebase:

```
51028:  cacheList: [],          // declaration
51515:  this.cacheList.push(n); // the ONLY write
51535:  var t, i = a(this.cacheList);   // read (getCacheObj)
```

**No TTL. No expiry. No clear. No invalidation on any event.** It is a permanent, unbounded,
process-lifetime cache. The replay path:

```js
n.c_idx = this._idx;
this.send(e, t);                       // fresh request goes out...
if (n.msg) {                           // ...and the STALE cached response is replayed NOW
  n.msg.c_idx = -1;
  this.handleMsg(n.msg);
}
```

Concrete failure in `refer_myrewards`:
1. User opens the panel → `sendAndCache({c: 371})` → cache populated, ₹500 claimable shown.
2. User claims. Local `cash`/`bonus` zeroed by the response handler.
3. User re-opens the panel → `onEnable` → `sendAndCache` finds the cache entry →
   **immediately replays the stale ₹500 response** → the claim button re-enables
   (`interactable = t > 0`) with the old balance.
4. If the fresh request then fails (timeout / reconnect), the handlers never run
   (`if (200 == e.code)`), so **the stale ₹500 stays on screen permanently.**

Secondary: the cache callback is registered **high-priority and never unregistered**
(`registerMsg(n.parm.c, n.callback, this, !0)`), and `cacheIdxList` grows without bound
(L51524) — a slow leak proportional to browsing, since `refer_myreferrals_item` creates a new
entry per `referid` viewed.

**Fix:** add a TTL, invalidate on every mutating response, and cap `cacheIdxList`.

## A6. Share rewards are self-asserted by the client

`LMSlots_BigWinShare` grants a reward for sharing a big win:

```js
t && Global.isNative() && cc.vv.FBMgr.fbShareWeb(t, null, "", function(t) {
  cc.vv.NetManager.send({ c: MsgId.GAME_SHARE_REWARD, gameid: i, cat: e.type });
});
```

and `FBMgr.shareResultCall` invokes that callback **unconditionally**:

```js
shareResultCall: function(e) {
  var t = e.result + "";
  if ("1" == t) { cc.vv.FloatTip.show("Sharing success！"); Global.saveLocal("doShareAction", 1); }
  this._shareEndCall && this._shareEndCall(e);   // <-- runs on FAILURE too
}
```

So the reward request fires whether the share succeeded or not. There is no share token, no
callback id, no server-side verification — just `{c: 191, gameid, cat}` on an **unauthenticated
WebSocket** (§B7). An attacker doesn't even need to press the button; they can send the frame
directly. Same pattern for `doShareAction`, a purely local flag.

## A7. Agent contact details are unvalidated, server-controlled URLs

`yd_rank_referrals` reads the support contacts straight out of the rank response:
```js
e.telegram && (this.agentTG = e.telegram);
e.whatapp  && (this.agentWS = e.whatapp);     // sic: "whatapp"
this.tg_img = e.telegram_img;
```
`refer_makemoney` then hands them to the OS:
```js
var e = ...getComponent("yd_rank_referrals").getAgentWS();
e && cc.vv.PlatformApiMgr.openURL(e);        // no scheme allow-list, no domain check
```
Since `apiUrl` is `http://` and the WS has no MAC, an on-path attacker rewrites `agentWS` and
every user who taps "contact your agent on WhatsApp" is routed to the attacker — in a
real-money app, that is a deposit-phishing channel with a trusted in-app entry point.

**Fix:** allow-list `https://wa.me/`, `https://t.me/`, `https://www.facebook.com/` and pin the
expected agent handle server-side.

## A8. PII exposure in the referral feed

`REF_BOARDCAST` (376) drives a scrolling ticker of other users' referral activity:
```js
cc.find("node_head", i).getComponent("HeadCmp").setHead(n.uid || 1, n.icon);   // real uid + avatar
cc.find("New RichText", i)...string = ___(a, n.coin, Global.maskNameStr(n.name, 3, 3));
```
The mask is:
```js
maskNameStr = function(e, t, i) {
  return e ? e.substring(0, t) + "***" + e.substring(e.length - i, e.length) : "***";
};
```
`maskNameStr(name, 3, 3)` reveals the **first 3 and last 3 characters**. For any name of 6
characters or fewer that is the entire name; for 7 characters, 6 of 7. Combined with the real
`uid` and avatar loaded alongside, the ticker is a user-directory scrape. `ReferRewardDetailItem`
also renders raw `e.uid` into `lbl_name`.

## A9. Share-link generation bugs

`common_sharefriends.onClickFBShare` is wrong:
```js
cc.vv.PlatformApiMgr.openURL(cc.js.formatStr(
  "https://www.facebook.com/sharer/sharer.php?u=%s", encodeURIComponent(this._getShareContent())));
```
`u=` receives the **whole share text** (which already embeds the URL) instead of the URL.
Facebook will resolve a text blob, not a link — the shared referral post is broken.
Compare the correct version in `refer_makemoney.onClickFB`:
```js
"...sharer.php?u=%s&quote=%s", encodeURIComponent(sharelink), encodeURIComponent(content)
```
Two share components, two different (one broken) implementations. `onClickViberShare` uses
`viber://forward?text=`, which is not a supported Viber share scheme.

## A10. Null-dereference crashes in the referral UI

| Location | Trigger |
|---|---|
| `refer_myrewards._showRewads` | `var i = this._serverData.today \|\| null;` → `1 == e ? i = this._serverData.total \|\| null : ...` → the very next statement does `i.cash` → **TypeError** if `total`/`today` is absent. Both tabs are exposed (`_showRewads(1)` / `_showRewads(2)`) |
| `refer_myrewards._showCanRecvInfo` | `this._serverData.cash + this._serverData.bonus` → `NaN` → claim button silently disabled |
| `refer_myreferrals` | `_servData` is never initialised (only assigned at L120). `onClickPageNext` (L97), `_showPageNum` (L108) and `onListRender` (L112) all dereference it with no guard → **TypeError** if tapped before the first response. (`_showRefs` *is* guarded with `if (t)`.) |
| `refer_myreferrals` L121 | **`NaN` pagination reaches the server.** `total_page = Math.ceil(e.total / e.limit)` → `NaN` when `total` is absent, `Infinity` when `limit` is 0. The `NaN < 1` guard in `sendReq` (`t < 1 && (t = 1)`) does **not** catch `NaN` — `NaN < 1` is `false` — so `_page` stays `NaN` and `JSON.stringify` serialises it as `{"page": null}` on the wire. Verified: `node -e 'JSON.stringify({page: Math.ceil(undefined/5)})'` → `{"page":null}` |
| `refer_Leadboard_Claim.REF_LEADERBOARD_CLAIM` | `e.rewards.push({type:1, count: e.addcoin})` → pushes `count: undefined` when the server omits `addcoin`; also **double-counts** when the server already returned `rewards` |
| `refer_rule.showRebetCfg` | indexes `e._cfg.recharge[i-1]` / `.bet[i-1]` / `.tax[i-1]` with no length check — a short array crashes the rules panel |
| `refer_rule.update` / `_movelist` | `n.y += 1` per frame — scroll speed is framerate-dependent |

## A11. Attack playbooks (what I would actually do)

**Playbook 1 — referral farming.** Mint guest accounts (`Date.now()+"_"+Math.random()`, ~26
bits of entropy, §A3.1). For each, launch the web build with `?itcode=<my code>` — or on
native, trigger the Play install with a chosen `referrer=`. Bind, hit the `reg` reward. Nothing
in the client prevents it and `vid` is always `"-1"`.

**Playbook 2 — support-channel phishing.** Take an on-path position (the API is HTTP and the WS
has no MAC). Rewrite `agentWS` / `telegram` in the rank response to your own `wa.me` handle.
Every user tapping "contact agent" now reaches you, in-app, pre-trusted.

**Playbook 3 — referral balance inflation (display).** Inject a forged `REF_MY_REWARDS` (371)
frame with `cash`/`bonus` set arbitrarily. No MAC to fail, no signature required. Then
screenshot "₹50,000 pending referral reward" for a support-scam or a chargeback story. Real
funds are unaffected — the server owns the ledger — but the support burden and fraud surface
are real.

**Playbook 4 — race the claim.** Rapid double-tap on the claim button (no guard, §A4) while
simultaneously replaying the stale cached response (§A5) to keep the button enabled. Only a
server-side idempotency check stops this.

---

# PART B — ENCRYPTION

## B1. The three layers, and what each is worth

| Layer | Scheme | Key material | Effective strength |
|---|---|---|---|
| Script protection | XXTEA → gzip | `b32a2160-0c63-41` in `.rodata` | **0 bits** (readable in 2 min) |
| Config / localStorage | delta-chain + `escape()` | **none** | **0 bits** (keyless) |
| HTTP response | AES-256-GCM + HMAC-SHA256 | two static 32-byte strings in the APK | **0 bits** (static, extractable) |
| WebSocket | — | — | **none** |
| Payment PIN | — | — | **none** |

## B2. XXTEA — full recovery path and cryptanalysis

**Recovery (static, no execution required):**
```
jsb_set_xxtea_key   exported at 0x6e74ec
   └─ PLT stub      0x313100   (GOT slot 0x1530ec8, rela.plt entry 1974)
       └─ only caller  0x3330c0
            0x3330a8  adrp x1, #0x112c000
            0x3330b0  add  x1, x1, #0xb05        -> .rodata 0x112cb05
            0x3330b8  bl   #0x3204b0             (std::string ctor)
            0x3330c0  bl   #0x313100
.rodata @ 0x112cb05:  Cocos Game\0 b32a2160-0c63-41\0 jsb-adapter/jsb-builtin.js\0
```

**Key handling, confirmed from the disassembly of `xxtea_decrypt` @ `0x70b764`:**
```
cmp w3, #0xf            ; key_len > 15 ?
b.hi  0x70b80c          ;   yes -> use the raw key pointer/length as-is
  ...                   ;   no  -> memcpy into a 16-byte zero-padded buffer
```
Our key is exactly 16 bytes, so it is used verbatim as 4 little-endian `uint32`.

**Two deviations from textbook XXTEA** that cost me three failed attempts, transcribed from the
core at `0x70b834`:
1. `y` is loaded **once** (`ldr w12, [x20]`) *before* the round loop and then carries across
   rounds — it is not re-read from `v[0]` each round.
2. The `p == 0` step uses `z = v[n-1]` (`ldr w14, [x20, x8, lsl #2]`, `x8 = n-1`), **not** the
   carried `z = v[0]` that the Wikipedia listing implies.
3. `sum` initialises to `(6 + 52/n) * DELTA`, emitted by the compiler as
   `(52/n)*0x9e3779b9 + 0xb54cda56` (where `0xb54cda56 == 6*DELTA mod 2^32`).
4. The trailing length word must satisfy `n*4-7 <= len <= n*4-4` — not the `[n-3, n]` range
   most ports assume.

**Cryptanalysis of the choice itself.** `b32a2160-0c63-41` is a truncated UUID: 14 hex
characters at fixed positions plus two literal dashes. That is ~**56 bits** of entropy — the
charset and dash placement are not secret. At ~10⁶ XXTEA trials/sec/core that is months on one
core and hours on a modest GPU cluster. But the entropy is irrelevant: the key sits in
plaintext in `.rodata`, so the attack is a string search.

**The deeper problem is the format, not the key.** XXTEA is a bare block cipher — **no
authentication**. Even with a perfect key, the ciphertext is malleable. And the plaintext is
gzip, whose first 10 bytes are a fixed header (`1f 8b 08 00 00 00 00 00 00 03`), giving an
attacker a free 10-byte known-plaintext block at a known offset.

**Verification:** re-encrypting the decrypted gzip stream reproduces all 9 original `.jsc`
files **byte-for-byte**.

## B3. The delta cipher — literally zero bits of key

```js
h.compile = function(e) {
  for (var t = String.fromCharCode(e.charCodeAt(0) + e.length), i = 1; i < e.length; i++)
    t += String.fromCharCode(e.charCodeAt(i) + e.charCodeAt(i-1));
  return t = escape(t);
};
```
`c[0] = p[0] + len`, `c[i] = p[i] + p[i-1]`. A keyless, invertible, linear running sum. No
secret exists to brute-force. Demonstrated:

```
plaintext : 1726300000000_48291037
stored as : Ghihic%60%60%60%60%60%60%60%8F%93ljkjacj
recovered : 1726300000000_48291037          (key bits used: 0)

plaintext : eyJhbGciOiJIUzI1NiJ9.fake.token
stored as : %84%DE%C3%B2%CA%A9%AA%CC%B8%B8%B3%93%9E%CF%C3z%7F%B7%B3%83g%94%C7%CC%D0%93%A2%E3%DA%D0%D3
recovered : eyJhbGciOiJIUzI1NiJ9.fake.token (key bits used: 0)
```

This is what protects `SAVE_PLAYER_TOKEN`, `localtoken`, `recent_uid`, `SAVE_KEY_REQ_LOGIN`
(the full login request incl. device id) and `phNum` in `localStorage` — and `allowBackup="true"`
means `adb backup` retrieves the lot.

Round-trip verified: re-encoding all 7 decoded constants reproduces the exact shipped strings
(including `escape()`'s quirk of leaving `A-Za-z0-9@*_+-./` unescaped — which is why my first
attempt appeared to fail).

## B4. The response envelope, byte for byte

```
Server -> Client
{
  "data":      base64( IV[12] || ciphertext[N] || GCM_tag[16] ),
  "timestamp": <unix seconds>,
  "signature": hex( HMAC-SHA256( data_string + str(timestamp), P_K ) )
}
```
- `P_K` = `rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z` (32 ASCII bytes → HMAC key)
- `P_AK` = `j39qexkacw7gtnzrnnlwuibjnd494xhw` (32 ASCII bytes → AES-256 key, via
  `i[n] = 255 & e.charCodeAt(n)`)
- IV must be exactly 12 bytes; the fallback hard-requires it
  (`"AES-GCM 仅支持 12 字节 IV"`)
- AAD is empty; GHASH length block is `0 || len(C)*8`

**I audited the hand-rolled CryptoJS fallback in `aes-gcm-decrypt.js` and it is correct:**
`H = AES_ECB(0^128)` ✓ · `J0 = IV || 0x00000001` ✓ · CTR starts at `J0+1` ✓ · GHASH reduction
constant `3774873600 == 0xE1000000` ✓ · tag compare `L |= E[T] ^ s[T]` is **constant-time** ✓.

## B5. Empirical proof — running the APK's own code

I extracted `response-decrypt.js`, `aes-gcm-decrypt.js`, `crypto-js.min.js` and the engine's
`__awaiter`/`__generator` (from `cocos2d-jsb.js:68657`), loaded them into Node 22, and attacked
them. The forger uses **pycryptodome — a completely independent implementation** — so agreement
is meaningful, not a shared bug.

```
=== 0. Sanity: is validateTimestamp ever invoked by decryptResponse? ===
  "validateTimestamp" appears 1x, called via this. 0x
  PASS  TTL check is DEAD CODE (never called) -> unlimited replay window

=== 1. Forge a wallet response using ONLY the recovered APK keys ===
  PASS  forged envelope passes signature verification
  PASS  forged plaintext decrypts correctly -> {"code":0,"cash":999999,"bonus":888888,"msg":"forged"}

=== 2. Signature canonicalisation is ambiguous (data + ts, no separator) ===
  PASS  HMAC("abc",123) === HMAC("abc1",23) -> 311a1abdcd3ba2b73d266a60...

=== 3. Encryption is opt-out: plain JSON is accepted with NO verification ===
  PASS  isEncryptedResponse(plain) === false
  PASS  plain JSON returned to business logic untouched -> cash=12345678

=== 4. Replay: same envelope accepted indefinitely ===
  PASS  identical envelope accepted twice (and 1s later)

=== 5. Is each integrity layer actually working? ===
  PASS  5a. flipped byte caught by HMAC layer -> 签名验证失败
  PASS  5b. re-signed tamper caught by GCM tag -> AES解密失败: OperationError
  PASS  5c. => primitives are sound; the flaw is key management, not the cipher

=== 6. Same attack works on the CryptoJS fallback path (no WebCrypto) ===
  PASS  useNativeCrypto() now false
  PASS  forged envelope accepted via CryptoJS fallback too -> {"code":0,"cash":555,"msg":"fallback"}

12 passed, 0 failed
```

Harness: [`harness/`](harness/) — `extract.py` regenerates the four APK-derived modules
from the decrypted JS, `attack.js` runs the suite, `forge.py` builds the forged envelopes.
`node harness/attack.js` → `12 passed, 0 failed`.

## B6. The TTL check is dead code → unlimited replay

`validateTimestamp` is **defined** (`project.js:95204`) but **never called**. `decryptResponse`
only calls `validateSignature`:

```js
return [4, this.validateSignature(i, n, o)];
case 1:
  if (!c.sent()) throw new Error("签名验证失败");
  return [4, this.aesDecrypt(i)];        // no timestamp check anywhere
```

`this.timestampTtl = 300` is set, logged (`ttl: this.timestampTtl`), and then ignored. My first
report said "5-minute replay window" — **that was wrong.** The window is **unbounded**: a
captured envelope is replayable forever, as test 4 confirms.

## B7. Canonicalisation is ambiguous — collision demonstrated

```js
n = e + t;                          // data string + timestamp, NO separator
o = await this.hmacSha256(n, this.k);
s = i === o;                        // non-constant-time compare
```
Test 2 proves `HMAC("abc", 123) === HMAC("abc1", 23)` → `311a1abdcd3ba2b73d266a60...`. Any
valid signed payload can be re-split into a different `(data, timestamp)` pair that still
verifies. Combined with §B6, the timestamp is not even checked — so the ambiguity is currently
latent rather than exploitable, but it becomes live the moment someone "fixes" B6 by calling
`validateTimestamp` without also fixing the canonicalisation.

Also `i === o` is a plain string comparison — early-exit, timing-observable. Use
`crypto.timingSafeEqual` (or the existing constant-time XOR loop already in `aes-gcm-decrypt`).

## B8. Encryption is opt-out

```js
if (t && cc.vv.UserManager.responseDecryptClient && u(n)) {   // u = isEncryptedResponse
    n = await cc.vv.UserManager.responseDecryptClient.decryptResponse(n);
}
i(t, n);        // otherwise: raw JSON straight to business logic
```
`isEncryptedResponse` requires `data:string`, `timestamp:number`, `signature:string`. Omit all
three and the response is trusted completely — test 3. On a plaintext `http://` transport this
is a three-field edit for a full MITM.

## B9. The primitives are fine — which is the point

Tests 5a and 5b show both integrity layers working:
- flipping a ciphertext byte and keeping the old signature → **HMAC rejects it**
- flipping a ciphertext byte and **re-signing with the stolen key** → **GCM tag rejects it**

So the crypto is competently implemented. There is exactly one defect: **the keys are static
and ship inside the APK.** Everything else in §B5-B8 is a consequence.

## B10. Bundled crypto supply chain

| Package | Version | Provenance | Status |
|---|---|---|---|
| `elliptic` | **6.5.2** | engine-bundled. Verbatim from the embedded `package.json` at module 82: `_id: "elliptic@6.5.2"`, `_resolved: "https://registry.npmjs.org/elliptic/-/elliptic-6.5.2.tgz"`, `_shasum: "05c5678d7173c049d8ca433552224a495d0e3762"`, `_requiredBy: ["/browserify-sign", "/create-ecdh"]`, `_where: "/Users/nantas/jenkins/workspace/Creator_2D/fireball/mac/fireball/dist/CocosCreator.app/Contents/Resources/app/node_modules/browserify-sign"` | **6.5.2 is the exact version named by CVE-2020-13822** (ECDSA signature malleability via encoding variations, leading `\0` bytes, or integer overflow; fixed 6.5.3) and is also below CVE-2020-28498 (secp256k1 `derive()` does not check the public-key point is on the curve → invalid-curve private-key leak; fixed 6.5.4). Further behind: CVE-2024-42459/42460 (fixed 6.5.6) and CVE-2024-48948/48949 (fixed 6.5.8) |
| `crypto-js` | 4.2.0 | CDN reference `cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js` in the error text | current |
| `bn.js`, `asn1.js`, `crypto-browserify`, `minimalistic-*` | — | same Cocos toolchain | — |

I grepped for app-level use: **no module calls `CryptoJS.AES` / `DES` / `RSA` / `enc` / `mode`
directly, and nothing `require`s `"crypto"`.** The only live consumer of CryptoJS is
`aes-gcm-decrypt`'s `n.algo.AES.createEncryptor` (ECB block primitive, used correctly to build
CTR+GHASH). So `elliptic` and the rest of crypto-browserify are **unreachable dead weight** —
attack surface with no functionality. They should be stripped from the bundle.

## B11. What correct looks like

1. **Never ship a long-lived symmetric key.** Do ECDH (X25519) at login, derive a per-session
   key with HKDF, and use it for both AES-GCM and HMAC. The static value then only bootstraps
   the handshake and can rotate server-side.
2. **Make the envelope mandatory.** Reject any wallet response lacking it. Better: drop the
   bespoke scheme and run everything over TLS with certificate pinning — you get encryption,
   integrity, authentication and replay protection from one well-reviewed mechanism.
3. **Canonicalise before signing.** `HMAC(JSON.stringify({data, timestamp, nonce}))`, and
   actually call `validateTimestamp`.
4. **Add a nonce** and a server-side replay cache.
5. **Sign requests too**, with an idempotency key on every wallet mutation (§A4).
6. **Constant-time compare** everywhere.
7. **Strip the debug logging** — `textSample: ...substring(0,32)`, `sigPrefix`, `expectPrefix`
   and `keyLen` are written to logcat on every decrypted wallet response today.
8. **Replace the delta cipher** with `EncryptedSharedPreferences` / Android Keystore. It
   currently provides 0 bits.
9. **Sign the hot-update manifest** with an asymmetric key baked into the APK, over HTTPS, and
   remove the `compressed` and `.manifest` verification bypasses.

---

---

# PART C — OTP SEND / VERIFY, AND THE WITHDRAWAL PATH

**New in this pass — also empirically proven.** `harness/otp_attack.js` loads the APK's own
`Http` module (extracted verbatim, lines 34656–34716) with a stubbed XHR and captures the exact
URL it builds. **16 / 16 assertions pass.**

## C1. The withdrawal request puts the payment PIN and SMS OTP in a GET URL — Critical

The call chain, verified link by link:

```js
withdraw_bank.sendDrawReq        (project.js:96953)
    t = { dcoin, bankid, force?, passwd?, code?, mobile? }   // passwd = payment PIN, code = SMS OTP
      ↓
withdraw_bank.sendParam          (project.js:96974)
    this.sendHttp("draw/order", e, callback)                 // THREE arguments
      ↓
charge_api.sendHttp              (project.js:84278)   — withdraw_bank extends charge_api (:96690)
    var n = arguments.length > 3 && void 0 !== arguments[3] ? arguments[3] : "GET";   // -> "GET"
      ↓
UserManager.sendPayServer        (project.js:80210)
    t.lang = s; t.uid = UserManager.uid; t.token = UserManager.token;   // appended unconditionally
      ↓
Http.sendReq                     (project.js:34672)
    for (var _ in t) h += _ + "=" + t[_];
    "GET" == o && (u += "?" + encodeURI(h));                 // body sent only for POST
```

The URL the app actually produces (captured by running its own `sendReq`):

```
http://pay.example.invalid/v1/draw/order?dcoin=5000&bankid=77&force=1
   &passwd=482913            <- the payment PIN
   &code=391042              <- the SMS OTP
   &mobile=9876543210        <- the phone number
   &lang=en&uid=10023456
   &token=a1b2c3d4e5f60718293a4b5c   <- the session token
```

URL query strings are the single most-logged part of an HTTP request. That PIN, OTP and session
token land in web-server access logs, load-balancer logs, any proxy or CDN in the path, and the
`Referer` header of anything the page subsequently loads.

**Scope is wider than withdrawals.** `sendPayServer` defaults to `"GET"` and appends
`t.uid` + `t.token` (`project.js:80224-80225`) to *every* request, so the session token rides in
URL query strings across the whole pay API — `user/balance`, `user/banks`, `draw/alltypes`,
`draw/drawType`, `sms/index`.

**Fix:** POST with a JSON body for anything carrying a credential. Never put a token in a query
string.

## C2. Every HTTP response body is logged, with no debug gate — High

```js
// Http.sendReq — the request log IS gated:
Global.localVersion && console.log("#######request url:" + u + " => " + JSON.stringify(t));

// Http.onReadyStateChanged (project.js:34695) — the response log is NOT:
if (e.status >= 200 && e.status < 400) {
    console.log("http res(" + e.responseText.length + "): " + e.responseText);
```

Harness assertion group 5 confirms the asymmetry by regex against the extracted module. Every
pay-API and OTP-API response body goes to `console.log` in a production build. With
`allowBackup="true"` and a USB-debuggable device, `adb logcat` captures all of it.

**If the OTP endpoint ever returns the code in its response body, it lands in logcat in
cleartext.** I could not determine whether it does without sending traffic to
`service.fewhu37a1.com`, and I did not — but the client-side `console.log` is unconditional
either way, so session-bearing bodies from `draw/*` and `user/balance` are logged regardless.

## C3. OTP send is unauthenticated — High

```js
// registration / login path (_doSendOtp, project.js:61532)
cc.vv.NetManager.requestHttp("", { phone: e, channel: this._otpType, otptype: 6 },
    cb, cc.vv.UserManager.parseUrl(Global.otpurl), "GET", !1);

// withdrawal path (withdraw_bank.onClickOTP, project.js:97023)
this.sendHttp("sms/index", { phone: this.user_mobile, channel: this._otpType, otptype: 4 }, cb);
```

The request carries **only** `phone`, `channel` and `otptype` — no `uid`, no token, no device id,
no nonce, no HMAC (harness assertion group 2). Anyone who can reach the endpoint can trigger an
SMS or a **voice call** (`data.voice` selects the message text) to any number: SMS bombing and
per-message toll fraud.

The only rate limit is a UI timer:
```js
t._optTime = 120;
t.optLabel.node.getComponent("ReTimer").setReTimer(t._optTime, 1, function () {
    t.btn_opt.getComponent("ButtonGrayCmp").interactable = !0;   // re-enable after 120 s
```
Purely cosmetic. Note also that the registration path (`otptype: 6`) does **not** handle
`code 339 / send_too_frequently`, while the bind path (`sms/index`) does — suggesting the
frequency guard may be absent server-side on that endpoint too.

**The phone number itself is in the URL** on both paths, since both are GET.

`Global.Phonecheck = /^\d{10}$/` (`project.js:33739`) *is* applied before these sends, which
blocks query injection through the phone field here. See C5 for where it is not applied.

## C4. OTP verification — no client-side attempt limit, and a per-reason oracle

```js
// project.js:30831 — distinct responses per failure reason
426/216 -> "Registration unavailable now"    335 -> "enter the OTP for new device login"
334     -> "Invalid OTP code"                333 -> "wrong password!"
955     -> "This account does not exist!"    201 -> "Phone_used"
```

I searched all five withdrawal-OTP call sites (`:96965`, `:97505`, `:97927`, `:98307`,
`:98692`). Each does only:
```js
var n = cc.find("input", i).getComponent(cc.EditBox).string;
if (!n) { cc.vv.FloatTip.show(___("Invalid OTP code")); return; }   // "is the box empty?" — that's all
t.code = n; t.mobile = this.user_mobile;
```
**There is no OTP attempt counter anywhere in the client.** The payment PIN *does* have one
(`_nErrorCnt >= 3` → force reset), but it lives on the component instance, so navigating away
clears it. Both limits must be enforced server-side.

**Correctly done, for the record:** the OTP is scrubbed before the login request is cached —
```js
if (r.otp) { r.otp = void 0; r.LoginExData = Global.LoginExData.reloginAction; }   // project.js:30709
Global.saveLocal(Global.SAVE_KEY_REQ_LOGIN, JSON.stringify(r));
```
so it does not reach localStorage.

**But note:** for the password-reset flow the *new password* is sent in the same message as the
OTP — `reqLogin(e, this.pwdStr, Global.LoginType.PHONE, "", "rest", this.optStr)` — over a
WebSocket that can be plaintext `ws://` (§B/WS).

## C5. `encodeURI` instead of `encodeURIComponent` — parameter injection

```js
var h = "";
for (var _ in t) { "" != h && (h += "&"); h += _ + "=" + t[_]; }   // raw & and =
"GET" == o && (u += "?" + encodeURI(h));                            // encodeURI does NOT escape & = + # ? ; /
```

Harness assertion group 3 proves a value of `9876543210&otptype=9&admin=1` survives as two extra
real parameters:
```
…/v1/sms/index?phone=9876543210&otptype=9&admin=1&channel=0&otptype=4
                                  ^^^^^^^^^^^^^^^^^^^^^ injected, parsed as real params
```
`Phonecheck` blocks this on the OTP paths. But `onClickBinding` gates its phone check on a
server-controlled flag —
`if (Global.Phonecheck && cc.vv.UserManager.bind_req_phone && !Global.Phonecheck.test(e))` —
so when `bind_req_phone` is false the regex is skipped entirely.

**Fix:** build the query with `URLSearchParams`, or `encodeURIComponent` per component.

## C6. OTP-less login

```js
cc.vv.PlatformApiMgr.doOTPLessLogin(function (e) {
    var t = parseInt(e.result);
    if (1 == t) { var i = e.token;
        cc.vv.GameManager.reqLogin("", "", Global.LoginType.OTPLESS, i, null, i); }
```
Phone and password are **empty strings**; the same WhatsApp-issued token is passed as both
`accessToken` and `token` (`constructLoginMsg` assigns `s.accessToken = n; s.token = o`). The
native side is `loginOTPLess()V` → `OTPLessCallback`. Security rests entirely on the server
validating that token — unverifiable from the client.

---

# PART D — ADDITIONAL REFERRAL FINDINGS

## D1. Referral-link hijack — High

```js
REFER_LINK_UPDATE: function (e) {
    if (200 == e.code) {
        cc.vv.UserManager.sharelink = e.sharelink;      // no validation whatsoever
```
`sharelink` is then rendered into a **QR code** (`QRCode.data = cc.vv.UserManager.sharelink`,
`project.js:88901`), copied to the clipboard, and embedded in every WhatsApp / Facebook /
Telegram / system share. On the cleartext `http://` API an on-path attacker substitutes their
own referral link and **every share the victim subsequently makes credits the attacker**.

## D2. Nine dead referral message IDs

An entire older protocol (`REQ_REFFERS_*`) was abandoned in place and now collides with
`EVENT_FB_INVITE_*` in the definition table:

| id | name | refs |
|---|---|---|
| 254 | `REFER_INFO` | 0 |
| 267 | `REFER_BROADCAST_INFO` | 0 |
| 255 | `REQ_REFFERS_LIST` | 0 |
| 256 | `REQ_REFFERS_REWARDS` | 0 |
| 259 | `REQ_REFFERS_DETAILS` | 0 |
| 261 | `REQ_REFFERS_LIST_DETAILS` | 0 |
| 262 | `REQ_REFFERS_REWARDS_DETAILS` | 0 |
| 430 | `SHARE_WHATSAPP_REPORT` | 0 |
| 241 | `EVENT_FB_SHARE_SUCCESS` | 0 |

## D3. Further referral defects

| Where | What |
|---|---|
| `yd_rank_referrals.EVENT_GET_RANK_INFO` | `for (t = 0; t < e.list.length; t++)` — no null check on `e.list`; the guard is only `200 == e.code && (4 == e.rtype \|\| 6 == e.rtype)` |
| `yd_rank_referrals` tabs | "This week" (`rtype 4`) and "Yesterday" (`rtype 6`) land in the **same** handler with no way to tell which tab is showing → a late `rtype:4` reply overwrites the Yesterday view |
| `refer_myrewards` daily gate | `needPopDayTips("ref_myrewards_last")` is written **only** when `e.coin > 0 \|\| e.count > 0` (`:94800`), so a user with no yesterday-rewards re-requests `REF_REWARDS_LASTDAY` on every panel open |
| `refer_makemoney.onClickCopy` | Shows `copy_successfully` **before** copying, and copies the share *text* rather than the link |
| `refer_makemoney.onClickSYS` | On non-native falls back to `openURL(sharelink)` — opens the raw link in a browser instead of sharing |
| `refer_makemoney.onRecvOnTGBindBot` | `e.payload && cc.vv.PlatformApiMgr.openURL(e.payload)` — a second server-controlled, unvalidated `openURL` sink |
| `PBPopupInvite._checkInviteCnt` | The 3-invites-per-table cap is a localStorage JSON check inside `try/catch` that **fails open** (`var e = !0`). Clearing or corrupting `DATA_INVITE_IN_CHAT` bypasses it; the 100 s cooldown is the same |

---

## Summary of what changed vs. the first report

| Claim | First report | Corrected |
|---|---|---|
| Replay window | "5 minutes (300 s TTL)" | **Unbounded** — `validateTimestamp` is never called (proven, test 0 + 4) |
| Response forgery | "keys are static, so forgeable" (read) | **Demonstrated** against the app's own code (test 1) |
| Encryption bypass | "unencrypted responses accepted" (read) | **Demonstrated** (test 3) |
| Crypto quality | "sound primitives" (audited by eye) | **Both layers verified working** (tests 5a/5b) |
| Referral ID collisions | not covered | **117 total, 4 live**, one corrupting the bonus pool (§A1.1) |
| Claim idempotency | not covered | **6 of 6 claim buttons unguarded** (§A4) |
| Response cache | not covered | **Never invalidated — proven**, 3 touch points only (§A5) |
| Share rewards | not covered | **Client-self-asserted, fires on failure too** (§A6) |
| **Withdrawal transport** | not covered | **Payment PIN + SMS OTP + session token sent as GET query params** — proven by running the app's own `Http.sendReq` (§C1) |
| **OTP send** | not covered | **Unauthenticated GET**, phone in the URL, 120 s UI-only rate limit (§C3) |
| **Response logging** | not covered | **Every response body `console.log`ged with no debug gate** (§C2) |
| **OTP brute force** | not covered | **No client-side attempt counter**; per-reason error oracle (§C4) |
| **Referral-link hijack** | not covered | `sharelink` is server-controlled and feeds the QR code + every share (§D1) |
| **Dead protocol** | not covered | **9 dead referral MsgIds** from an abandoned `REQ_REFFERS_*` protocol (§D2) |

## Companion artefacts

| File | What it is |
|---|---|
| [`FLOW.html`](FLOW.html) | Interactive flow map — 7 tabs (Overview / Refer & Earn / OTP / Withdrawal / Encryption / WebSocket / Findings), 34 findings indexed by severity. Self-contained, no external dependencies. |
| [`harness/attack.js`](harness/attack.js) | Runs the APK's `response-decrypt.js` — **12/12** |
| [`harness/otp_attack.js`](harness/otp_attack.js) | Runs the APK's `Http.sendReq` — **16/16** |
| [`harness/forge.py`](harness/forge.py) | Attacker-side envelope builder (pycryptodome, independent stack) |
| [`harness/extract.py`](harness/extract.py) | Regenerates the APK-derived modules from the decrypted JS |

## What I still cannot verify

- Any **server-side** behaviour: whether claims are idempotent, whether `referid` is
  authorisation-checked (§A4.1), whether OTP or PIN attempt counters are enforced server-side,
  whether `sms/index` rate-limits at all, and whether `payapi` is served as `http` or `https`
  (it is assigned at login from `this.payapi = t.payapi`).
- **Whether the OTP endpoint returns the code in its response body.** I did not send traffic to
  `service.fewhu37a1.com` and did not attempt to. The client-side `console.log` (§C2) is
  unconditional regardless, so this is worth checking in your own server logs.
- Whether the WhatsApp OTP-less token (§C6) is validated server-side.
- Whether the forged-envelope attack succeeds against a **live** server. I proved the client
  accepts forgeries; I sent no traffic to `ifs.wfvbu98d.com`.
- Runtime behaviour on a device. Everything here is static analysis plus execution of the
  extracted modules in Node 22.
