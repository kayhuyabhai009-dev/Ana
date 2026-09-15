#!/usr/bin/env python3
"""Regenerate the six APK-derived modules used by attack.js / otp_attack.js.

Run from the repo root after decrypting the .jsc bundles:

    python3 harness/extract.py work/dec/project.js work/dec/cocos2d-jsb.js

Writes into harness/ (those six files are git-ignored: they are derived from
the APK, not authored here). loader.js, attack.js, otp_attack.js, forge.py and
this script are authored and version-controlled.

  crypto-js.min.js  crypto-js.js  aes-gcm-decrypt.js  response-decrypt.js
  http.js           tslib.js
"""
import json, re, sys, os

if len(sys.argv) != 3:
    print(__doc__); sys.exit(1)
project, engine = sys.argv[1], sys.argv[2]
out = os.path.join(os.path.dirname(os.path.abspath(__file__)))

# --- 1. locate the browserify module boundaries for the four crypto modules ---
src = open(project, encoding='utf-8', errors='replace').read()
lines = src.split('\n')
HDR = re.compile(r'^([A-Za-z0-9_$."\-]+):\s*\[\s*function\(e,\s*t,\s*i\)\s*\{')
bounds, cur = {}, None
for n, ln in enumerate(lines):
    m = HDR.match(ln)
    if m:
        if cur: bounds[cur][1] = n
        cur = m.group(1).strip('"'); bounds[cur] = [n, len(lines)]
if cur: bounds[cur][1] = len(lines)

def grab(name):
    lo, hi = bounds[name]
    body = lines[lo + 1:hi]              # drop the `Name: [ function(e,t,i){` header
    cut = None                           # strip the trailing browserify deps map
    for i in range(len(body) - 1, -1, -1):
        if body[i].strip() in ('}, {', '}, {} ],'):
            cut = i; break
    if cut is not None: body = body[:cut]
    while body and body[-1].strip() == '': body.pop()
    return '\n'.join(body) + '\n'

for mod in ['crypto-js.min', 'crypto-js', 'aes-gcm-decrypt', 'response-decrypt', 'Http']:
    path = os.path.join(out, (mod.lower() if mod == 'Http' else mod) + '.js')
    open(path, 'w').write(grab(mod))
    print(f'  wrote harness/{mod.lower() if mod == "Http" else mod}.js')

# --- 2. pull __awaiter / __generator out of the engine (TS runtime helpers) ---
eng = open(engine, encoding='utf-8', errors='replace').read()
def brace_match(text, marker):
    i = text.index(marker)
    j = text.index('{', i); d = 0; k = j
    while k < len(text):
        if text[k] == '{': d += 1
        elif text[k] == '}':
            d -= 1
            if d == 0: break
        k += 1
    end = k + 1
    if text[end:end + 1] == ';': end += 1
    return text[i:end]

helpers = (brace_match(eng, 'window.__awaiter = function')
           + brace_match(eng, 'window.__generator = function'))
open(os.path.join(out, 'tslib.js'), 'w').write(
    helpers.replace('window.__awaiter', 'globalThis.__awaiter')
           .replace('window.__generator', 'globalThis.__generator') + '\n')
print('  wrote harness/tslib.js')
