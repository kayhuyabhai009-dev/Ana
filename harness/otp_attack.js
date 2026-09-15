// Runs the APK's ACTUAL Http.sendReq / onReadyStateChanged against the real
// withdrawal + OTP request shapes, and shows exactly what lands on the wire.
const fs = require('fs');

let captured = null;
const logs = [];

function fakeXHR() {
  return {
    timeout: 0,
    readyState: 0,
    status: 0,
    responseText: '',
    setRequestHeader(k, v) { (this._h ||= {})[k] = v; },
    open(method, url) { captured = { method, url, headers: this._h || {} }; },
    send(body) { captured.body = body; },
  };
}

global.console = { log: (...a) => logs.push(a.join(' ')), warn: () => {}, error: () => {} };
global.cc = {
  _RF: { push() {}, pop() {} },
  Class: (o) => { function C() {} Object.assign(C, o.statics || {}); return C; },
  Component: function () {},
  loader: { getXMLHttpRequest: () => fakeXHR() },
};
global.Global = { isNative: () => true, localVersion: false };

const M = { exports: {} };
new Function('e', 't', 'i', fs.readFileSync(__dirname + '/http.js', 'utf8'))(
  (d) => { throw new Error('unexpected dep ' + d); }, M, M.exports);
const Http = M.exports;

let pass = 0, fail = 0;
const check = (n, c, x = '') => { c ? (pass++, logs.push(`  PASS  ${n} ${x}`)) : (fail++, logs.push(`  FAIL  ${n} ${x}`)); };

// ---- the real parameter object built by withdraw_bank.sendDrawReq ----
const drawOrder = {
  dcoin: 5000, bankid: 77, force: 1,
  passwd: '482913',            // the payment PIN, from safecenter_inputPIN
  code: '391042',              // the SMS OTP typed by the user
  mobile: '9876543210',
};
// sendPayServer() appends these to every request:
const withAuth = { ...drawOrder, lang: 'en', uid: 10023456, token: 'a1b2c3d4e5f60718293a4b5c' };

logs.push('=== 1. The withdrawal request the app actually builds ===');
captured = null;
Http.sendReq('draw/order', withAuth, () => {}, 'http://pay.example.invalid/v1/', 'GET', true, 30000, false);
logs.push('  method : ' + captured.method);
logs.push('  url    : ' + captured.url);
const q = new URLSearchParams(captured.url.split('?')[1]);
check('HTTP method is GET', captured.method === 'GET');
check('payment PIN is in the URL query string', q.get('passwd') === '482913', `-> passwd=${q.get('passwd')}`);
check('SMS OTP is in the URL query string', q.get('code') === '391042', `-> code=${q.get('code')}`);
check('phone number is in the URL query string', q.get('mobile') === '9876543210');
check('session token is in the URL query string', q.get('token') === 'a1b2c3d4e5f60718293a4b5c');
check('nothing is sent in the request body', captured.body === undefined);

logs.push('');
logs.push('=== 2. The OTP-send request (withdraw_bank.onClickOTP -> sms/index) ===');
captured = null;
Http.sendReq('sms/index', { phone: '9876543210', channel: 0, otptype: 4, lang: 'en', uid: 10023456, token: 'a1b2c3d4e5f60718293a4b5c' },
  () => {}, 'http://pay.example.invalid/v1/', 'GET', true, 30000, false);
logs.push('  url    : ' + captured.url);
const q2 = new URLSearchParams(captured.url.split('?')[1]);
check('OTP-send is also GET', captured.method === 'GET');
check('phone number in URL on OTP send', q2.get('phone') === '9876543210');
check('OTP send carries NO uid-scoped nonce/HMAC', !q2.has('sign') && !q2.has('nonce') && !q2.has('ts'));

logs.push('');
logs.push('=== 3. encodeURI (not encodeURIComponent) leaves reserved chars live ===');
// sendReq does:  u += "?" + encodeURI(h)   -- h is built with raw "&" and "="
const hostile = { phone: '9876543210&otptype=9&admin=1', channel: 0, otptype: 4 };
captured = null;
Http.sendReq('sms/index', hostile, () => {}, 'http://pay.example.invalid/v1/', 'GET', true, 30000, false);
logs.push('  url    : ' + captured.url);
const q3 = new URLSearchParams(captured.url.split('?')[1]);
check('injected "&admin=1" survives as a real parameter', q3.get('admin') === '1', `-> admin=${q3.get('admin')}`);
check('injected "&otptype=9" overrode the intended value', q3.getAll('otptype').includes('9'));

logs.push('');
logs.push('=== 4. Every HTTP response body is logged, ungated ===');
const before = logs.length;
Http.onReadyStateChanged(
  { readyState: 4, status: 200, responseText: JSON.stringify({ code: 0, data: { otp: '391042', mobile: '9876543210' } }) },
  (ok, res) => { captured = res; });
const leaked = logs.slice(before).join('\n');
logs.push('  captured console.log: ' + leaked.trim());
check('response body written to console.log', /http res\(/.test(leaked));
check('=> an OTP in the response would land in logcat', /391042/.test(leaked));
check('the callback still received the parsed body', captured && captured.data && captured.data.otp === '391042');

logs.push('');
logs.push('=== 5. Request-URL logging is gated, response logging is NOT ===');
const src = fs.readFileSync(__dirname + '/http.js', 'utf8');
check('request log is behind Global.localVersion', /Global\.localVersion && console\.log\("#######request url:/.test(src));
check('response log has no gate at all',
  /if \(e\.status >= 200 && e\.status < 400\) \{\s*console\.log\("http res\(/.test(src));

const out = logs.join('\n');
process.stdout.write(out + `\n\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
