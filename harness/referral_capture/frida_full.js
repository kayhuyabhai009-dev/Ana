/*
 * frida_full.js — ONE comprehensive runtime-capture script for ShareSlots (original APK).
 *
 * Captures EVERYTHING at runtime and writes it to logcat AND to a file in the app's own
 * external-files dir (no root, no storage permission needed):
 *
 *   [RT][HTTP]   every HTTP request/response  (okhttp + HttpURLConnection)  -> pay API
 *   [RT][WS]     every WebSocket frame in/out (raw bytes; msgpack after an 8-byte header)
 *   [RT][CRYPTO] Cipher init/doFinal, SecretKeySpec (keys), IvParameterSpec (IV),
 *                Mac (HMAC), MessageDigest (md5/sha)  -> encryption + keys
 *   [RT][BIND]   kyc/bind + user/editCard payloads, flags an EMPTY otp `code`
 *
 * It also disables TLS certificate pinning so a mitmproxy/HttpCanary CA is accepted.
 *
 * Run (rooted device / emulator / frida-gadget repack):
 *   frida -U -f com.shareslots.games.fun -l frida_full.js
 * Pull the log file:
 *   adb pull /sdcard/Android/data/com.shareslots.games.fun/files/runtime.log
 * WS frames are msgpack — decode them with harness/referral_capture/decode_hcy.py logic.
 */
'use strict';

var TAG = 'RT';
var LOG_TO_FILE = true;
var MAXBODY = 1 << 20; // 1 MB cap per body

function now() { return new Date().toISOString(); }

function hex(bytes) {
  if (!bytes) return '';
  var a = [];
  for (var i = 0; i < bytes.length && i < 4096; i++) {
    var h = (bytes[i] & 0xff).toString(16);
    a.push(h.length < 2 ? '0' + h : h);
  }
  return a.join('');
}

var outFile = null;
function ensureFile() {
  if (outFile !== null) return outFile;
  try {
    var AT = Java.use('android.app.ActivityThread');
    var ctx = AT.currentApplication().getApplicationContext();
    var dir = ctx.getExternalFilesDir(null);
    if (dir) outFile = dir.getAbsolutePath() + '/runtime.log';
  } catch (e) { outFile = false; }
  return outFile;
}

function L(tag, msg) {
  var line = '[' + TAG + '][' + tag + '] ' + msg;
  console.log(line);
  if (LOG_TO_FILE) {
    var p = ensureFile();
    if (p) {
      try {
        var F = Java.use('java.io.FileWriter');
        var w = F.$new(p, true);
        w.write(now() + ' ' + line + '\n');
        w.flush(); w.close();
      } catch (e) {}
    }
  }
}

// read an okhttp RequestBody to a string (non-destructive)
function readReqBody(body) {
  if (!body) return '';
  try {
    var Buffer = Java.use('okio.Buffer');
    var b = Buffer.$new();
    body.writeTo(b);
    return b.readUtf8();
  } catch (e) { return '<binary ' + e + '>'; }
}

Java.perform(function () {
  L('INIT', 'ShareSlots full capture armed');

  /* ===================== 1. TLS PINNING BYPASS ===================== */
  try {
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var TrustAll = Java.registerClass({
      name: 'dev.rt.TrustAll', implements: [X509],
      methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {}, getAcceptedIssuers: function () { return []; } }
    });
    var HV = Java.use('javax.net.ssl.HostnameVerifier');
    var TrueHV = Java.registerClass({ name: 'dev.rt.TrueHV', implements: [HV], methods: { verify: function () { return true; } } });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustAll.$new()], null);
    var Https = Java.use('javax.net.ssl.HttpsURLConnection');
    Https.setDefaultSSLSocketFactory(ctx.getSocketFactory());
    Https.setDefaultHostnameVerifier(TrueHV.$new());
    L('INIT', 'trust-all + accept-any-hostname installed');
  } catch (e) { L('INIT', 'trust-all skipped: ' + e); }

  ['okhttp3.CertificatePinner', 'org.cocos2dx.okhttp3.CertificatePinner'].forEach(function (cls) {
    try {
      var CP = Java.use(cls);
      CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {};
      L('INIT', cls + ' bypassed');
    } catch (e) {}
  });
  try {
    var OHV = Java.use('org.cocos2dx.okhttp3.internal.tls.OkHostnameVerifier');
    OHV.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () { return true; };
    OHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () { return true; };
    L('INIT', 'OkHostnameVerifier bypassed');
  } catch (e) {}

  /* ===================== 2. HTTP — okhttp ===================== */
  try {
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    RealCall.getResponseWithInterceptorChain.implementation = function () {
      var resp = this.getResponseWithInterceptorChain();
      try {
        var req = resp.request();
        var url = req.url().toString();
        var method = req.method();
        var rb = readReqBody(req.body());
        L('HTTP', 'REQ ' + method + ' ' + url + (rb ? '  body=' + rb : ''));
        var pb = resp.peekBody(MAXBODY).string();
        L('HTTP', 'RES ' + resp.code() + ' ' + url + '  ' + pb);
        flagBind(url, rb, pb);
      } catch (e) { L('HTTP', 'err ' + e); }
      return resp;
    };
    L('INIT', 'okhttp RealCall hooked');
  } catch (e) { L('INIT', 'okhttp hook skipped: ' + e); }

  /* ===================== 3. HTTP — HttpURLConnection ===================== */
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      var c = this.openConnection();
      try { L('HTTP', 'OPEN ' + this.getProtocol().toUpperCase() + ' ' + this.toString()); } catch (e) {}
      return c;
    };
    L('INIT', 'HttpURLConnection hooked');
  } catch (e) {}

  /* ===================== 4. WebSocket (wss) ===================== */
  // okhttp RealWebSocket send + listener onMessage
  try {
    var RWS = Java.use('okhttp3.RealWebSocket');
    RWS.send.overload('java.lang.String').implementation = function (s) { L('WS', 'SEND(str) ' + s); return this.send(s); };
    RWS.send.overload('okio.ByteString').implementation = function (b) { L('WS', 'SEND(bin) ' + hex(b.toByteArray())); return this.send(b); };
    L('INIT', 'okhttp RealWebSocket hooked');
  } catch (e) {}
  // generic WebSocketListener.onMessage (covers cocos + okhttp listeners)
  ['okhttp3.WebSocketListener', 'org.cocos2dx.lib.WebSocket$SocketListener'].forEach(function (cls) {
    try {
      var WL = Java.use(cls);
      WL.onMessage.overload('okhttp3.WebSocket', 'okio.ByteString').implementation = function (ws, b) {
        L('WS', 'RECV(bin) ' + hex(b.toByteArray())); return this.onMessage(ws, b);
      };
      WL.onMessage.overload('okhttp3.WebSocket', 'java.lang.String').implementation = function (ws, s) {
        L('WS', 'RECV(str) ' + s); return this.onMessage(ws, s);
      };
      L('INIT', cls + '.onMessage hooked');
    } catch (e) {}
  });

  /* ===================== 5. CRYPTO — keys / IV / HMAC / digest ===================== */
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function (m, k) {
      L('CRYPTO', 'Cipher.init mode=' + m + ' alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded()));
      return this.init(m, k);
    };
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (m, k, s) {
      L('CRYPTO', 'Cipher.init mode=' + m + ' alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded()) + ' spec=' + s);
      return this.init(m, k, s);
    };
    Cipher.doFinal.overload('[B').implementation = function (inp) {
      var out = this.doFinal(inp);
      L('CRYPTO', 'Cipher.doFinal in=' + hex(inp) + ' out=' + hex(out));
      return out;
    };
    L('INIT', 'Cipher hooked');
  } catch (e) { L('INIT', 'Cipher hook skipped: ' + e); }

  try {
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
      L('CRYPTO', 'SecretKeySpec alg=' + a + ' key=' + hex(k));
      return this.$init(k, a);
    };
    var IVS = Java.use('javax.crypto.spec.IvParameterSpec');
    IVS.$init.overload('[B').implementation = function (iv) {
      L('CRYPTO', 'IvParameterSpec iv=' + hex(iv));
      return this.$init(iv);
    };
    L('INIT', 'SecretKeySpec/IvParameterSpec hooked');
  } catch (e) {}

  try {
    var Mac = Java.use('javax.crypto.Mac');
    Mac.init.overload('java.security.Key').implementation = function (k) {
      L('CRYPTO', 'Mac.init alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded()));
      return this.init(k);
    };
    Mac.doFinal.overload('[B').implementation = function (inp) {
      var out = this.doFinal(inp);
      L('CRYPTO', 'Mac.doFinal in=' + hex(inp) + ' mac=' + hex(out));
      return out;
    };
    L('INIT', 'Mac (HMAC) hooked');
  } catch (e) {}

  try {
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (inp) {
      var out = this.digest(inp);
      L('CRYPTO', 'MessageDigest.' + this.getAlgorithm() + ' in=' + hex(inp) + ' out=' + hex(out));
      return out;
    };
    L('INIT', 'MessageDigest hooked');
  } catch (e) {}

  /* ============ 6. flag the no-OTP bank/phone bind ============ */
  function flagBind(url, reqBody, resBody) {
    try {
      if (!/kyc\/bind|user\/editCard|draw\/order/i.test(url)) return;
      var hasCode = /["&?]code=/.test(reqBody || '');
      var emptyCode = /[?&]code=(&|$)/.test(reqBody || '') || /"code"\s*:\s*""/.test(reqBody || '');
      L('BIND', url + '  otp_code_present=' + hasCode + '  otp_code_EMPTY=' + emptyCode + '  req=' + reqBody);
    } catch (e) {}
  }

  L('INIT', 'ready — use the app; logs go to logcat and runtime.log');
});
