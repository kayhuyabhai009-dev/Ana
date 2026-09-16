/*
 * frida_full.js — ONE comprehensive runtime-capture script for the ORIGINAL ShareSlots APK.
 * Rooted device, no repack. Hooks are matched to the app's actual (shaded) classes.
 *
 *   frida -U -f com.shareslots.games.fun -l frida_full.js
 *
 * Logs to logcat AND to /sdcard/Android/data/com.shareslots.games.fun/files/runtime.log
 * (app-specific dir — no storage permission needed):
 *   adb pull /sdcard/Android/data/com.shareslots.games.fun/files/runtime.log
 *
 * Captured (tag [RT][...]):
 *   HTTP    every game API request+response (org.cocos2dx.lib.Cocos2dxHttpURLConnection)
 *   WS      every WebSocket frame out/in (org.cocos2dx.okhttp3 RealWebSocket + listener)
 *   CRYPTO  Cipher init/doFinal, SecretKeySpec(keys), IvParameterSpec(IV), Mac(HMAC), MessageDigest
 *   BIND    kyc/bind + user/editCard payloads, flags an EMPTY otp `code`
 * Also disables TLS pinning so a mitmproxy/HttpCanary CA is accepted.
 *
 * WS frames are [8-byte header][msgpack] — decode with harness/referral_capture/decode_hcy.py.
 */
'use strict';

var TAG = 'RT';
var LOG_TO_FILE = true;

function now() { return new Date().toISOString(); }

function hex(bytes) {
  if (!bytes) return '';
  var a = [];
  var n = Math.min(bytes.length, 8192);
  for (var i = 0; i < n; i++) { var h = (bytes[i] & 0xff).toString(16); a.push(h.length < 2 ? '0' + h : h); }
  return a.join('') + (bytes.length > n ? '…(' + bytes.length + 'b)' : '');
}

function u8(bytes) {
  if (!bytes) return '';
  try { return Java.use('java.lang.String').$new(bytes, 'UTF-8'); } catch (e) { return hex(bytes); }
}

var outFile;
function ensureFile() {
  if (outFile !== undefined) return outFile;
  try {
    var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var dir = ctx.getExternalFilesDir(null);
    outFile = dir ? dir.getAbsolutePath() + '/runtime.log' : false;
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
        var w = Java.use('java.io.FileWriter').$new(p, true);
        w.write(now() + ' ' + line + '\n'); w.flush(); w.close();
      } catch (e) {}
    }
  }
}

function flagBind(where, body) {
  try {
    if (!body) return;
    if (!/kyc\/bind|editCard|draw\/order|cat=mobile|cat=bank/i.test(body)) return;
    var empty = /[?&]code=(&|$)/.test(body) || /"code"\s*:\s*""/.test(body) || /code=$/.test(body);
    L('BIND', where + '  otp_code_EMPTY=' + empty + '  ' + body.slice(0, 1000));
  } catch (e) {}
}

Java.perform(function () {
  L('INIT', 'ShareSlots full capture armed');

  /* ---------- 1. TLS pinning bypass ---------- */
  try {
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var TrustAll = Java.registerClass({ name: 'dev.rt.TrustAll', implements: [X509],
      methods: { checkClientTrusted: function () {}, checkServerTrusted: function () {}, getAcceptedIssuers: function () { return []; } } });
    var HV = Java.use('javax.net.ssl.HostnameVerifier');
    var TrueHV = Java.registerClass({ name: 'dev.rt.TrueHV', implements: [HV], methods: { verify: function () { return true; } } });
    var ctx = Java.use('javax.net.ssl.SSLContext').getInstance('TLS');
    ctx.init(null, [TrustAll.$new()], null);
    var Https = Java.use('javax.net.ssl.HttpsURLConnection');
    Https.setDefaultSSLSocketFactory(ctx.getSocketFactory());
    Https.setDefaultHostnameVerifier(TrueHV.$new());
    L('INIT', 'trust-all installed');
  } catch (e) { L('INIT', 'trust-all skipped: ' + e); }

  ['org.cocos2dx.okhttp3.CertificatePinner', 'okhttp3.CertificatePinner'].forEach(function (cls) {
    try {
      var CP = Java.use(cls);
      CP.check.overload('java.lang.String', 'java.util.List').implementation = function () {};
      CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () {};
      L('INIT', cls + ' bypassed');
    } catch (e) {}
  });
  ['org.cocos2dx.okhttp3.internal.tls.OkHostnameVerifier', 'okhttp3.internal.tls.OkHostnameVerifier'].forEach(function (cls) {
    try {
      var OHV = Java.use(cls);
      OHV.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () { return true; };
      OHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () { return true; };
      L('INIT', cls + ' bypassed');
    } catch (e) {}
  });

  /* ---------- 2. HTTP (game API via Cocos2dxHttpURLConnection) ---------- */
  try {
    var H = Java.use('org.cocos2dx.lib.Cocos2dxHttpURLConnection');
    H.createHttpURLConnection.implementation = function (url) { L('HTTP', 'REQ ' + url); return this.createHttpURLConnection(url); };
    H.setRequestMethod.implementation = function (c, m) { L('HTTP', 'METHOD ' + m); return this.setRequestMethod(c, m); };
    H.sendRequest.implementation = function (c, body) {
      var s = u8(body); L('HTTP', 'REQ-BODY ' + s); flagBind('http-req', s); return this.sendRequest(c, body);
    };
    H.getResponseCode.implementation = function (c) { var r = this.getResponseCode(c); L('HTTP', 'RES-CODE ' + r); return r; };
    H.getResponseContent.implementation = function (c) {
      var b = this.getResponseContent(c); var s = u8(b);
      L('HTTP', 'RES ' + s.slice(0, 4000)); flagBind('http-res', s); return b;
    };
    L('INIT', 'Cocos2dxHttpURLConnection hooked');
  } catch (e) { L('INIT', 'http hook skipped: ' + e); }

  /* ---------- 3. WebSocket OUT (shaded okhttp RealWebSocket) ---------- */
  try {
    var RWS = Java.use('org.cocos2dx.okhttp3.internal.ws.RealWebSocket');
    RWS.send.overload('java.lang.String').implementation = function (s) { L('WS', 'SEND(str) ' + s); return this.send(s); };
    RWS.send.overload('org.cocos2dx.okio.ByteString').implementation = function (b) { L('WS', 'SEND(bin) ' + hex(b.toByteArray())); return this.send(b); };
    L('INIT', 'RealWebSocket.send hooked');
  } catch (e) { L('INIT', 'ws-send hook skipped: ' + e); }

  /* ---------- 4. WebSocket IN (concrete WebSocketListener subclasses) ---------- */
  function hookListeners() {
    var WSL;
    try { WSL = Java.use('org.cocos2dx.okhttp3.WebSocketListener'); } catch (e) { return; }
    Java.enumerateLoadedClasses({
      onMatch: function (name) {
        try {
          var C = Java.use(name);
          if (!C.class || !WSL.class.isAssignableFrom(C.class)) return;
          if (name === 'org.cocos2dx.okhttp3.WebSocketListener') return;
          try { C.onMessage.overload('org.cocos2dx.okhttp3.WebSocket', 'org.cocos2dx.okio.ByteString').implementation =
            function (ws, b) { L('WS', 'RECV(bin) ' + hex(b.toByteArray())); return this.onMessage(ws, b); }; } catch (e) {}
          try { C.onMessage.overload('org.cocos2dx.okhttp3.WebSocket', 'java.lang.String').implementation =
            function (ws, s) { L('WS', 'RECV(str) ' + s); return this.onMessage(ws, s); }; } catch (e) {}
          L('INIT', 'WS listener hooked: ' + name);
        } catch (e) {}
      },
      onComplete: function () {}
    });
  }
  hookListeners();
  setTimeout(hookListeners, 4000);   // catch listeners created after startup
  setTimeout(hookListeners, 12000);

  /* ---------- 5. CRYPTO (keys / IV / HMAC / digest) ---------- */
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.init.overload('int', 'java.security.Key').implementation = function (m, k) {
      L('CRYPTO', 'Cipher.init mode=' + m + ' alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded())); return this.init(m, k);
    };
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (m, k, s) {
      L('CRYPTO', 'Cipher.init mode=' + m + ' alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded()) + ' spec=' + s); return this.init(m, k, s);
    };
    Cipher.doFinal.overload('[B').implementation = function (i) { var o = this.doFinal(i); L('CRYPTO', 'Cipher.doFinal in=' + hex(i) + ' out=' + hex(o)); return o; };
    L('INIT', 'Cipher hooked');
  } catch (e) { L('INIT', 'Cipher skipped: ' + e); }

  try {
    var SKS = Java.use('javax.crypto.spec.SecretKeySpec');
    SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) { L('CRYPTO', 'SecretKeySpec alg=' + a + ' key=' + hex(k)); return this.$init(k, a); };
    var IVS = Java.use('javax.crypto.spec.IvParameterSpec');
    IVS.$init.overload('[B').implementation = function (iv) { L('CRYPTO', 'IvParameterSpec iv=' + hex(iv)); return this.$init(iv); };
    L('INIT', 'SecretKeySpec/IvParameterSpec hooked');
  } catch (e) {}

  try {
    var Mac = Java.use('javax.crypto.Mac');
    Mac.init.overload('java.security.Key').implementation = function (k) { L('CRYPTO', 'Mac.init alg=' + k.getAlgorithm() + ' key=' + hex(k.getEncoded())); return this.init(k); };
    Mac.doFinal.overload('[B').implementation = function (i) { var o = this.doFinal(i); L('CRYPTO', 'Mac.doFinal in=' + hex(i) + ' mac=' + hex(o)); return o; };
    L('INIT', 'Mac hooked');
  } catch (e) {}

  try {
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (i) { var o = this.digest(i); L('CRYPTO', 'MessageDigest.' + this.getAlgorithm() + ' in=' + hex(i) + ' out=' + hex(o)); return o; };
    L('INIT', 'MessageDigest hooked');
  } catch (e) {}

  L('INIT', 'ready — use the app; logs -> logcat + runtime.log');
});
