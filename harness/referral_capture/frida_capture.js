/*
 * frida_capture.js  —  ShareSlots referral capture, no repack needed.
 * Run on a ROOTED device with frida-server:
 *   frida -U -f com.shareslots.games.fun -l frida_capture.js
 * (or attach to the already-running app)
 *
 * Does two things:
 *   1. Disables TLS certificate pinning (OkHttp CertificatePinner + hostname verifier +
 *      the Cocos JS cert.pem path) so a mitmproxy/Charles CA on the device is accepted.
 *   2. Logs every HTTP request/response whose URL looks referral/bank/withdraw related.
 *
 * This keeps the ORIGINAL APK and hot-update ON, so no crash and all server features work.
 */

// ---- helper: log to frida console AND (optionally) to the device file ----
function L(tag, msg) {
  console.log("[" + tag + "] " + msg);
  try {
    var f = new File("/data/local/tmp/referral_capture.log", "a");
    f.write(JSON.stringify({ t: Date.now(), tag: tag, msg: msg }) + "\n");
    f.flush(); f.close();
  } catch (e) {}
}

var INTEREST = /refer|invite|sharelink|draw|user\/banks|kyc|user\/info|share|agent|bonus|commission|order/i;

function logReq(method, url, body) {
  if (!INTEREST.test(url)) return;
  L("HTTP", method + " " + url + (body ? "  BODY=" + body : ""));
}
function logResp(url, code, body) {
  if (!INTEREST.test(url)) return;
  var s = body ? ("" + body) : "";
  L("RESP", code + " " + url + "  " + s.slice(0, 4000));
}

Java.perform(function () {

  /* ================= 1. SSL PINNING BYPASS ================= */

  // OkHttp CertificatePinner.check -> no-op
  try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.overload("java.lang.String", "java.util.List").implementation = function () {};
    CP.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function () {};
    console.log("[*] okhttp3.CertificatePinner bypassed");
  } catch (e) { console.log("[*] okhttp3.CertificatePinner not present (" + e + ")"); }

  // Cocos-shaded okhttp (this app ships org.cocos2dx.okhttp3.*)
  try {
    var CP2 = Java.use("org.cocos2dx.okhttp3.CertificatePinner");
    CP2.check.overload("java.lang.String", "java.util.List").implementation = function () {};
    CP2.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function () {};
    console.log("[*] org.cocos2dx.okhttp3.CertificatePinner bypassed");
  } catch (e) {}

  try {
    var OHV = Java.use("org.cocos2dx.okhttp3.internal.tls.OkHostnameVerifier");
    OHV.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function () { return true; };
    OHV.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () { return true; };
    console.log("[*] OkHostnameVerifier bypassed");
  } catch (e) {}

  // Register a permissive HostnameVerifier + X509TrustManager, install as defaults.
  try {
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var TrueHV = Java.registerClass({
      name: "dev.arena.TrueHV",
      implements: [HostnameVerifier],
      methods: { verify: function () { return true; } }
    });

    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustAll = Java.registerClass({
      name: "dev.arena.TrustAll",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });

    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustAll.$new()], null);

    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
    HttpsURLConnection.setDefaultHostnameVerifier(TrueHV.$new());
    console.log("[*] trust-all + accept-any-hostname installed for HttpsURLConnection");
  } catch (e) { console.log("[*] trust-all install skipped (" + e + ")"); }

  /* ================= 2. HTTP / WS LOGGING ================= */

  // java.net.HttpURLConnection (Cocos Creator Http on Android uses this)
  try {
    var URL = Java.use("java.net.URL");
    URL.openConnection.overload().implementation = function () {
      var conn = this.openConnection();
      try { logReq(this.getProtocol().toUpperCase(), this.toString(), null); } catch (e) {}
      return conn;
    };
    console.log("[*] HttpURLConnection hooked");
  } catch (e) { console.log("[*] URL hook skipped (" + e + ")"); }

  // OkHttp response logging
  try {
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    RealCall.getResponseWithInterceptorChain.implementation = function () {
      var resp = this.getResponseWithInterceptorChain();
      try {
        var req = resp.request();
        logResp(req.url().toString(), resp.code(), "");
      } catch (e) {}
      return resp;
    };
    console.log("[*] OkHttp RealCall hooked");
  } catch (e) {}

  console.log("[*] ShareSlots referral capture armed. Use the app; referral/bank/withdraw traffic will be logged.");
});
