// Harness: runs the APK's ACTUAL response-decrypt.js / aes-gcm-decrypt.js / crypto-js.min.js
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const DIR = __dirname;

// ---- minimal Cocos shim (only what these 4 modules touch) -------------------
globalThis.cc = {
  _RF: { push() {}, pop() {} },
  log: (...a) => { if (process.env.VERBOSE) console.log('[cc.log]', ...a); },
  warn: () => {},
};
require(path.join(DIR, 'tslib.js'));           // globalThis.__awaiter / __generator

// ---- tiny browserify-style loader ------------------------------------------
const cache = {};
function load(name) {
  if (cache[name]) return cache[name];
  const file = path.join(DIR, name + '.js');
  const src = fs.readFileSync(file, 'utf8');
  const module_ = { exports: {} };
  cache[name] = module_.exports;
  const req = (dep) => {
    dep = dep.replace(/^\.\//, '');
    if (dep === 'crypto') return require('crypto');   // CryptoJS UMD probes node crypto
    return load(dep);
  };
  // modules are bodies of  function(e, t, i) { ... }
  // browserify modules are the body of  function(e, t, i) { ... }
  vm.runInThisContext(`(function(e, t, i){\n${src}\n})`,
    { filename: file })(req, module_, module_.exports);
  cache[name] = module_.exports;
  return module_.exports;
}

const RD = load('response-decrypt');
module.exports = { RD, load, cc: globalThis.cc };
