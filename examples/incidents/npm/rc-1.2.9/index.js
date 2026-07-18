// rc@1.2.9 (Nov 2021). Hijacked alongside coa as part of the same
// campaign — both packages were popular ts/build dependencies that got
// preinstall scripts pointing at a remote-hosted second-stage loader.
//
// Detection target:
//   - install-hook (preinstall declared in package.json)
//   - install-hook-suspicious (inline `node -e require('http')`)
//   - dynamic-eval (eval(d.toString()) inside the inline preinstall)
//   - net-egress (require('http').get)

module.exports = function rc() {
  // Stub: real rc is a config loader. The malware lived purely in
  // the preinstall script in package.json.
  return {};
};
