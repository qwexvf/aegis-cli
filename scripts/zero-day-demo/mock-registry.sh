#!/usr/bin/env bash
# Tiny npm-registry-shaped HTTP server that serves the local
# scripts/zero-day-demo/pkg/ tree as @aegis/zero-day-demo@1.0.0.
#
# Usage:  ./scripts/zero-day-demo/mock-registry.sh
# Then:   AEGIS_NPM_REGISTRY=http://localhost:18080 aegis snapshot enrich
set -e

PORT="${PORT:-18080}"
HERE="$(cd "$(dirname "$0")" && pwd)"

cat > /tmp/aegis-zero-day-registry.py <<PY
import os, sys, tarfile, io, gzip, json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "18080"))
PKG_DIR = "${HERE}/pkg"
NAME = "@aegis/zero-day-demo"
VERSION = "1.0.0"
ESCAPED_NAME = NAME.replace("/", "%2f")
TARBALL_PATH = f"/{NAME}/-/zero-day-demo-{VERSION}.tgz"


def build_tarball():
    """Build a npm-shaped tarball: every entry under 'package/'."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w") as tf:
            for fname in os.listdir(PKG_DIR):
                full = os.path.join(PKG_DIR, fname)
                if not os.path.isfile(full):
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                info = tarfile.TarInfo(name=f"package/{fname}")
                info.size = len(data)
                info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TARBALL = build_tarball()


def metadata():
    return json.dumps({
        "name": NAME,
        "dist-tags": {"latest": VERSION},
        "versions": {
            VERSION: {
                "name": NAME,
                "version": VERSION,
                "dist": {
                    "tarball": f"http://localhost:{PORT}{TARBALL_PATH}"
                },
            }
        },
    }).encode()


FILES_PREFIX = "/files/"


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        # Allow the web app (different origin / port) to fetch source.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        # npm escapes "@scope/name" as "@scope%2fname"
        if self.path == f"/{ESCAPED_NAME}" or self.path == f"/{NAME}":
            body = metadata()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == TARBALL_PATH:
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(TARBALL)))
            self.end_headers()
            self.wfile.write(TARBALL)
            return
        # Raw file passthrough for the web editor view: GET /files/<path>
        # serves <PKG_DIR>/<path> verbatim. Used by the package-graph
        # editor when unpkg doesn't have this synthetic package.
        if self.path.startswith(FILES_PREFIX):
            rel = self.path[len(FILES_PREFIX):]
            # Trivial path traversal guard.
            if ".." in rel.split("/"):
                self.send_response(403); self._cors(); self.end_headers(); return
            full = os.path.normpath(os.path.join(PKG_DIR, rel))
            if not full.startswith(os.path.realpath(PKG_DIR)):
                self.send_response(403); self._cors(); self.end_headers(); return
            if not os.path.isfile(full):
                self.send_response(404); self._cors(); self.end_headers(); return
            with open(full, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self._cors()
        self.end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock-registry] " + (fmt % args) + "\n")


print(f"[mock-registry] serving {NAME}@{VERSION} on http://localhost:{PORT}", file=sys.stderr)
HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
PY

PORT="$PORT" exec python3 /tmp/aegis-zero-day-registry.py
