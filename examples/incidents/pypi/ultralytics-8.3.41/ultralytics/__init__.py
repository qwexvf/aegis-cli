"""
ultralytics@8.3.41 / 8.3.42 (Dec 2024). Compromised via a malicious
GitHub Actions PR that injected a coinminer into the published wheel.
The payload was a stray binary at an unexpected path — NOT a CPython
ABI-tagged extension or auditwheel-bundled .libs/ entry — which is the
shape our binary-dropper detector flags for PyPI.
"""

__version__ = "8.3.41"
