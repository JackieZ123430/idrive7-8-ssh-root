import os
import sys

if getattr(sys, "frozen", False):
    _ROOT = os.path.dirname(os.path.abspath(sys.executable))
else:
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSET_DIR = os.path.join(_ROOT, "data", "assets")

FILES = {
    1: "01_PRIVATE_KEY.pem",
    3: "03_CERTIFICATE.pem",
    4: "04_RSA_PRIVATE_KEY.pem",
    5: "05_SSH_ROOT_KEY.pem",
    7: "07_M7F1.bin",
    13: "13_HEXDUMP.txt",
    14: "14_HEXDUMP.txt",
    15: "15_HEXDUMP.txt",
}


class Assets:
    def __init__(self, directory=ASSET_DIR):
        self.directory = directory
        self._cache = {}

    def raw(self, aid):
        if aid not in self._cache:
            path = os.path.join(self.directory, FILES[aid])
            if not os.path.isfile(path):
                raise FileNotFoundError(path)
            with open(path, "rb") as f:
                self._cache[aid] = f.read()
        return self._cache[aid]

    def cert(self, aid=3):
        from cryptography import x509
        return x509.load_pem_x509_certificate(self.raw(aid))
