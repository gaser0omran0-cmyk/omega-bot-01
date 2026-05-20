import os, subprocess, sys, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENC_KEY_B64 = os.environ.get("ENC_KEY")
PAYLOAD_B64 = os.environ.get("PAYLOAD_BIN")
if not ENC_KEY_B64 or not PAYLOAD_B64:
    sys.stderr.write("FATAL: Secrets missing.\n")
    sys.exit(1)

def safe_decode(s):
    s = s.strip()
    missing = 4 - len(s) % 4
    if missing != 4:
        s += '=' * missing
    return base64.urlsafe_b64decode(s)

try:
    key = safe_decode(ENC_KEY_B64)
    blob = safe_decode(PAYLOAD_B64)
    nonce, ct = blob[:12], blob[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
except Exception as e:
    sys.stderr.write(f"Decryption failed: {e}\n")
    sys.exit(1)

exec(plaintext.decode("utf-8"))
