"""
crypto_utils.py
----------------
Cryptographic core for SecureImage (key-based image encryption and sharing).

  - Every image is encrypted with its own fresh AES-256-GCM key.
  - That AES key is wrapped with the SERVER's RSA public key before being
    stored in MongoDB (a database leak alone never exposes it).
  - A random SECRET TOKEN is shown to the uploader ONCE. Only its SHA-256
    hash is stored.
  - To decrypt, the receiver submits "{image_id}.{secret}". The server checks
    the hash, unwraps the AES key with its RSA private key, and decrypts.

RSA KEY STORAGE (important for Render)
  Render's filesystem is ephemeral, so a key written to disk is lost on every
  restart/redeploy and all stored images would become undecryptable.
  Key loading order:
    1. SERVER_PRIVATE_KEY_PEM environment variable   <- use this on Render
    2. server_private.pem next to this file           <- local development
    3. Generate a new key (and try to save it to disk) <- first local run only
"""

import os
import secrets
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_PRIVATE_KEY_PATH = os.path.join(_DIR, "server_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(_DIR, "server_public.pem")


def _pem_from_env():
    raw = os.environ.get("SERVER_PRIVATE_KEY_PEM", "").strip()
    if not raw:
        return None
    # Allow single-line values where newlines were typed as the two characters \n
    return raw.replace("\\n", "\n").encode("utf-8")


def load_or_create_server_keypair():
    """Returns (public_key, private_key)."""
    pem = _pem_from_env()
    if pem:
        private_key = serialization.load_pem_private_key(pem, password=None)
        return private_key.public_key(), private_key

    if os.path.exists(SERVER_PRIVATE_KEY_PATH):
        with open(SERVER_PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        return private_key.public_key(), private_key

    if os.environ.get("RENDER"):
        print(
            "WARNING: SERVER_PRIVATE_KEY_PEM is not set on Render. A temporary key "
            "will be generated and images will be UNREADABLE after the next restart. "
            "Run `python generate_key.py` and add the output as an environment variable."
        )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    try:
        with open(SERVER_PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(SERVER_PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
    except OSError:
        pass  # read-only filesystem; key lives in memory only
    return public_key, private_key


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------
def encrypt_image(image_bytes: bytes):
    """Returns (ciphertext, nonce, aes_key)."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, image_bytes, associated_data=None)
    return ciphertext, nonce, aes_key


def decrypt_image(ciphertext: bytes, nonce: bytes, aes_key: bytes) -> bytes:
    """Raises if the ciphertext was tampered with (GCM authentication)."""
    return AESGCM(aes_key).decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# RSA wrapping of the AES key
# ---------------------------------------------------------------------------
_OAEP = lambda: padding.OAEP(  # noqa: E731
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def encrypt_aes_key_with_rsa(aes_key: bytes, public_key) -> bytes:
    return public_key.encrypt(aes_key, _OAEP())


def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key) -> bytes:
    return private_key.decrypt(encrypted_key, _OAEP())


# ---------------------------------------------------------------------------
# Shareable secret token
# ---------------------------------------------------------------------------
def generate_secret_token() -> str:
    """URL-safe random token, e.g. 'Kx9mQ2pLz7Rt4Ywb'."""
    return secrets.token_urlsafe(12)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash)


def get_sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
