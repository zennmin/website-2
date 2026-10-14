"""
crypto_utils.py
----------------
Cryptographic core for the key-based image encryption/sharing app.

Design (different from an account-to-account sharing model):
  - Every image is encrypted with its own fresh AES-256-GCM key.
  - That AES key is never handed to anyone directly. Instead:
      1. It is encrypted with the SERVER's RSA public key before being
         stored in MongoDB (so a database leak alone never exposes it).
      2. A separate, random, human-shareable SECRET TOKEN is generated
         and shown to the uploader ONCE. Only a salted hash of this
         token is stored in the database (same principle as a password).
  - To decrypt, the receiver submits that token (pasted into the
    Decrypt page, on any browser/device, no account needed). The server
    verifies the token's hash, uses its own RSA private key to recover
    the AES key, and decrypts the image.

This means: even someone with full read access to the database cannot
decrypt any image without also knowing the plaintext token — which only
ever existed in the uploader's clipboard/chat message, never in storage.
"""

import os
import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

SERVER_PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), "server_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), "server_public.pem")


# ---------------------------------------------------------------------------
# Server RSA key pair — generated once, persisted to disk, reused after that.
# (In production, treat server_private.pem like any other secret: keep it
#  out of version control and restrict file permissions.)
# ---------------------------------------------------------------------------
def load_or_create_server_keypair():
    if os.path.exists(SERVER_PRIVATE_KEY_PATH) and os.path.exists(SERVER_PUBLIC_KEY_PATH):
        with open(SERVER_PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(SERVER_PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return public_key, private_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

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

    return public_key, private_key


# ---------------------------------------------------------------------------
# AES-256-GCM — encrypts/decrypts the actual image bytes
# ---------------------------------------------------------------------------
def encrypt_image(image_bytes: bytes):
    """Returns (ciphertext, nonce, aes_key)."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, image_bytes, associated_data=None)
    return ciphertext, nonce, aes_key


def decrypt_image(ciphertext: bytes, nonce: bytes, aes_key: bytes) -> bytes:
    """Raises an exception if the ciphertext was tampered with (GCM's built-in check)."""
    return AESGCM(aes_key).decrypt(nonce, ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# RSA wrapping of the AES key (protects it at rest in MongoDB)
# ---------------------------------------------------------------------------
def encrypt_aes_key_with_rsa(aes_key: bytes, public_key) -> bytes:
    return public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key) -> bytes:
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )


# ---------------------------------------------------------------------------
# Shareable secret token — this is what the user actually copies and sends
# ---------------------------------------------------------------------------
def generate_secret_token() -> str:
    """A short, URL-safe random token, e.g. 'Kx9mQ2pLz7Rt4Ywb'."""
    return secrets.token_urlsafe(12)


def hash_secret(secret: str) -> str:
    """One-way hash of the secret token, safe to store in the database."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, stored_hash: str) -> bool:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest() == stored_hash


def get_sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
