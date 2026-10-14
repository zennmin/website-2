"""
db.py
-----
MongoDB connection helper.

Reads the connection string from the MONGO_URI environment variable so the
same code works locally, on MongoDB Atlas, or on any hosting provider.
Defaults to a local MongoDB instance for development.

Collections used:
  - users  : {email, password_hash, dob, age, profession, created_at}
  - images : {image_id, owner_email, filename, ciphertext, nonce,
              encrypted_aes_key, key_hash, created_at}

TLS NOTE: some hosting containers (Render included) ship an outdated or
minimal system CA bundle that fails to negotiate TLS with MongoDB Atlas,
producing errors like "SSL handshake failed ... TLSV1_ALERT_INTERNAL_ERROR"
even though the connection string itself is correct. Passing `certifi`'s
CA bundle explicitly avoids depending on the container's system certs.
"""

import os
import certifi
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB_NAME", "image_vault")

# Only Atlas (mongodb+srv:// or TLS-enabled) connections need the explicit
# CA bundle; a plain local mongodb:// URI (e.g. for local development)
# doesn't use TLS at all, so we only pass it when it's relevant.
if MONGO_URI.startswith("mongodb+srv://") or "tls=true" in MONGO_URI.lower() or "ssl=true" in MONGO_URI.lower():
    _client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
else:
    _client = MongoClient(MONGO_URI)

_db = _client[DB_NAME]

users_collection = _db["users"]
images_collection = _db["images"]

# Helpful indexes — safe to call repeatedly, MongoDB no-ops if they exist.
users_collection.create_index("email", unique=True)
images_collection.create_index("image_id", unique=True)

