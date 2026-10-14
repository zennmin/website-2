"""
db.py
-----
MongoDB connection helper. Reads MONGO_URI (works with local mongod or Atlas).

Collections:
  users  : {email, password_hash, dob, age, profession, created_at}
  images : {image_id, owner_email, filename, ciphertext, nonce,
            encrypted_aes_key, key_hash, original_hash, created_at}
"""

import os
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB_NAME", "secure_image")

# Fail fast instead of hanging a request for 30s if Mongo is unreachable.
_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
_db = _client[DB_NAME]

users_collection = _db["users"]
images_collection = _db["images"]

# Indexes are best-effort so a briefly unreachable DB doesn't stop the app booting.
try:
    users_collection.create_index("email", unique=True)
    images_collection.create_index("image_id", unique=True)
    images_collection.create_index("owner_email")
except Exception as exc:  # noqa: BLE001
    print(f"WARNING: could not create MongoDB indexes at startup: {exc}")
