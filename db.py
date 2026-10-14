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
"""

import os
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.environ.get("MONGO_DB_NAME", "image_vault")

_client = MongoClient(MONGO_URI)
_db = _client[DB_NAME]

users_collection = _db["users"]
images_collection = _db["images"]

# Helpful indexes — safe to call repeatedly, MongoDB no-ops if they exist.
users_collection.create_index("email", unique=True)
images_collection.create_index("image_id", unique=True)
