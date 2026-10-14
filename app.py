"""
app.py
------
Flask backend for the key-based Image Encryption & Sharing app.

Routes:
  GET/POST  /signup     Create an account (email, password, dob, profession)
  GET/POST  /login      Log in
  GET       /logout     Log out
  GET       /           Dashboard (requires login) — upload/encrypt + your images
  POST      /encrypt    Encrypt an uploaded image, returns a one-time share key
  GET       /decrypt    Public page — paste a share key to unlock an image
  POST      /decrypt    Public endpoint — verifies the key, returns the image

Only /encrypt and the dashboard require login. Decryption is intentionally
public and account-free, so a share key works for anyone, on any device,
in any browser — exactly like sharing a link or a password.
"""

import os
import io
import uuid
from datetime import datetime, date
from functools import wraps

from flask import Flask, request, jsonify, session, redirect, url_for, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from bson.binary import Binary

import crypto_utils
import db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-before-deploying")

SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = crypto_utils.load_or_create_server_keypair()

PROFESSIONS = ["Student", "Teacher", "Engineer", "Researcher", "Other"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "email" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def calculate_age(dob_str: str) -> int:
    dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


# ---------------------------------------------------------------------------
# Auth pages
# ---------------------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html", professions=PROFESSIONS)

    data = request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    dob = data.get("dob", "")
    profession = data.get("profession", "")

    if not email or not password or not dob or not profession:
        return jsonify({"error": "All fields are required."}), 400
    if db.users_collection.find_one({"email": email}):
        return jsonify({"error": "An account with this email already exists."}), 400

    try:
        age = calculate_age(dob)
    except ValueError:
        return jsonify({"error": "Invalid date of birth."}), 400

    db.users_collection.insert_one({
        "email": email,
        "password_hash": generate_password_hash(password),
        "dob": dob,
        "age": age,
        "profession": profession,
        "created_at": datetime.utcnow(),
    })

    session["email"] = email
    return jsonify({"message": "Account created.", "redirect": url_for("dashboard")}), 201


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    data = request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = db.users_collection.find_one({"email": email})
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect email or password."}), 401

    session["email"] = email
    return jsonify({"message": "Logged in.", "redirect": url_for("dashboard")})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard (upload + encrypt, view your own images)
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    email = session["email"]
    user = db.users_collection.find_one({"email": email})
    images = list(db.images_collection.find({"owner_email": email}).sort("created_at", -1))
    return render_template("dashboard.html", user=user, images=images)


@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt():
    if "image" not in request.files:
        return jsonify({"error": "No image file provided."}), 400

    image_file = request.files["image"]
    image_bytes = image_file.read()
    if not image_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    # AES layer — encrypt the image itself
    ciphertext, nonce, aes_key = crypto_utils.encrypt_image(image_bytes)

    # RSA layer — protect the AES key at rest in the database
    encrypted_aes_key = crypto_utils.encrypt_aes_key_with_rsa(aes_key, SERVER_PUBLIC_KEY)

    # Shareable secret — only its hash is stored, the plaintext is shown once
    secret = crypto_utils.generate_secret_token()
    key_hash = crypto_utils.hash_secret(secret)

    image_id = uuid.uuid4().hex[:8]

    db.images_collection.insert_one({
        "image_id": image_id,
        "owner_email": session["email"],
        "filename": image_file.filename,
        "ciphertext": Binary(ciphertext),
        "nonce": Binary(nonce),
        "encrypted_aes_key": Binary(encrypted_aes_key),
        "key_hash": key_hash,
        "original_hash": crypto_utils.get_sha256_hash(image_bytes),
        "created_at": datetime.utcnow(),
    })

    share_key = f"{image_id}.{secret}"

    return jsonify({
        "message": "Image encrypted and stored.",
        "image_id": image_id,
        "filename": image_file.filename,
        "share_key": share_key,
    }), 201


# ---------------------------------------------------------------------------
# Public decryption (no login — works on any browser/device)
# ---------------------------------------------------------------------------
@app.route("/decrypt", methods=["GET"])
def decrypt_page():
    return render_template("decrypt.html")


@app.route("/decrypt", methods=["POST"])
def decrypt_submit():
    share_key = request.form.get("share_key", "").strip()

    if "." not in share_key:
        return jsonify({"error": "That doesn't look like a valid key."}), 400

    image_id, secret = share_key.split(".", 1)
    record = db.images_collection.find_one({"image_id": image_id})

    if not record:
        return jsonify({"error": "No image found for this key."}), 404
    if not crypto_utils.verify_secret(secret, record["key_hash"]):
        return jsonify({"error": "Incorrect key."}), 403

    try:
        aes_key = crypto_utils.decrypt_aes_key_with_rsa(bytes(record["encrypted_aes_key"]), SERVER_PRIVATE_KEY)
        image_bytes = crypto_utils.decrypt_image(bytes(record["ciphertext"]), bytes(record["nonce"]), aes_key)
    except Exception:
        return jsonify({"error": "Decryption failed — the data may be corrupted."}), 400

    verified = crypto_utils.get_sha256_hash(image_bytes) == record.get("original_hash")

    return send_file(
        io.BytesIO(image_bytes),
        mimetype="image/png",
        as_attachment=False,
        download_name=record["filename"],
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
