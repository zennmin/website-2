"""
app.py
------
Flask backend for SecureImage — key-based image encryption & sharing.

Routes:
  GET   /               Public landing page (interactive demo)
  GET   /healthz        Health check for Render
  GET/POST /signup      Create an account
  GET/POST /login       Log in
  GET   /logout         Log out
  GET   /dashboard      Upload/encrypt + your images (login required)
  POST  /encrypt        Encrypt an image, returns a one-time share key (login)
  GET   /decrypt        Public page — paste a share key
  POST  /decrypt        Public — verifies the key, returns the image
  GET   /download/<id>              Owner download (login)
  GET   /download/share/<key>       Public download with a share key
"""

import os
import io
import time
import uuid
import mimetypes
from collections import defaultdict, deque
from datetime import datetime, date
from functools import wraps

from flask import Flask, request, jsonify, session, redirect, url_for, render_template, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from bson.binary import Binary

import crypto_utils
import db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

ON_RENDER = bool(os.environ.get("RENDER"))
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-this-before-deploying")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=ON_RENDER,          # HTTPS only in production
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024,
)
# Render terminates TLS at a proxy; trust its forwarded headers (real client IP, https).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if ON_RENDER and app.secret_key.startswith("dev-only"):
    print("WARNING: SECRET_KEY is not set; sessions are insecure.")

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
    if dob > today:
        raise ValueError("dob in future")
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


# Simple in-memory limiter for wrong-key guesses (per worker process).
# For multiple instances, back this with Redis or MongoDB.
_FAIL_WINDOW = 300
_FAIL_LIMIT = 10
_failures = defaultdict(deque)


def _client_ip():
    return request.remote_addr or "unknown"


def _is_blocked():
    q = _failures[_client_ip()]
    now = time.time()
    while q and now - q[0] > _FAIL_WINDOW:
        q.popleft()
    return len(q) >= _FAIL_LIMIT


def _record_failure():
    _failures[_client_ip()].append(time.time())


def _resolve_share_key(share_key):
    """Returns (record, image_bytes, error_response). Handles limiting + verification."""
    share_key = (share_key or "").strip()
    if _is_blocked():
        return None, None, (jsonify({"error": "Too many wrong attempts. Try again in a few minutes."}), 429)
    if "." not in share_key:
        return None, None, (jsonify({"error": "That doesn't look like a valid key."}), 400)

    image_id, secret = share_key.split(".", 1)
    record = db.images_collection.find_one({"image_id": image_id})
    if not record:
        _record_failure()
        return None, None, (jsonify({"error": "No image found for this key."}), 404)
    if not crypto_utils.verify_secret(secret, record["key_hash"]):
        _record_failure()
        return None, None, (jsonify({"error": "Incorrect key."}), 403)

    try:
        image_bytes = _decrypt_record(record)
    except Exception:
        return None, None, (jsonify({"error": "Decryption failed — the data may be corrupted."}), 400)
    return record, image_bytes, None


def _decrypt_record(record):
    aes_key = crypto_utils.decrypt_aes_key_with_rsa(bytes(record["encrypted_aes_key"]), SERVER_PRIVATE_KEY)
    return crypto_utils.decrypt_image(bytes(record["ciphertext"]), bytes(record["nonce"]), aes_key)


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    return resp


@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "That file is too large."}), 413


# ---------------------------------------------------------------------------
# Public pages
# ---------------------------------------------------------------------------
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/healthz")
def healthz():
    return "ok", 200


# ---------------------------------------------------------------------------
# Auth
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
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if profession not in PROFESSIONS:
        return jsonify({"error": "Please choose a profession from the list."}), 400
    if db.users_collection.find_one({"email": email}):
        return jsonify({"error": "An account with this email already exists."}), 400

    try:
        age = calculate_age(dob)
    except ValueError:
        return jsonify({"error": "Invalid date of birth."}), 400

    try:
        db.users_collection.insert_one({
            "email": email,
            "password_hash": generate_password_hash(password),
            "dob": dob,
            "age": age,
            "profession": profession,
            "created_at": datetime.utcnow(),
        })
    except Exception:
        return jsonify({"error": "An account with this email already exists."}), 400

    session.clear()
    session["email"] = email
    session.permanent = True
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

    session.clear()
    session["email"] = email
    session.permanent = True
    return jsonify({"message": "Logged in.", "redirect": url_for("dashboard")})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ---------------------------------------------------------------------------
# Dashboard + encrypt
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    email = session["email"]
    user = db.users_collection.find_one({"email": email})
    if not user:
        session.clear()
        return redirect(url_for("login"))
    images = list(
        db.images_collection.find({"owner_email": email}, {"ciphertext": 0})
        .sort("created_at", -1)
    )
    return render_template("dashboard.html", user=user, images=images)


@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt():
    if "image" not in request.files:
        return jsonify({"error": "No image file provided."}), 400

    image_file = request.files["image"]
    if image_file.mimetype and not image_file.mimetype.startswith("image/"):
        return jsonify({"error": "Only image files are supported."}), 400
    image_bytes = image_file.read()
    if not image_bytes:
        return jsonify({"error": "Uploaded file is empty."}), 400

    ciphertext, nonce, aes_key = crypto_utils.encrypt_image(image_bytes)
    encrypted_aes_key = crypto_utils.encrypt_aes_key_with_rsa(aes_key, SERVER_PUBLIC_KEY)

    secret = crypto_utils.generate_secret_token()
    key_hash = crypto_utils.hash_secret(secret)
    image_id = uuid.uuid4().hex[:8]
    filename = os.path.basename(image_file.filename or "image.png") or "image.png"

    db.images_collection.insert_one({
        "image_id": image_id,
        "owner_email": session["email"],
        "filename": filename,
        "ciphertext": Binary(ciphertext),
        "nonce": Binary(nonce),
        "encrypted_aes_key": Binary(encrypted_aes_key),
        "key_hash": key_hash,
        "original_hash": crypto_utils.get_sha256_hash(image_bytes),
        "created_at": datetime.utcnow(),
    })

    return jsonify({
        "message": "Image encrypted and stored.",
        "image_id": image_id,
        "filename": filename,
        "share_key": f"{image_id}.{secret}",
    }), 201


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------
@app.route("/download/<image_id>", methods=["GET"])
@login_required
def download_user_image(image_id):
    record = db.images_collection.find_one({"image_id": image_id, "owner_email": session["email"]})
    if not record:
        return jsonify({"error": "No image found or access denied."}), 404
    try:
        image_bytes = _decrypt_record(record)
    except Exception:
        return jsonify({"error": "Decryption failed — the data may be corrupted."}), 400
    return send_file(io.BytesIO(image_bytes), mimetype="application/octet-stream",
                     as_attachment=True, download_name=record.get("filename", f"{image_id}.png"))


@app.route("/download/share/<path:share_key>", methods=["GET"])
def download_by_share_key(share_key):
    record, image_bytes, err = _resolve_share_key(share_key)
    if err:
        return err
    return send_file(io.BytesIO(image_bytes), mimetype="application/octet-stream",
                     as_attachment=True, download_name=record.get("filename", "image.png"))


# ---------------------------------------------------------------------------
# Public decrypt
# ---------------------------------------------------------------------------
@app.route("/decrypt", methods=["GET"])
def decrypt_page():
    return render_template("decrypt.html", prefill_key=request.args.get("key", "").strip())


@app.route("/decrypt", methods=["POST"])
def decrypt_submit():
    record, image_bytes, err = _resolve_share_key(request.form.get("share_key", ""))
    if err:
        return err

    filename = record.get("filename", "image.png")
    guessed = mimetypes.guess_type(filename)[0] or "image/png"
    if not guessed.startswith("image/"):
        guessed = "image/png"

    response = send_file(io.BytesIO(image_bytes), mimetype=guessed,
                         as_attachment=False, download_name=filename)
    response.headers["X-Filename"] = filename
    response.headers["X-Integrity"] = (
        "verified" if crypto_utils.get_sha256_hash(image_bytes) == record.get("original_hash") else "mismatch"
    )
    response.headers["Access-Control-Expose-Headers"] = "X-Filename, X-Integrity"
    return response


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=not ON_RENDER, host="0.0.0.0", port=port)
