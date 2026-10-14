# SecureImage — Key-Based Image Encryption & Sharing

A full account + MongoDB version of the image encryption project, built around
a **key-based sharing model**: encrypting an image produces one shareable key
string. Anyone who has that key can decrypt the image on the public
`/decrypt` page — any browser, any device, no account required. Accounts are
only needed to *encrypt and manage* images, not to open them.

This has been tested end-to-end in this environment (signup → duplicate-email
rejection → wrong-password rejection → login → encrypt → logout → decrypt
with a wrong key correctly rejected → decrypt with the correct key →
byte-for-byte match against the original image).

## How the encryption actually works

1. **AES-256-GCM** encrypts the image itself with a key generated fresh for
   that one image.
2. That AES key is immediately **RSA-encrypted** with the server's own
   key pair and stored in that form in MongoDB — a database leak alone
   never exposes it.
3. A separate random **secret token** is generated and shown to the
   uploader **once**. Only its SHA-256 hash is stored in MongoDB (same
   principle as a password) — the plaintext token exists nowhere except
   in whatever message the uploader sends to the recipient.
4. The **share key** you actually copy is `{image_id}.{secret}` —
   e.g. `a1b2c3d4.Kx9mQ2pLz7Rt4Ywb`. The receiver pastes this single
   string into `/decrypt`. The server looks up the image by its ID,
   hashes the secret and compares it, then — only if it matches —
   uses its RSA private key to recover the AES key and decrypt the image.

This is a different trust model from a typical "share with this specific
user's account" design — it's closer to how a password-protected file link
works. Worth mentioning explicitly in your report: it trades per-user
access control for universal, account-free access via a possession-based
secret (whoever holds the key can open the image).

## Files

```
app.py               Flask routes: signup, login, dashboard, encrypt, decrypt
crypto_utils.py       AES-GCM + RSA + secret-token helpers
db.py                 MongoDB connection (reads MONGO_URI from environment)
requirements.txt
templates/
  base.html            shared layout/topbar
  signup.html          email, password, date of birth, profession
  login.html
  dashboard.html       drag-and-drop upload, one-time key reveal, image list
  decrypt.html         public key-entry page
static/style.css       shared styling
```

## Setup

### 1. Get MongoDB running
Either install MongoDB locally (`mongod`), or use a free
[MongoDB Atlas](https://www.mongodb.com/atlas) cluster — either works with
zero code changes, you just set `MONGO_URI`.

### 2. Install & run
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

export MONGO_URI="mongodb://localhost:27017"      # or your Atlas connection string
export SECRET_KEY="something-random-and-long"       # Flask session signing key

python app.py
```
Visit **http://127.0.0.1:5000** — you'll land on the login page.

### 3. Try it
1. **Sign up** with an email, password, date of birth, and profession
2. On the dashboard, **drag in an image** and click "Encrypt & store"
3. Copy the **share key** shown (it's only shown once)
4. Open `/decrypt` in an **incognito window** (proving no login is needed)
5. Paste the key — the image unlocks and displays, with a download link

## Deploying

- **Render** (recommended, same as discussed for the earlier prototype):
  - Build command: `pip install -r requirements.txt`
  - Start command: `gunicorn app:app`
  - Add environment variables in Render's dashboard: `MONGO_URI`, `SECRET_KEY`
- **MongoDB**: use MongoDB Atlas's free tier rather than trying to run
  `mongod` on Render — Render's free web services don't give you a
  persistent place to run a separate database process.
- The server's RSA key pair (`server_private.pem` / `server_public.pem`) is
  generated automatically on first run and saved next to `app.py`. On a
  platform with an ephemeral filesystem (most free tiers), this file will
  be regenerated on every restart/redeploy — which means **previously
  encrypted images become undecryptable** after a restart, since the RSA
  key that wrapped their AES keys no longer exists. For anything beyond a
  demo, generate the key pair once and store it via the platform's secret/
  environment-variable storage instead of relying on the filesystem.

## What's intentionally simplified

| This build | A production version would add |
|---|---|
| Session cookie login (Flask's built-in `session`) | CSRF protection, session expiry, "remember me" |
| Server RSA key on local disk | Key stored in a secrets manager (AWS KMS, Vault, etc.) |
| No rate limiting | Rate-limit `/decrypt` attempts — it's a password-style guess surface |
| No email verification | Confirm email ownership before allowing login |
| Single MongoDB instance, no backups | Managed DB with backups/replication |

## Note on the crypto library

Same as the earlier prototype: this uses Python's `cryptography` library
(AES-GCM + RSA-OAEP) rather than `pycryptodome`, since this sandbox has no
internet access to install it. Both implement the same standards — swap
freely if your team prefers `pycryptodome` for the final submission.
