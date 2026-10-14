# SecureImage — key-based image encryption & sharing

Flask + MongoDB app. Encrypt an image, get one share key, anyone with the key
unlocks it at `/decrypt` (no account). Public landing page at `/` includes an
in-browser AES-GCM demo.

## Deploy on Render (about 10 minutes)

### 1. MongoDB Atlas (free)
1. Create a free cluster at https://www.mongodb.com/atlas
2. Database Access: add a user + password.
3. Network Access: allow `0.0.0.0/0` (Render free tier has no fixed IP).
4. Connect -> Drivers -> copy the `mongodb+srv://...` connection string
   (put your password in it).

### 2. Generate the server RSA key (once, on your computer)
```bash
pip install cryptography
python generate_key.py
```
Copy the single-line output. **Back it up** — if it is lost, stored images can
never be decrypted. Render's disk is wiped on each deploy, so the key must live
in an environment variable, not a file.

### 3. Push to GitHub
```bash
git init && git add . && git commit -m "SecureImage"
# create an empty repo on GitHub, then:
git remote add origin <your-repo-url> && git push -u origin main
```

### 4. Create the service on Render
Dashboard -> New -> **Blueprint** -> pick the repo (uses `render.yaml`), or
New -> Web Service with:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 2 --timeout 120 --bind 0.0.0.0:$PORT`
- Health check path: `/healthz`

Environment variables:
| Name | Value |
|---|---|
| `MONGO_URI` | your Atlas connection string |
| `SERVER_PRIVATE_KEY_PEM` | output of `generate_key.py` |
| `SECRET_KEY` | long random string (Blueprint generates it) |
| `PYTHON_VERSION` | `3.12.8` |

Deploy, then open your `.onrender.com` URL.

## Run locally
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export MONGO_URI="mongodb://localhost:27017"
export SECRET_KEY="anything-long"
python app.py        # http://127.0.0.1:5000
```
Locally the RSA key is created automatically as `server_private.pem`
(git-ignored).

## Routes
`/` landing · `/signup` · `/login` · `/logout` · `/dashboard` (login) ·
`/encrypt` (login, POST) · `/decrypt` (public) · `/download/<id>` (owner) ·
`/download/share/<key>` (public) · `/healthz`

## Notes
- Free Render services sleep after inactivity; the first request can take ~30s.
- Wrong-key attempts are limited to 10 per 5 minutes per IP (in memory, per
  worker). Use Redis/Mongo-backed limiting if you scale out.
- Upload limit is 10 MB (`MAX_UPLOAD_MB` to change). Images are stored in
  MongoDB, so mind Atlas free-tier storage (512 MB).
- Anyone holding a share key can open the image — treat it like a password.
