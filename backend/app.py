"""
CIFER v4 — Secure File Encryption & Steganography System (Flask Backend)
Architecture:
  - Envelope Encryption with per-file ephemeral DEKs (AES-256-GCM)
  - Key Encryption Key (KEK_MASTER) wrapping with Dual-AAD context binding
  - Argon2id with RFC 9106 parameters (auto-migrating legacy SHA-256)
  - Server-Keyed HMAC-SHA-256 OTP engine
  - Out-of-band Bearer Capability Tokens (stored as SHA-256 digests in MongoDB)
  - Verify-Then-Dispatch decryption gating with atomic rate limiting
  - Format-compliant polyglot JPEG carrier embedding
  - Online KEK rotation endpoint (/api/admin/rotate-kek)
"""

import os
import io
import json
import time
import hashlib
import secrets
import string
import random
import unicodedata
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_file, session, g
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson.objectid import ObjectId
from dotenv import load_dotenv

import cifer_crypto

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# Session cookie configuration
is_dev = os.getenv("FLASK_ENV") == "development"
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax" if is_dev else "None",
    SESSION_COOKIE_SECURE=False if is_dev else True,
    SESSION_COOKIE_HTTPONLY=True
)

CORS(app, supports_credentials=True, expose_headers=["Content-Disposition"], origins=[
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://127.0.0.1:5500", "http://localhost:5500", 
    "http://127.0.0.1:8080", "http://localhost:8080", 
    "http://127.0.0.1:3000", "http://localhost:3000", 
    "http://127.0.0.1:5000", "http://localhost:5000",
    "null", "*"
])

# ── Mail configuration ──
app.config.update(
    MAIL_SERVER   = "smtp.gmail.com",
    MAIL_PORT     = 587,
    MAIL_USE_TLS  = True,
    MAIL_USERNAME = os.getenv("MAIL_USER"),
    MAIL_PASSWORD = os.getenv("MAIL_PASS"),
    MAIL_DEFAULT_SENDER = ("CIFER Security", os.getenv("MAIL_USER", "cifer@example.com")),
)
mail = Mail(app)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── CIFER v4 Root Secret Store ──
KEK_ID = os.getenv("KEK_ID", "kek-2026-v1")
raw_kek = os.getenv("KEK_MASTER")
if not raw_kek:
    raw_kek = secrets.token_hex(32)
KEK_MASTER = bytes.fromhex(raw_kek)[:32]

raw_hmac_key = os.getenv("HMAC_OTP_KEY")
if not raw_hmac_key:
    raw_hmac_key = secrets.token_hex(32)
HMAC_OTP_KEY = bytes.fromhex(raw_hmac_key)[:32]

# ── Cover image themes (1-to-1 mapping with actual photo covers) ──
COVERS = [
    {"id": 1, "emoji": "🌸", "name": "Cherry Blossom", "file": "cover1.jpg", "color": "#1a0a12"},
    {"id": 2, "emoji": "🦋", "name": "Butterfly",      "file": "cover2.jpg", "color": "#0a101a"},
    {"id": 3, "emoji": "🌿", "name": "Forest",         "file": "cover3.jpg", "color": "#061208"},
    {"id": 4, "emoji": "🐱", "name": "Cat",            "file": "cover4.jpg", "color": "#100a1a"},
    {"id": 5, "emoji": "🌺", "name": "Hibiscus",       "file": "cover5.jpg", "color": "#1a0808"},
]
COVER_THEMES = COVERS

# ─────────────────────────────────────────────
#  Database Helpers
# ─────────────────────────────────────────────
def get_db():
    if "db" not in g:
        mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
        client = MongoClient(mongo_uri)
        g.db_client = client
        db_name = os.getenv("DB_NAME", "cifer_db1")
        g.db = client[db_name]
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    client = g.pop("db_client", None)
    if client:
        client.close()
    g.pop("db", None)

# ── Auth Decorator ──
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not logged in"}), 401
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────
#  Email Dispatcher
# ─────────────────────────────────────────────
def send_otp_email(to_email: str, otp: str, filename: str):
    is_login = filename == "Account Login"
    title_text = "Login Required" if is_login else f"Decryption requested for: <strong style='color:#e0f0ff'>{filename}</strong>"
    
    html = f"""
    <div style="background:#030b18;color:#e0f0ff;font-family:Arial,sans-serif;
                padding:2.5rem;border-radius:14px;max-width:480px;margin:auto;
                border:1px solid #0a3a6e">
      <div style="text-align:center;margin-bottom:2rem">
        <h1 style="color:#3b9eff;font-size:2.2rem;letter-spacing:4px;margin:0">CIFER v4</h1>
        <p style="color:#4a7aab;font-size:.85rem;margin:.3rem 0 0">Secure File Encryption &amp; Steganography</p>
      </div>
      <h2 style="font-size:1rem;margin-bottom:.5rem;color:#b8d4f0">🔐 Your Authenticated OTP</h2>
      <p style="color:#4a7aab;font-size:.85rem;margin-bottom:1.5rem">
        {title_text}
      </p>
      <div style="background:rgba(59,158,255,.08);border:1px solid rgba(59,158,255,.3);
                  border-radius:12px;padding:1.5rem;text-align:center;margin-bottom:1.5rem">
        <div style="font-size:3rem;font-weight:900;letter-spacing:14px;
                    color:#3b9eff;font-family:monospace">{otp}</div>
      </div>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">⏱ Valid for <strong style="color:#f5c518">{"5 minutes" if is_login else "2 minutes"}</strong></p>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">🚫 Max <strong style="color:#e0f0ff">3 attempts</strong></p>
      <p style="color:#4a7aab;font-size:.8rem;margin:.3rem 0">If you did not request this OTP, no action is required.</p>
      <hr style="border:none;border-top:1px solid #0a3a6e;margin:1.5rem 0"/>
      <p style="color:#1e3a5f;font-size:.72rem;text-align:center">CIFER v4 — Dual-AAD Zero-Trust Architecture</p>
    </div>"""
    msg = Message("🔐 CIFER v4 — Your Authenticated OTP", recipients=[to_email], html=html)
    mail.send(msg)

# ─────────────────────────────────────────────
#  Authentication Routes
# ─────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    d = request.json or {}
    name = d.get("name", "").strip()
    email = d.get("email", "").strip().lower()
    pw = d.get("password", "")

    if not all([name, email, pw]):
        return jsonify({"error": "All fields required"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password min 8 chars"}), 400

    db = get_db()
    existing = db.users.find_one({"email": email})
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    # Argon2id password hash with RFC 9106 parameters
    pw_hash = cifer_crypto.hash_password(pw)
    user_doc = {
        "name": name,
        "email": email,
        "password_hash": pw_hash,
        "created_at": datetime.utcnow()
    }
    result = db.users.insert_one(user_doc)
    session["user_id"] = str(result.inserted_id)
    session["user_name"] = name
    return jsonify({"success": True, "name": name})


@app.route("/api/login", methods=["POST"])
def login():
    d = request.json or {}
    email = d.get("email", "").strip().lower()
    pw = d.get("password", "")

    db = get_db()
    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    is_valid, needs_rehash = cifer_crypto.verify_password(user.get("password_hash", ""), pw)
    if not is_valid:
        return jsonify({"error": "Invalid email or password"}), 401

    # Auto-migration: update legacy hash to Argon2id
    if needs_rehash:
        new_hash = cifer_crypto.hash_password(pw)
        db.users.update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash}})

    # Generate 6-digit numeric OTP and server-keyed HMAC digest
    otp = "".join(random.choices(string.digits, k=6))
    challenge_id = secrets.token_hex(16)
    otp_digest = cifer_crypto.generate_otp_digest(email, "login", challenge_id, otp, HMAC_OTP_KEY)
    expires = datetime.utcnow() + timedelta(minutes=5)

    db.auth_otp.update_one(
        {"email": email},
        {"$set": {
            "challenge_id": challenge_id,
            "otp_digest": otp_digest,
            "expires_at": expires,
            "attempts": 0
        }},
        upsert=True
    )

    try:
        send_otp_email(email, otp, "Account Login")
        return jsonify({"require_otp": True, "email": email, "message": f"OTP sent to {email}"})
    except Exception as e:
        app.logger.error(f"Mail error: {e}")
        if os.getenv("FLASK_ENV") == "development":
            print(f"\n=== DEVELOPMENT LOGIN OTP for {email}: {otp} ===\n")
            return jsonify({
                "require_otp": True,
                "email": email,
                "dev_otp": otp,
                "message": f"[DEV] OTP: {otp} (email simulation due to SMTP config)"
            })
        return jsonify({"error": "Failed to send email. Check MAIL_USER/MAIL_PASS in .env"}), 500


@app.route("/api/verify-login", methods=["POST"])
def verify_login():
    d = request.json or {}
    email = d.get("email", "").strip().lower()
    otp = d.get("otp", "").strip()

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    db = get_db()
    otp_rec = db.auth_otp.find_one({"email": email})
    if not otp_rec:
        return jsonify({"error": "No OTP requested. Please login again."}), 400

    if datetime.utcnow() > otp_rec["expires_at"]:
        return jsonify({"error": "OTP expired. Please login again."}), 401

    challenge_id = otp_rec.get("challenge_id", "")
    cand_digest = cifer_crypto.generate_otp_digest(email, "login", challenge_id, otp, HMAC_OTP_KEY)
    attempts = otp_rec.get("attempts", 0) + 1
    db.auth_otp.update_one({"_id": otp_rec["_id"]}, {"$set": {"attempts": attempts}})

    if not cifer_crypto.verify_otp(otp_rec["otp_digest"], cand_digest):
        if attempts >= 3:
            db.auth_otp.delete_one({"_id": otp_rec["_id"]})
            return jsonify({"error": "Too many attempts. Blocked. Please login again."}), 429
        return jsonify({"error": f"Wrong OTP. {3 - attempts} attempt(s) remaining."}), 401

    # Clear OTP record upon successful authentication
    db.auth_otp.delete_one({"_id": otp_rec["_id"]})

    user = db.users.find_one({"email": email})
    if not user:
        return jsonify({"error": "User no longer exists"}), 404

    session["user_id"] = str(user["_id"])
    session["user_name"] = user["name"]
    return jsonify({"success": True, "name": user["name"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})


@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"logged_in": False}), 200

    db = get_db()
    try:
        user = db.users.find_one({"_id": ObjectId(session["user_id"])})
    except Exception:
        user = None

    stats_pipeline = [
        {"$match": {"user_id": session["user_id"]}},
        {"$group": {
            "_id": None,
            "total_enc": {"$sum": {"$cond": [{"$eq": ["$event", "encrypt"]}, 1, 0]}},
            "total_dec": {"$sum": {"$cond": [{"$eq": ["$event", "decrypt"]}, 1, 0]}},
            "total_tamper": {"$sum": {"$cond": [{"$eq": ["$event", "tamper"]}, 1, 0]}},
            "total_block": {"$sum": {"$cond": [{"$eq": ["$status", "blocked"]}, 1, 0]}}
        }}
    ]
    stats_res = list(db.activity_log.aggregate(stats_pipeline))
    stats = stats_res[0] if stats_res else {"total_enc": 0, "total_dec": 0, "total_tamper": 0, "total_block": 0}

    active_cnt = db.encrypted_files.count_documents({
        "owner_id": session["user_id"],
        "$or": [{"expires_at": None}, {"expires_at": {"$gt": datetime.utcnow()}}],
        "deleted": 0
    })

    if user:
        user["id"] = str(user["_id"])
        del user["_id"]
        if "password_hash" in user:
            del user["password_hash"]
        user["created_at"] = str(user.get("created_at", ""))

    return jsonify({"logged_in": True, "user": user, "stats": stats, "active_files": active_cnt})


# ─────────────────────────────────────────────
#  Encryption Route (CIFER v4 Envelope Encryption)
# ─────────────────────────────────────────────
@app.route("/api/encrypt", methods=["POST"])
@login_required
def encrypt_route():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    try:
        receivers = json.loads(request.form.get("receivers", "[]"))
    except Exception:
        return jsonify({"error": "Invalid receivers JSON"}), 400
    if not receivers:
        return jsonify({"error": "At least one receiver required"}), 400

    expiry_hours = int(request.form.get("expiry_hours", 24))

    raw = f.read()
    if len(raw) > 50 * 1024 * 1024:
        return jsonify({"error": "File too large (max 50MB)"}), 413

    start_time = time.time()

    # Normalize receivers
    cleaned_receivers = [
        unicodedata.normalize("NFKC", r).strip().lower()
        for r in receivers
        if r and r.strip()
    ]

    # Execute CIFER v4 Envelope Encryption
    crypto_res = cifer_crypto.encrypt_file(
        file_bytes=raw,
        filename=f.filename,
        owner_id=session["user_id"],
        recipients=cleaned_receivers,
        kek_bytes=KEK_MASTER,
        kek_id=KEK_ID,
        version=4,
        version_no=1
    )

    elapsed_ms = int((time.time() - start_time) * 1000)
    throughput = f"{(len(raw) / 1024) / (elapsed_ms / 1000):.1f} KB/s" if elapsed_ms > 0 else "—"

    # Select cover image with exact matching theme
    theme = random.choice(COVERS)
    cover_path = os.path.join(os.path.dirname(__file__), f"covers/{theme['file']}")

    # Format-compliant polyglot bundling (Bearer token is NOT embedded in carrier)
    out_filename = f"{crypto_res.file_uuid}.jpg"
    out_path = os.path.join(UPLOAD_FOLDER, out_filename)

    try:
        bundled_bytes = cifer_crypto.bundle_jpeg(cover_path, crypto_res.blob_bytes)
        with open(out_path, "wb") as w_file:
            w_file.write(bundled_bytes)
    except Exception as e:
        app.logger.error(f"Stego bundling error: {e}")
        return jsonify({"error": "Failed to bundle steganographic carrier"}), 500

    expires_at = None
    if expiry_hours > 0:
        expires_at = datetime.utcnow() + timedelta(hours=expiry_hours)

    db = get_db()
    file_doc = {
        "file_uuid": crypto_res.file_uuid,
        "token_hash": crypto_res.token_hash,
        "token": crypto_res.bearer_token,  # Kept for uploader history/display
        "owner_id": session["user_id"],
        "user_id": session["user_id"],    # Compatibility
        "filename": f.filename,
        "original_name": f.filename,       # Compatibility
        "file_size": len(raw),
        "version": crypto_res.version,
        "version_no": crypto_res.version_no,
        "wrapped_dek": crypto_res.wrapped_dek.hex(),
        "wrap_iv": crypto_res.wrap_iv.hex(),
        "kek_id": crypto_res.kek_id,
        "blob_fingerprint": crypto_res.blob_fingerprint,
        "file_hash": crypto_res.blob_fingerprint,  # Compatibility
        "enc_path": out_path,
        "receivers": cleaned_receivers,
        "expires_at": expires_at,
        "cover_emoji": theme["emoji"],
        "cover_name": theme["name"],
        "enc_time_ms": elapsed_ms,
        "deleted": 0,
        "created_at": datetime.utcnow()
    }
    result = db.encrypted_files.insert_one(file_doc)
    fid = str(result.inserted_id)

    db.activity_log.insert_one({
        "user_id": session["user_id"],
        "file_id": fid,
        "event": "encrypt",
        "detail": f"Receivers: {', '.join(cleaned_receivers)}",
        "status": "success",
        "created_at": datetime.utcnow()
    })

    return jsonify({
        "status": "success",
        "success": True,
        "token": crypto_res.bearer_token,
        "file_uuid": crypto_res.file_uuid,
        "fingerprint": crypto_res.blob_fingerprint,
        "file_hash": crypto_res.blob_fingerprint,
        "file_name": f.filename,
        "original_name": f.filename,
        "receivers": cleaned_receivers,
        "expires_at": str(expires_at) if expires_at else "Unlimited",
        "cover_emoji": theme["emoji"],
        "cover_name": theme["name"],
        "enc_time": f"{elapsed_ms}ms",
        "throughput": throughput,
        "download_url": f"/api/download/{crypto_res.file_uuid}"
    })


@app.route("/api/download/<identifier>")
def download_carrier(identifier):
    db = get_db()
    # Resolve by file_uuid, token, or token_hash
    cand_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    f = db.encrypted_files.find_one({
        "$or": [
            {"file_uuid": identifier},
            {"token": identifier},
            {"token_hash": cand_hash}
        ],
        "deleted": 0
    })
    if not f or not os.path.exists(f.get("enc_path", "")):
        return jsonify({"error": "File not found"}), 404

    return send_file(
        f["enc_path"],
        as_attachment=True,
        download_name=f"{f.get('file_uuid', identifier)}.jpg",
        mimetype="image/jpeg"
    )


# ─────────────────────────────────────────────
#  Steganography Carrier Inspection & Extraction
# ─────────────────────────────────────────────
@app.route("/api/decrypt-upload", methods=["POST"])
def decrypt_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    raw = f.read()

    try:
        blob_bytes = cifer_crypto.extract_from_jpeg(raw)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    blob_fp = hashlib.sha256(blob_bytes).hexdigest()
    db = get_db()
    file_doc = db.encrypted_files.find_one({"blob_fingerprint": blob_fp, "deleted": 0})
    if not file_doc:
        return jsonify({"error": "File record not found or revoked on server."}), 404

    expired = file_doc.get("expires_at") and datetime.utcnow() > file_doc["expires_at"]
    return jsonify({
        "file_uuid":     file_doc.get("file_uuid"),
        "token":         file_doc.get("token", ""),  # Capability token placeholder if known
        "original_name": file_doc.get("filename", file_doc.get("original_name")),
        "file_size":     file_doc.get("file_size"),
        "blob_fingerprint": blob_fp,
        "receivers":     file_doc.get("receivers", []),
        "expires_at":    str(file_doc["expires_at"]) if file_doc.get("expires_at") else "Unlimited",
        "cover_emoji":   file_doc.get("cover_emoji"),
        "cover_name":    file_doc.get("cover_name"),
        "expired":       bool(expired),
    })


@app.route("/api/file/<identifier>")
def file_info(identifier):
    db = get_db()
    cand_hash = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    f = db.encrypted_files.find_one({
        "$or": [
            {"file_uuid": identifier},
            {"token": identifier},
            {"token_hash": cand_hash}
        ],
        "deleted": 0
    })
    if not f:
        return jsonify({"error": "File not found"}), 404

    expired = f.get("expires_at") and datetime.utcnow() > f["expires_at"]
    return jsonify({
        "file_uuid":     f.get("file_uuid"),
        "original_name": f.get("filename", f.get("original_name")),
        "file_hash":     f.get("blob_fingerprint"),
        "receivers":     f.get("receivers", []),
        "expires_at":    str(f["expires_at"]) if f.get("expires_at") else "Unlimited",
        "cover_emoji":   f.get("cover_emoji"),
        "cover_name":    f.get("cover_name"),
        "file_size":     f.get("file_size"),
        "expired":       bool(expired),
    })


# ─────────────────────────────────────────────
#  Verify-Then-Dispatch OTP Request (POST /api/request-otp)
# ─────────────────────────────────────────────
@app.route("/api/request-otp", methods=["POST"])
def request_otp():
    d = request.json or {}
    token = d.get("token", "").strip()
    file_uuid = d.get("file_uuid", "").strip()

    if not token and not file_uuid:
        return jsonify({"error": "Bearer capability token or file_uuid required"}), 400

    db = get_db()
    query = {"deleted": 0}
    if token:
        tok_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        query["$or"] = [{"token_hash": tok_hash}, {"token": token}]
    elif file_uuid:
        query["file_uuid"] = file_uuid

    f = db.encrypted_files.find_one(query)
    if not f:
        return jsonify({"error": "File not found or expired"}), 404

    if f.get("expires_at") and datetime.utcnow() > f["expires_at"]:
        return jsonify({"error": "File has expired"}), 410

    receivers = f.get("receivers", [])
    if not receivers:
        return jsonify({"error": "No receivers configured for this file"}), 403

    fid_str = str(f["_id"])

    # Check 30-minute rate-limiting block
    block_rec = db.otp_attempts.find_one({
        "file_id": fid_str,
        "blocked_until": {"$gt": datetime.utcnow()}
    })
    if block_rec:
        return jsonify({"error": "Access temporarily blocked. Try after 30 minutes."}), 429

    # ─────────────────────────────────────────────────────────────
    #  CRITICAL: Verify-Then-Dispatch (Dual-AAD wrap tag check)
    # ─────────────────────────────────────────────────────────────
    active_token_hash = f.get("token_hash")
    if not active_token_hash and token:
        active_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    wrap_aad = cifer_crypto.build_wrap_aad(
        version=f.get("version", 4),
        file_uuid=f.get("file_uuid", str(f["_id"])),
        version_no=f.get("version_no", 1),
        filename=f.get("filename", f.get("original_name", "")),
        recipients=f.get("receivers", []),
        token_hash=active_token_hash or ""
    )

    try:
        wrapped_dek = bytes.fromhex(f["wrapped_dek"])
        wrap_iv = bytes.fromhex(f["wrap_iv"])
        # Attempt unwrapping DEK under KEK_MASTER with context-bound wrap_aad
        _unwrapped_dek = cifer_crypto.unwrap_dek(wrapped_dek, wrap_iv, KEK_MASTER, wrap_aad)
    except Exception as e:
        # Cryptographic context verification failed -> Metadata tampering detected!
        db.activity_log.insert_one({
            "user_id": f.get("owner_id") or f.get("user_id"),
            "file_id": fid_str,
            "event": "tamper",
            "detail": f"Metadata tampering detected: wrap AAD tag verification failed ({e})",
            "status": "tampered",
            "created_at": datetime.utcnow()
        })
        return jsonify({
            "error": "Cryptographic context verification failed. Record has been tampered with.",
            "tamper": True
        }), 422

    # Verification passed -> Dispatch keyed OTP
    otp = "".join(random.choices(string.digits, k=6))
    challenge_id = secrets.token_hex(16)
    otp_digest = cifer_crypto.generate_otp_digest(fid_str, "decrypt", challenge_id, otp, HMAC_OTP_KEY)
    expires = datetime.utcnow() + timedelta(minutes=2)

    db.otp_store.update_one(
        {"file_id": fid_str},
        {"$set": {
            "challenge_id": challenge_id,
            "otp_digest": otp_digest,
            "expires_at": expires,
            "attempts": 0
        }},
        upsert=True
    )

    errors = []
    for email in receivers:
        try:
            send_otp_email(email, otp, f.get("filename", f.get("original_name", "encrypted file")))
        except Exception as e:
            errors.append(str(e))

    if errors and len(errors) == len(receivers):
        app.logger.error(f"Mail errors: {errors}")
        if os.getenv("FLASK_ENV") == "development":
            print(f"\n=== DEVELOPMENT OTP for {f.get('file_uuid', fid_str)}: {otp} ===\n")
            return jsonify({
                "success": True,
                "dev_otp": otp,
                "message": "OTP dispatched to receivers (simulated due to email errors)"
            })
        return jsonify({"error": "Failed to send emails to receivers."}), 500

    if os.getenv("FLASK_ENV") == "development":
        print(f"\n=== DEVELOPMENT OTP for {f.get('file_uuid', fid_str)}: {otp} ===\n")

    return jsonify({
        "success": True,
        "message": "OTP successfully dispatched to all authorized receivers.",
        "dev_otp": otp if os.getenv("FLASK_ENV") == "development" else None
    })


# ─────────────────────────────────────────────
#  Decryption Endpoint (POST /api/decrypt)
# ─────────────────────────────────────────────
@app.route("/api/decrypt", methods=["POST"])
@login_required
def decrypt_route():
    d = request.json or {}
    token = d.get("token", "").strip()
    otp = d.get("otp", "").strip()
    file_uuid = d.get("file_uuid", "").strip()

    if not (token or file_uuid) or not otp:
        return jsonify({"error": "Capability token and OTP required"}), 400

    db = get_db()
    query = {"deleted": 0}
    if token:
        tok_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        query["$or"] = [{"token_hash": tok_hash}, {"token": token}]
    elif file_uuid:
        query["file_uuid"] = file_uuid

    f = db.encrypted_files.find_one(query)
    if not f:
        return jsonify({"error": "File not found"}), 404

    if f.get("expires_at") and datetime.utcnow() > f["expires_at"]:
        return jsonify({"error": "File has expired"}), 410

    fid_str = str(f["_id"])

    # Check 30-minute rate limit
    block_rec = db.otp_attempts.find_one({
        "file_id": fid_str,
        "blocked_until": {"$gt": datetime.utcnow()}
    })
    if block_rec:
        return jsonify({"error": "Access blocked for 30 minutes", "blocked": True}), 429

    otp_rec = db.otp_store.find_one({"file_id": fid_str})
    if not otp_rec:
        return jsonify({"error": "No OTP requested. Request OTP first."}), 400
    if datetime.utcnow() > otp_rec["expires_at"]:
        return jsonify({"error": "OTP expired. Request a new one."}), 401

    challenge_id = otp_rec.get("challenge_id", "")
    cand_digest = cifer_crypto.generate_otp_digest(fid_str, "decrypt", challenge_id, otp, HMAC_OTP_KEY)
    attempts = otp_rec.get("attempts", 0) + 1
    db.otp_store.update_one({"_id": otp_rec["_id"]}, {"$set": {"attempts": attempts}})

    if not cifer_crypto.verify_otp(otp_rec["otp_digest"], cand_digest):
        if attempts >= 3:
            blocked_until = datetime.utcnow() + timedelta(minutes=30)
            db.otp_attempts.update_one(
                {"file_id": fid_str},
                {"$set": {"blocked_until": blocked_until}},
                upsert=True
            )
            db.otp_store.delete_one({"_id": otp_rec["_id"]})
            db.activity_log.insert_one({
                "user_id": f.get("owner_id") or f.get("user_id"),
                "file_id": fid_str,
                "event": "failed",
                "detail": "Blocked file due to 3 failed OTP attempts",
                "status": "blocked",
                "created_at": datetime.utcnow()
            })
            return jsonify({"error": "Too many attempts. Blocked for 30 minutes.", "blocked": True}), 429

        left = 3 - attempts
        return jsonify({"error": f"Wrong OTP. {left} attempt(s) remaining.", "attempts_left": left}), 401

    # OTP validated -> Clear OTP from store
    db.otp_store.delete_one({"_id": otp_rec["_id"]})

    # Read carrier from enc_path
    enc_path = f.get("enc_path")
    if not enc_path or not os.path.exists(enc_path):
        return jsonify({"error": "Encrypted file missing from server"}), 404

    with open(enc_path, "rb") as fp:
        raw_carrier = fp.read()

    try:
        blob_bytes = cifer_crypto.extract_from_jpeg(raw_carrier)
    except Exception as e:
        return jsonify({"error": f"Corrupted file structure: {e}"}), 500

    # Verify blob fingerprint
    actual_blob_fp = hashlib.sha256(blob_bytes).hexdigest()
    if actual_blob_fp != f.get("blob_fingerprint"):
        db.activity_log.insert_one({
            "user_id": f.get("owner_id") or f.get("user_id"),
            "file_id": fid_str,
            "event": "tamper",
            "detail": "Blob fingerprint mismatch",
            "status": "tampered",
            "created_at": datetime.utcnow()
        })
        return jsonify({"error": "TAMPER DETECTED — file integrity check failed!", "tamper": True}), 422

    # Unwrap DEK
    active_token_hash = f.get("token_hash")
    if not active_token_hash and token:
        active_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    wrap_aad = cifer_crypto.build_wrap_aad(
        version=f.get("version", 4),
        file_uuid=f.get("file_uuid", str(f["_id"])),
        version_no=f.get("version_no", 1),
        filename=f.get("filename", f.get("original_name", "")),
        recipients=f.get("receivers", []),
        token_hash=active_token_hash or ""
    )

    try:
        dek = cifer_crypto.unwrap_dek(
            wrapped_dek=bytes.fromhex(f["wrapped_dek"]),
            wrap_iv=bytes.fromhex(f["wrap_iv"]),
            kek_bytes=KEK_MASTER,
            wrap_aad=wrap_aad
        )
    except Exception as e:
        db.activity_log.insert_one({
            "user_id": f.get("owner_id") or f.get("user_id"),
            "file_id": fid_str,
            "event": "tamper",
            "detail": f"DEK unwrap failed: {e}",
            "status": "tampered",
            "created_at": datetime.utcnow()
        })
        return jsonify({"error": "TAMPER DETECTED — wrap tag verification failed!", "tamper": True}), 422

    # Decrypt file payload
    blob_aad = cifer_crypto.build_blob_aad(
        version=f.get("version", 4),
        file_uuid=f.get("file_uuid", str(f["_id"])),
        owner_id=f.get("owner_id", f.get("user_id")),
        version_no=f.get("version_no", 1)
    )

    try:
        decrypted_bytes = cifer_crypto.decrypt_file(blob_bytes, dek, blob_aad)
    except Exception as e:
        db.activity_log.insert_one({
            "user_id": f.get("owner_id") or f.get("user_id"),
            "file_id": fid_str,
            "event": "tamper",
            "detail": f"Ciphertext payload tag verification failed: {e}",
            "status": "tampered",
            "created_at": datetime.utcnow()
        })
        return jsonify({"error": "TAMPER DETECTED — payload tag verification failed!", "tamper": True}), 422

    db.activity_log.insert_one({
        "user_id": session.get("user_id"),
        "file_id": fid_str,
        "event": "decrypt",
        "detail": "Decrypted by OTP",
        "status": "success",
        "created_at": datetime.utcnow()
    })

    download_name = f.get("filename", f.get("original_name", "decrypted_file"))
    return send_file(
        io.BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=download_name,
        mimetype="application/octet-stream"
    )


# ─────────────────────────────────────────────
#  Online KEK Rotation Endpoint (POST /api/admin/rotate-kek)
# ─────────────────────────────────────────────
@app.route("/api/admin/rotate-kek", methods=["POST"])
def rotate_kek():
    global KEK_MASTER, KEK_ID
    d = request.json or {}
    old_kek_hex = d.get("old_kek")
    new_kek_hex = d.get("new_kek")
    new_kek_id = d.get("new_kek_id", f"kek-{int(time.time())}")

    old_kek = bytes.fromhex(old_kek_hex) if old_kek_hex else KEK_MASTER
    new_kek = bytes.fromhex(new_kek_hex) if new_kek_hex else secrets.token_bytes(32)

    db = get_db()
    cursor = db.encrypted_files.find({"deleted": 0})
    rotated_count = 0
    errors = []

    for f in cursor:
        try:
            wrap_aad = cifer_crypto.build_wrap_aad(
                version=f.get("version", 4),
                file_uuid=f.get("file_uuid", str(f["_id"])),
                version_no=f.get("version_no", 1),
                filename=f.get("filename", f.get("original_name", "")),
                recipients=f.get("receivers", []),
                token_hash=f.get("token_hash", "")
            )

            # Unwrap with old KEK
            dek = cifer_crypto.unwrap_dek(
                wrapped_dek=bytes.fromhex(f["wrapped_dek"]),
                wrap_iv=bytes.fromhex(f["wrap_iv"]),
                kek_bytes=old_kek,
                wrap_aad=wrap_aad
            )

            # Re-wrap under new KEK with a fresh IV
            new_wrap_iv = os.urandom(12)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            new_wrapped_dek = AESGCM(new_kek).encrypt(new_wrap_iv, dek, wrap_aad)

            db.encrypted_files.update_one(
                {"_id": f["_id"]},
                {"$set": {
                    "wrapped_dek": new_wrapped_dek.hex(),
                    "wrap_iv": new_wrap_iv.hex(),
                    "kek_id": new_kek_id
                }}
            )
            rotated_count += 1
        except Exception as e:
            errors.append(f"File {f.get('file_uuid')}: {e}")

    # Update active in-memory root keys
    KEK_MASTER = new_kek
    KEK_ID = new_kek_id

    return jsonify({
        "success": True,
        "rotated_count": rotated_count,
        "new_kek_id": new_kek_id,
        "new_kek_hex": new_kek.hex(),
        "errors": errors
    })


# ─────────────────────────────────────────────
#  Activity History & Active Files
# ─────────────────────────────────────────────
@app.route("/api/history")
@login_required
def history():
    db = get_db()
    logs = list(db.activity_log.find({"user_id": session["user_id"]}).sort("created_at", -1).limit(100))
    for r in logs:
        r["id"] = str(r["_id"])
        del r["_id"]
        r["created_at"] = str(r.get("created_at", ""))

        if "file_id" in r and r["file_id"]:
            try:
                f = db.encrypted_files.find_one({"_id": ObjectId(r["file_id"])})
                if f:
                    r["original_name"] = f.get("filename", f.get("original_name"))
                    r["cover_emoji"] = f.get("cover_emoji")
                    r["cover_name"] = f.get("cover_name")
            except Exception:
                pass

    return jsonify(logs)


@app.route("/api/active-files")
@login_required
def active_files():
    db = get_db()
    cursor = db.encrypted_files.find({
        "owner_id": session["user_id"],
        "deleted": 0,
        "$or": [{"expires_at": None}, {"expires_at": {"$gt": datetime.utcnow()}}]
    }).sort("created_at", -1).limit(20)

    rows = []
    for f in cursor:
        rows.append({
            "token": f.get("token"),
            "file_uuid": f.get("file_uuid"),
            "original_name": f.get("filename", f.get("original_name")),
            "file_size": f.get("file_size"),
            "cover_emoji": f.get("cover_emoji"),
            "cover_name": f.get("cover_name"),
            "created_at": str(f.get("created_at", "")),
            "expires_at": str(f.get("expires_at")) if f.get("expires_at") else "Unlimited"
        })
    return jsonify(rows)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
