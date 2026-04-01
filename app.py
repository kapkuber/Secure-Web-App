import os
import uuid
import hashlib
import re
import subprocess
from pathlib import Path
from datetime import datetime

import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort, Response, g
)

from config import Config
from security import (
    EncryptedStorage, SecurityLogger, SessionManager, RateLimiter,
    validate_username, validate_password, sanitize_input,
    safe_filename, safe_file_path, validate_file_upload,
    require_auth, require_role,
)

app = Flask(__name__)
app.config.from_object(Config)

BASE_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Instantiate security singletons
# ---------------------------------------------------------------------------

storage = EncryptedStorage(str(BASE_DIR / "secret.key"))

security_logger = SecurityLogger(
    security_log_path=str(BASE_DIR / app.config["LOG_FOLDER"] / "security.log"),
    access_log_path=str(BASE_DIR / app.config["LOG_FOLDER"] / "access.log"),
)

session_manager = SessionManager(
    sessions_file=str(BASE_DIR / app.config["DATA_FOLDER"] / "sessions.json"),
    session_timeout=app.config["SESSION_TIMEOUT"],
    storage=storage,
    logger=security_logger,
)

rate_limiter = RateLimiter(
    max_attempts=app.config["RATE_LIMIT_ATTEMPTS"],
    window_seconds=app.config["RATE_LIMIT_WINDOW"],
)

# Attach logger to app so require_role decorator can access it
app.security_logger = security_logger

# ---------------------------------------------------------------------------
# Data-file path helpers
# ---------------------------------------------------------------------------

def _data(filename: str) -> str:
    return str(BASE_DIR / app.config["DATA_FOLDER"] / filename)

def load_users():     return storage.load_json(_data("users.json"), default={})
def save_users(d):    storage.save_json(_data("users.json"), d)
def load_docs():      return storage.load_json(_data("documents.json"), default={})
def save_docs(d):     storage.save_json(_data("documents.json"), d)
def load_shares():    return storage.load_json(_data("shares.json"), default={})
def save_shares(d):   storage.save_json(_data("shares.json"), d)
def load_audit():     return storage.load_json(_data("audit.json"), default=[])
def save_audit(d):    storage.save_json(_data("audit.json"), d)

def _upload_dir() -> Path:
    return BASE_DIR / app.config["UPLOAD_FOLDER"]

# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

def audit(event: str, detail: str = "") -> None:
    entries = load_audit()
    entries.append({
        "timestamp": datetime.utcnow().isoformat(),
        "event":     event,
        "user":      g.get("user_id", "anonymous"),
        "ip":        g.get("ip", ""),
        "detail":    detail,
    })
    save_audit(entries)

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode(), bcrypt.gensalt(app.config["BCRYPT_ROUNDS"])
    ).decode()

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ---------------------------------------------------------------------------
# Access control helpers
# ---------------------------------------------------------------------------

def owns_document(user_id: str, doc_id: str) -> bool:
    doc = load_docs().get(doc_id)
    return doc is not None and doc["owner"] == user_id

def can_access_document(user_id: str, doc_id: str) -> bool:
    if owns_document(user_id, doc_id):
        return True
    for share in load_shares().values():
        if share["doc_id"] == doc_id and share["shared_with"] == user_id:
            exp = share.get("expires")
            if exp and datetime.utcnow().isoformat() > exp:
                continue
            return True
    return False

# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _cookie_kwargs() -> dict:
    """Return kwargs for set_cookie; disables Secure in non-production."""
    return {
        "httponly": True,
        "secure":   app.config.get("ENV", "production") == "production"
                    and not app.config.get("TESTING", False),
        "samesite": "Lax",
        "max_age":  app.config["SESSION_TIMEOUT"],
    }

# ---------------------------------------------------------------------------
# Context processor — exposes current_user to all templates
# ---------------------------------------------------------------------------

@app.context_processor
def inject_user():
    return {
        "current_user":    g.get("user"),
        "current_user_id": g.get("user_id"),
    }

# ---------------------------------------------------------------------------
# @app.before_request
# ---------------------------------------------------------------------------

@app.before_request
def before_request() -> None:
    session_manager.cleanup_expired()

    g.ip  = request.remote_addr or ""
    g.ua  = request.headers.get("User-Agent", "")
    g.user_id = None
    g.user    = None

    token = request.cookies.get("session_token")
    sess  = session_manager.validate_session(token)
    if sess:
        users = load_users()
        user  = users.get(sess["user_id"])
        if user:
            g.user_id = sess["user_id"]
            g.user    = user

# ---------------------------------------------------------------------------
# @app.after_request — Security headers
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = (
        "geolocation=(), microphone=(), camera=()"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # No caching on authenticated responses
    if g.get("user_id") and not request.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-store"
    return response

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(429)
def rate_limited(e):
    return render_template("429.html"), 429

@app.errorhandler(500)
def internal_error(e):
    # Never expose stack traces
    return render_template("500.html"), 500

# ---------------------------------------------------------------------------
# Routes — Authentication
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user_id else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", "").strip())
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not validate_username(username):
            security_logger.log_event(
                SecurityLogger.REGISTER_FAILED, None, g.ip, g.ua,
                details={"reason": "invalid username", "username": username},
                severity="WARNING",
            )
            flash("Username must be 3–20 alphanumeric/underscore characters.")
            return render_template("register.html")

        errors = validate_password(password)
        if errors:
            security_logger.log_event(
                SecurityLogger.REGISTER_FAILED, None, g.ip, g.ua,
                details={"reason": "weak password"},
                severity="WARNING",
            )
            for e in errors:
                flash(e)
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.")
            return render_template("register.html")

        users = load_users()
        for u in users.values():
            if u["username"].lower() == username.lower():
                flash("Username already taken.")
                return render_template("register.html")

        user_id = str(uuid.uuid4())
        users[user_id] = {
            "username":      username,
            "password":      hash_password(password),
            "role":          "user",
            "created_at":    datetime.utcnow().isoformat(),
            "failed_logins": 0,
            "locked_until":  None,
        }
        save_users(users)
        security_logger.log_event(
            SecurityLogger.REGISTER_SUCCESS, user_id, g.ip, g.ua,
            details={"username": username},
        )
        flash("Account created. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Rate limit by IP
        if not rate_limiter.is_allowed(g.ip):
            security_logger.log_event(
                SecurityLogger.RATE_LIMIT_EXCEEDED, None, g.ip, g.ua,
                details={"endpoint": "login"},
                severity="WARNING",
            )
            flash("Too many login attempts. Please wait and try again.")
            return render_template("login.html"), 429

        users   = load_users()
        user_id = next(
            (uid for uid, u in users.items()
             if u["username"].lower() == username.lower()), None
        )

        def fail(msg: str):
            if user_id:
                users[user_id]["failed_logins"] = (
                    users[user_id].get("failed_logins", 0) + 1
                )
                if users[user_id]["failed_logins"] >= app.config["MAX_FAILED_ATTEMPTS"]:
                    from datetime import timedelta
                    users[user_id]["locked_until"] = (
                        datetime.utcnow().isoformat()
                    )  # stored; lock enforced by comparing failed_logins
                    security_logger.log_event(
                        SecurityLogger.ACCOUNT_LOCKED, user_id, g.ip, g.ua,
                        details={"username": username},
                        severity="WARNING",
                    )
                save_users(users)
            security_logger.log_event(
                SecurityLogger.LOGIN_FAILED, user_id, g.ip, g.ua,
                details={"username": username},
                severity="WARNING",
            )
            flash(msg)
            return render_template("login.html")

        if not user_id:
            return fail("Invalid username or password.")

        user = users[user_id]

        # Account lockout check
        if user.get("failed_logins", 0) >= app.config["MAX_FAILED_ATTEMPTS"]:
            locked_at = user.get("locked_until")
            if locked_at:
                from datetime import timedelta
                locked_dt  = datetime.fromisoformat(locked_at)
                unlock_dt  = locked_dt + timedelta(seconds=app.config["LOCKOUT_DURATION"])
                if datetime.utcnow() < unlock_dt:
                    flash("Account temporarily locked. Try again later.")
                    return render_template("login.html")
                # Lockout expired — reset
                users[user_id]["failed_logins"] = 0
                users[user_id]["locked_until"]  = None
                save_users(users)

        if not check_password(password, user["password"]):
            return fail("Invalid username or password.")

        # Success
        users[user_id]["failed_logins"] = 0
        users[user_id]["locked_until"]  = None
        save_users(users)

        token = session_manager.create_session(user_id, g.ip, g.ua)
        security_logger.log_event(
            SecurityLogger.LOGIN_SUCCESS, user_id, g.ip, g.ua,
            details={"username": username},
        )

        resp = redirect(url_for("dashboard"))
        resp.set_cookie("session_token", token, **_cookie_kwargs())
        return resp

    return render_template("login.html")

@app.route("/logout")
@require_auth
def logout():
    token = request.cookies.get("session_token")
    session_manager.destroy_session(token)
    security_logger.log_event(
        SecurityLogger.LOGOUT, g.user_id, g.ip, g.ua,
    )
    resp = redirect(url_for("login"))
    resp.delete_cookie("session_token")
    flash("You have been logged out.")
    return resp

# ---------------------------------------------------------------------------
# Routes — Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@require_auth
def dashboard():
    docs    = load_docs()
    shares  = load_shares()
    user_id = g.user_id
    now_iso = datetime.utcnow().isoformat()

    own_docs = {k: v for k, v in docs.items() if v["owner"] == user_id}

    shared_doc_ids = {
        s["doc_id"] for s in shares.values()
        if s["shared_with"] == user_id
        and (not s.get("expires") or now_iso < s["expires"])
    }
    shared_docs = {k: v for k, v in docs.items() if k in shared_doc_ids}

    security_logger.log_event(
        SecurityLogger.DATA_ACCESS, user_id, g.ip, g.ua,
        details={"view": "dashboard"},
    )
    return render_template("dashboard.html",
                           own_docs=own_docs,
                           shared_docs=shared_docs)

# ---------------------------------------------------------------------------
# Routes — Documents
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@require_auth
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file selected.")
            return render_template("upload.html")

        f = request.files["file"]
        if not f.filename:
            flash("No file selected.")
            return render_template("upload.html")

        valid, reason = validate_file_upload(
            f,
            app.config["ALLOWED_EXTENSIONS"],
            app.config["ALLOWED_MIME_TYPES"],
            app.config["MAX_CONTENT_LENGTH"],
        )
        if not valid:
            security_logger.log_event(
                SecurityLogger.INPUT_VALIDATION_FAILURE, g.user_id, g.ip, g.ua,
                details={"filename": f.filename, "reason": reason},
                severity="WARNING",
            )
            flash(f"Upload rejected: {reason}")
            return render_template("upload.html")

        try:
            fname = safe_filename(
                f.filename, app.config["ALLOWED_EXTENSIONS"],
                logger=security_logger,
                user_id=g.user_id, ip=g.ip, ua=g.ua,
            )
        except ValueError as exc:
            flash(str(exc))
            return render_template("upload.html")

        doc_id   = str(uuid.uuid4())
        enc_name = doc_id + ".enc"
        raw_data = f.read()
        enc_data = storage.encrypt_file(raw_data)

        dest = _upload_dir() / enc_name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(enc_data)

        docs = load_docs()
        docs[doc_id] = {
            "original_name": fname,
            "enc_filename":  enc_name,
            "owner":         g.user_id,
            "uploaded_at":   datetime.utcnow().isoformat(),
            "size":          len(raw_data),
            "checksum":      hashlib.sha256(raw_data).hexdigest(),
        }
        save_docs(docs)
        security_logger.log_event(
            SecurityLogger.FILE_UPLOAD, g.user_id, g.ip, g.ua,
            details={"filename": fname, "size": len(raw_data)},
        )
        flash("File uploaded and encrypted successfully.")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")

@app.route("/document/<doc_id>")
@require_auth
def view_document(doc_id):
    if not can_access_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id},
            severity="WARNING",
        )
        abort(403)
    docs = load_docs()
    doc  = docs.get(doc_id)
    if not doc:
        abort(404)
    security_logger.log_event(
        SecurityLogger.DATA_ACCESS, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id},
    )
    return render_template("document.html", doc=doc, doc_id=doc_id)

@app.route("/document/<doc_id>/download")
@require_auth
def download_document(doc_id):
    if not can_access_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "download"},
            severity="WARNING",
        )
        abort(403)
    docs = load_docs()
    doc  = docs.get(doc_id)
    if not doc:
        abort(404)

    try:
        safe_file_path(
            doc["enc_filename"], str(_upload_dir()),
            logger=security_logger,
            user_id=g.user_id, ip=g.ip, ua=g.ua,
        )
    except ValueError:
        abort(400)

    enc_data = (_upload_dir() / doc["enc_filename"]).read_bytes()
    plain    = storage.decrypt_file(enc_data)
    security_logger.log_event(
        SecurityLogger.FILE_DOWNLOAD, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "filename": doc["original_name"]},
    )
    return Response(
        plain,
        headers={
            "Content-Disposition": f'attachment; filename="{doc["original_name"]}"',
            "Content-Type": "application/octet-stream",
        },
    )

@app.route("/document/<doc_id>/delete", methods=["POST"])
@require_auth
def delete_document(doc_id):
    if not owns_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "delete"},
            severity="WARNING",
        )
        abort(403)
    docs = load_docs()
    doc  = docs.pop(doc_id, None)
    if not doc:
        abort(404)

    (_upload_dir() / doc["enc_filename"]).unlink(missing_ok=True)
    shares = {k: v for k, v in load_shares().items() if v["doc_id"] != doc_id}
    save_shares(shares)
    save_docs(docs)
    security_logger.log_event(
        SecurityLogger.FILE_DELETE, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "filename": doc["original_name"]},
    )
    flash("Document deleted.")
    return redirect(url_for("dashboard"))

# ---------------------------------------------------------------------------
# Routes — Sharing
# ---------------------------------------------------------------------------

@app.route("/document/<doc_id>/share", methods=["GET", "POST"])
@require_auth
def share_document(doc_id):
    if not owns_document(g.user_id, doc_id):
        abort(403)

    if request.method == "POST":
        target_username = sanitize_input(request.form.get("username", "").strip())
        expires_in      = request.form.get("expires_in", "").strip()

        users     = load_users()
        target_id = next(
            (uid for uid, u in users.items()
             if u["username"].lower() == target_username.lower()), None
        )
        if not target_id:
            flash("User not found.")
            return render_template("share.html", doc_id=doc_id)

        if target_id == g.user_id:
            flash("You cannot share with yourself.")
            return render_template("share.html", doc_id=doc_id)

        expires = None
        if expires_in:
            try:
                from datetime import timedelta
                expires = (
                    datetime.utcnow() + timedelta(hours=int(expires_in))
                ).isoformat()
            except ValueError:
                flash("Invalid expiry value.")
                return render_template("share.html", doc_id=doc_id)

        share_id = str(uuid.uuid4())
        shares   = load_shares()
        shares[share_id] = {
            "doc_id":      doc_id,
            "shared_by":   g.user_id,
            "shared_with": target_id,
            "created_at":  datetime.utcnow().isoformat(),
            "expires":     expires,
        }
        save_shares(shares)
        security_logger.log_event(
            SecurityLogger.SHARE_CREATED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "shared_with": target_username},
        )
        flash(f"Document shared with {target_username}.")
        return redirect(url_for("dashboard"))

    return render_template("share.html", doc_id=doc_id)

# ---------------------------------------------------------------------------
# Routes — Admin
# ---------------------------------------------------------------------------

@app.route("/admin")
@require_role("admin")
def admin_panel():
    security_logger.log_event(
        SecurityLogger.DATA_ACCESS, g.user_id, g.ip, g.ua,
        details={"view": "admin_panel"},
    )
    return render_template("admin.html",
                           users=load_users(),
                           docs=load_docs(),
                           shares=load_shares())

@app.route("/admin/audit")
@require_role("admin")
def audit_log():
    return render_template("audit.html", entries=load_audit())

# ---------------------------------------------------------------------------
# TLS certificate auto-generation
# ---------------------------------------------------------------------------

def ensure_tls_cert() -> None:
    cert_dir = BASE_DIR / app.config["CERT_FOLDER"]
    cert     = cert_dir / "cert.pem"
    key      = cert_dir / "key.pem"
    if cert.exists() and key.exists():
        return
    cert_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes",
            "-out",    str(cert),
            "-keyout", str(key),
            "-days",   "365",
            "-subj",   "/CN=localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    security_logger.log_event(
        SecurityLogger.SUSPICIOUS_ACTIVITY, None, "localhost", "",
        details={"action": "tls_cert_generated", "path": str(cert)},
        severity="INFO",
    )

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ensure_tls_cert()
    cert_dir = BASE_DIR / app.config["CERT_FOLDER"]
    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=(str(cert_dir / "cert.pem"), str(cert_dir / "key.pem")),
        debug=False,
    )
