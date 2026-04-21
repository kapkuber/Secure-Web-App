import os
import time
import uuid
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import bcrypt
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, abort, Response, g, make_response
)

from config import Config
from security import (
    EncryptedStorage, SecurityLogger, SessionManager, RateLimiter,
    validate_username, validate_email, validate_password,
    sanitize_input, safe_filename, safe_file_path, validate_file_upload,
    require_auth, require_role, deny_guest, est_timestamp,
)

app = Flask(__name__)
app.config.from_object(Config)

BASE_DIR = Path(__file__).parent

# Extension mapped to canonical MIME type
_EXT_MIME = {
    "pdf":  "application/pdf",
    "txt":  "text/plain",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "png":  "image/png",
    "jpg":  "image/jpeg",
    "jpeg": "image/jpeg",
}
# Security singletons
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

app.security_logger = security_logger

# Path helpers
def _data(filename: str) -> str:
    """Absolute path to a file in DATA_FOLDER (works with absolute overrides in tests)."""
    base = Path(app.config["DATA_FOLDER"])
    if base.is_absolute():
        return str(base / filename)
    return str(BASE_DIR / base / filename)

def _upload_dir() -> Path:
    base = Path(app.config["UPLOAD_FOLDER"])
    return base if base.is_absolute() else BASE_DIR / base

# Data store helpers
def load_users():    return storage.load_encrypted_json(_data("users.json"),     default={})
def save_users(d):   storage.save_encrypted_json(_data("users.json"),     d)
def load_docs():     return storage.load_encrypted_json(_data("documents.json"), default={})
def save_docs(d):    storage.save_encrypted_json(_data("documents.json"), d)
def load_shares():   return storage.load_encrypted_json(_data("shares.json"),    default={})
def save_shares(d):  storage.save_encrypted_json(_data("shares.json"),    d)
def load_audit():    return storage.load_encrypted_json(_data("audit.json"),     default=[])
def save_audit(d):   storage.save_encrypted_json(_data("audit.json"),     d)

def _migrate_plaintext_json_to_encrypted() -> None:
    """One-time migration: re-encrypt any data files still stored as plaintext JSON."""
    import json as _json
    files_and_defaults = [
        ("users.json",     {}),
        ("documents.json", {}),
        ("shares.json",    {}),
        ("sessions.json",  {}),
        ("audit.json",     []),
    ]
    for filename, default in files_and_defaults:
        path = Path(_data(filename))
        if not path.exists() or path.stat().st_size == 0:
            continue
        raw = path.read_bytes()
        try:
            storage._fernet.decrypt(raw)
            continue  # already encrypted
        except Exception:
            pass
        try:
            data = _json.loads(raw.decode("utf-8"))
            storage.save_encrypted_json(str(path), data)
            logging.getLogger("security").info("Migrated %s to encrypted storage", filename)
        except Exception as exc:
            logging.getLogger("security").error("Migration failed for %s: %s", filename, exc)

_migrate_plaintext_json_to_encrypted()

# Audit helper
def audit(
    event_type: str,
    doc_id: str = None,
    doc_name: str = None,
    details: dict = None,
    username: str = None,
    user_id: str = None,
) -> None:
    user = g.get("user") or {}
    timestamp = est_timestamp()
    entries = load_audit()
    entries.append({
        "audit_id":   str(uuid.uuid4()),
        "timestamp":  timestamp,
        "event_type": event_type,
        "user_id":    user_id or g.get("user_id"),
        "username":   username or user.get("username", "anonymous"),
        "doc_id":     doc_id,
        "doc_name":   doc_name,
        "ip_address": g.get("ip", ""),
        "details":    details or {},
    })
    save_audit(entries)

# Password helpers
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(
        plain.encode(), bcrypt.gensalt(app.config["BCRYPT_ROUNDS"])
    ).decode()

def check_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# File helpers
def _secure_delete_file(filepath: str) -> None:
    path = Path(filepath)
    if not path.exists():
        return
    try:
        size = path.stat().st_size
        if size > 0:
            with open(path, "r+b") as fh:
                fh.write(os.urandom(size))
                fh.flush()
                os.fsync(fh.fileno())
                fh.seek(0)
                fh.write(b"\x00" * size)
                fh.flush()
                os.fsync(fh.fileno())
        path.unlink()
    except Exception as exc:
        logging.getLogger("security").error(
            "secure_delete_file failed for %s: %s", filepath, exc
        )
        raise

# Document access helpers
def _live_doc(doc_id: str) -> dict | None:
    doc = load_docs().get(doc_id)
    return None if (doc is None or doc.get("is_deleted")) else doc

def owns_document(user_id: str, doc_id: str) -> bool:
    doc = _live_doc(doc_id)
    return doc is not None and doc["owner_id"] == user_id

def can_access_document(user_id: str, doc_id: str) -> bool:
    doc = _live_doc(doc_id)
    if doc is None:
        return False
    if doc["owner_id"] == user_id:
        return True
    for share in load_shares().values():
        if share["doc_id"] == doc_id and share["shared_with_user_id"] == user_id:
            return True
    return False

def can_edit_document(user_id: str, doc_id: str) -> bool:
    if owns_document(user_id, doc_id):
        return True
    for share in load_shares().values():
        if (share["doc_id"] == doc_id
                and share["shared_with_user_id"] == user_id
                and share.get("role") == "editor"):
            return True
    return False

def get_current_stored_file(doc: dict) -> str:
    cv = doc["current_version"]
    for v in doc["versions"]:
        if v["version"] == cv:
            return v["stored_file"]
    return doc["versions"][-1]["stored_file"]

# Cookie
def _cookie_kwargs() -> dict:
    return {
        "httponly": True,
        # secure=True in production
        "secure":   not app.config.get("TESTING", False),
        "samesite": "Strict",
        "max_age":  app.config["SESSION_TIMEOUT"],
    }

# Template helpers
@app.template_filter("ts_to_date")
def ts_to_date(ts):
    if ts is None:
        return "—"
    try:
        from zoneinfo import ZoneInfo
        eastern = ZoneInfo("America/New_York")
        dt = datetime.fromtimestamp(float(ts), tz=eastern)
        return dt.strftime(f"%Y-%m-%d %I:%M %p {dt.strftime('%Z')}")
    except (ValueError, TypeError, OSError):
        return str(ts)

@app.context_processor
def inject_user():
    return {
        "current_user":    g.get("user"),
        "current_user_id": g.get("user_id"),
    }

# before_request
@app.before_request
def before_request() -> None:
    # Force HTTPS
    if (not app.config.get("TESTING")
            and app.config.get("ENV") != "development"
            and not request.is_secure):
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

    # Keep session path in sync with data folder
    session_manager._file = _data("sessions.json")
    session_manager.cleanup_expired()
    g.ip      = request.remote_addr or ""
    g.ua      = request.headers.get("User-Agent", "")
    g.user_id = None
    g.user    = None

    token = request.cookies.get("session_token")
    sess  = session_manager.validate_session(token)
    if sess:
        user = load_users().get(sess["user_id"])
        if user and user.get("is_active", True):
            g.user_id = sess["user_id"]
            g.user    = user

# after_request security headers
@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
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
    if g.get("user_id") and not request.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-store"
    return response

# Error handlers
@app.errorhandler(403)
def forbidden(e):       return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):       return render_template("404.html"), 404

@app.errorhandler(429)
def rate_limited(e):    return render_template("429.html"), 429

@app.errorhandler(500)
def internal_error(e):  return render_template("500.html"), 500

# Routes — Authentication
@app.route("/")
def index():
    return redirect(url_for("dashboard") if g.user_id else url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user_id:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = sanitize_input(request.form.get("username", "").strip())
        email    = sanitize_input(request.form.get("email", "").strip().lower())
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not validate_username(username):
            security_logger.log_event(
                SecurityLogger.REGISTER_FAILED, None, g.ip, g.ua,
                details={"reason": "invalid username"}, severity="WARNING",
            )
            flash("Username must be 3–20 alphanumeric/underscore characters.")
            return render_template("register.html")

        if not validate_email(email):
            security_logger.log_event(
                SecurityLogger.REGISTER_FAILED, None, g.ip, g.ua,
                details={"reason": "invalid email"}, severity="WARNING",
            )
            flash("Please enter a valid email address.")
            return render_template("register.html")

        errors = validate_password(password)
        if errors:
            security_logger.log_event(
                SecurityLogger.REGISTER_FAILED, None, g.ip, g.ua,
                details={"reason": "weak password"}, severity="WARNING",
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
            if u.get("email", "").lower() == email:
                flash("Email already registered.")
                return render_template("register.html")

        # First user becomes admin, subsequent users are "user"
        role    = "admin" if not users else "user"
        user_id = str(uuid.uuid4())
        users[user_id] = {
            "user_id":         user_id,
            "username":        username,
            "email":           email,
            "password_hash":   hash_password(password),
            "role":            role,
            "created_at":      time.time(),
            "failed_attempts": 0,
            "locked_until":    None,
            "last_login":      None,
            "is_active":       True,
        }
        save_users(users)
        security_logger.log_event(
            SecurityLogger.REGISTER_SUCCESS, user_id, g.ip, g.ua,
            details={"username": username, "role": role},
        )
        audit("REGISTER_SUCCESS", username=username, user_id=user_id)
        flash("Registration successful, please log in")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user_id:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = sanitize_input(request.form.get("username", "").strip())
        password = sanitize_input(request.form.get("password", ""))

        if not app.config.get("TESTING") and not rate_limiter.is_allowed(g.ip):
            security_logger.log_event(
                SecurityLogger.RATE_LIMIT_EXCEEDED, None, g.ip, g.ua,
                details={"endpoint": "login"}, severity="WARNING",
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
                users[user_id]["failed_attempts"] = (
                    users[user_id].get("failed_attempts", 0) + 1
                )
                if users[user_id]["failed_attempts"] >= app.config["MAX_FAILED_ATTEMPTS"]:
                    users[user_id]["locked_until"] = (
                        time.time() + app.config["LOCKOUT_DURATION"]
                    )
                    security_logger.log_event(
                        SecurityLogger.ACCOUNT_LOCKED, user_id, g.ip, g.ua,
                        details={"username": username,
                                 "locked_until": users[user_id]["locked_until"]},
                        severity="ERROR",
                    )
                else:
                    security_logger.log_event(
                        SecurityLogger.LOGIN_FAILED, user_id, g.ip, g.ua,
                        details={"username": username}, severity="WARNING",
                    )
                save_users(users)
            else:
                # Unknown username log to avoid revealing user existence
                security_logger.log_event(
                    SecurityLogger.LOGIN_FAILED, None, g.ip, g.ua,
                    details={"username": username}, severity="WARNING",
                )
            flash(msg)
            return render_template("login.html")

        if not user_id:
            return fail("Invalid credentials")

        user = users[user_id]

        if not user.get("is_active", True):
            flash("Account disabled")
            return render_template("login.html")

        # Lockout check
        locked_until = user.get("locked_until")
        if locked_until and time.time() < float(locked_until):
            minutes_left = max(1, int((float(locked_until) - time.time()) / 60) + 1)
            security_logger.log_event(
                SecurityLogger.ACCOUNT_LOCKED, user_id, g.ip, g.ua,
                details={"username": username, "minutes_remaining": minutes_left},
                severity="WARNING",
            )
            flash(f"Account locked for {minutes_left} minute(s)")
            return render_template("login.html")

        # Expired lockout reset before checking password
        if locked_until and time.time() >= float(locked_until):
            users[user_id]["failed_attempts"] = 0
            users[user_id]["locked_until"]    = None
            save_users(users)

        if not check_password(password, user["password_hash"]):
            return fail("Invalid credentials")

        #  Successful authentication
        users[user_id]["failed_attempts"] = 0
        users[user_id]["locked_until"]    = None
        users[user_id]["last_login"]      = time.time()
        save_users(users)

        token = session_manager.create_session(user_id, g.ip, g.ua)
        security_logger.log_event(
            SecurityLogger.LOGIN_SUCCESS, user_id, g.ip, g.ua,
            details={"username": username},
        )
        audit("LOGIN_SUCCESS", username=username, user_id=user_id)

        response = make_response(redirect("/dashboard"))
        response.set_cookie("session_token", token, **_cookie_kwargs())
        return response

    return render_template("login.html")

@app.route("/logout")
@require_auth
def logout():
    token = request.cookies.get("session_token")
    session_manager.destroy_session(token)
    security_logger.log_event(SecurityLogger.LOGOUT, g.user_id, g.ip, g.ua)
    audit("LOGOUT")
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("session_token")
    flash("You have been logged out")
    return response

# Routes Dashboard
@app.route("/dashboard")
@require_auth
def dashboard():
    docs    = load_docs()
    shares  = load_shares()
    user_id = g.user_id

    own_docs = {
        k: v for k, v in docs.items()
        if v["owner_id"] == user_id and not v.get("is_deleted")
    }

    shared_doc_ids = {
        s["doc_id"] for s in shares.values()
        if s["shared_with_user_id"] == user_id
    }
    shared_docs = {
        k: v for k, v in docs.items()
        if k in shared_doc_ids and not v.get("is_deleted")
    }

    return render_template("dashboard.html", own_docs=own_docs, shared_docs=shared_docs)

# Routes Documents
@app.route("/upload", methods=["GET", "POST"])
@require_auth
@deny_guest
def upload():
    if request.method == "POST":
        if "file" not in request.files or not request.files["file"].filename:
            flash("No file selected.")
            return render_template("upload.html")

        f = request.files["file"]

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
                logger=security_logger, user_id=g.user_id, ip=g.ip, ua=g.ua,
            )
        except ValueError as exc:
            flash(str(exc))
            return render_template("upload.html")

        ext         = fname.rsplit(".", 1)[-1].lower()
        mime_type   = _EXT_MIME.get(ext, "application/octet-stream")
        doc_id      = str(uuid.uuid4())
        stored_name = doc_id
        stored_file = f"{stored_name}_v1.enc"

        raw_data = f.read()
        enc_data = storage.encrypt_file(raw_data)

        dest = _upload_dir() / stored_file
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(enc_data)

        now = time.time()
        docs = load_docs()
        docs[doc_id] = {
            "doc_id":          doc_id,
            "original_name":   fname,
            "stored_name":     stored_name,
            "owner_id":        g.user_id,
            "uploaded_at":     now,
            "size_bytes":      len(raw_data),
            "mime_type":       mime_type,
            "extension":       ext,
            "current_version": 1,
            "versions": [
                {
                    "version":     1,
                    "stored_file": stored_file,
                    "uploaded_at": now,
                    "uploaded_by": g.user_id,
                    "size_bytes":  len(raw_data),
                }
            ],
            "is_deleted": False,
        }
        save_docs(docs)
        security_logger.log_event(
            SecurityLogger.FILE_UPLOAD, g.user_id, g.ip, g.ua,
            details={"filename": fname, "size_bytes": len(raw_data), "doc_id": doc_id},
        )
        audit("FILE_UPLOAD", doc_id=doc_id, doc_name=fname)
        flash("File uploaded and encrypted successfully.")
        return redirect(url_for("dashboard"))

    return render_template("upload.html")

@app.route("/document/<doc_id>/version", methods=["POST"])
@require_auth
@deny_guest
def upload_version(doc_id):
    if not can_edit_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "version_upload"},
            severity="WARNING",
        )
        abort(403)

    docs = load_docs()
    doc  = docs.get(doc_id)
    if not doc or doc.get("is_deleted"):
        abort(404)

    if "file" not in request.files or not request.files["file"].filename:
        flash("No file selected.")
        return redirect(url_for("view_document", doc_id=doc_id))

    f = request.files["file"]
    valid, reason = validate_file_upload(
        f,
        app.config["ALLOWED_EXTENSIONS"],
        app.config["ALLOWED_MIME_TYPES"],
        app.config["MAX_CONTENT_LENGTH"],
    )
    if not valid:
        flash(f"Upload rejected: {reason}")
        return redirect(url_for("view_document", doc_id=doc_id))

    try:
        safe_filename(
            f.filename, app.config["ALLOWED_EXTENSIONS"],
            logger=security_logger, user_id=g.user_id, ip=g.ip, ua=g.ua,
        )
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("view_document", doc_id=doc_id))

    new_version = doc["current_version"] + 1
    stored_file = f"{doc['stored_name']}_v{new_version}.enc"

    raw_data = f.read()
    enc_data = storage.encrypt_file(raw_data)
    (_upload_dir() / stored_file).write_bytes(enc_data)

    now = time.time()
    doc["versions"].append({
        "version":     new_version,
        "stored_file": stored_file,
        "uploaded_at": now,
        "uploaded_by": g.user_id,
        "size_bytes":  len(raw_data),
    })
    doc["current_version"] = new_version
    doc["size_bytes"]      = len(raw_data)
    docs[doc_id] = doc
    save_docs(docs)

    security_logger.log_event(
        SecurityLogger.VERSION_UPLOAD, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "version": new_version},
    )
    audit("VERSION_UPLOAD", doc_id=doc_id, doc_name=doc["original_name"],
          details={"version": new_version})
    flash(f"Version {new_version} uploaded.")
    return redirect(url_for("view_document", doc_id=doc_id))

@app.route("/document/<doc_id>")
@require_auth
def view_document(doc_id):
    doc = _live_doc(doc_id)
    if not doc:
        abort(404)
    is_admin = (g.get("user") or {}).get("role") == "admin"
    if not is_admin and not can_access_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id}, severity="WARNING",
        )
        abort(403)

    can_edit = can_edit_document(g.user_id, doc_id)
    is_owner = owns_document(g.user_id, doc_id)

    # Build resolved share list for the owner so template can show revoke buttons
    doc_shares = []
    if is_owner:
        users = load_users()
        for sid, share in load_shares().items():
            if share["doc_id"] == doc_id:
                shared_user = users.get(share["shared_with_user_id"], {})
                doc_shares.append({
                    "share_id":   sid,
                    "username":   shared_user.get("username", "unknown"),
                    "role":       share["role"],
                    "created_at": share["created_at"],
                })
        doc_shares.sort(key=lambda s: s["created_at"], reverse=True)

    return render_template("document.html", doc=doc, doc_id=doc_id,
                           can_edit=can_edit, is_owner=is_owner,
                           doc_shares=doc_shares)

@app.route("/document/<doc_id>/download")
@require_auth
def download_document(doc_id):
    is_admin = (g.get("user") or {}).get("role") == "admin"
    if not is_admin and not can_access_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "download"}, severity="WARNING",
        )
        abort(403)
    doc = _live_doc(doc_id)
    if not doc:
        abort(404)

    stored_file = get_current_stored_file(doc)
    try:
        safe_file_path(
            stored_file, str(_upload_dir()),
            logger=security_logger, user_id=g.user_id, ip=g.ip, ua=g.ua,
        )
    except ValueError:
        abort(400)

    enc_data = (_upload_dir() / stored_file).read_bytes()
    plain    = storage.decrypt_file(enc_data)

    security_logger.log_event(
        SecurityLogger.FILE_DOWNLOAD, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "filename": doc["original_name"],
                 "version": doc["current_version"]},
    )
    audit("FILE_DOWNLOAD", doc_id=doc_id, doc_name=doc["original_name"])
    return Response(
        plain,
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(doc['original_name'], safe='')}",
            "Content-Type": doc.get("mime_type", "application/octet-stream"),
        },
    )

@app.route("/document/<doc_id>/delete", methods=["POST"])
@require_auth
def delete_document(doc_id):
    if not owns_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "delete"}, severity="WARNING",
        )
        abort(403)
    docs = load_docs()
    doc  = docs.get(doc_id)
    if not doc:
        abort(404)

    # Securely wipe every version file from disk, mark deleted in metadata.
    # The document record and audit history are preserved but file contents are not.
    upload_dir = str(_upload_dir())
    for version in doc.get("versions", []):
        stored_file = version.get("stored_file", "")
        if not stored_file:
            continue
        try:
            file_path = safe_file_path(stored_file, upload_dir)
            _secure_delete_file(file_path)
        except (ValueError, Exception) as exc:
            security_logger.log_event(
                SecurityLogger.FILE_DELETE, g.user_id, g.ip, g.ua,
                details={"doc_id": doc_id, "version_file": stored_file,
                         "error": str(exc)},
                severity="WARNING",
            )

    docs[doc_id]["is_deleted"] = True
    save_docs(docs)

    security_logger.log_event(
        SecurityLogger.FILE_DELETE, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "filename": doc["original_name"],
                 "versions_wiped": len(doc.get("versions", []))},
    )
    audit("FILE_DELETE", doc_id=doc_id, doc_name=doc["original_name"])
    flash("Document deleted.")
    return redirect(url_for("dashboard"))

# Routes — Sharing
@app.route("/document/<doc_id>/share", methods=["GET", "POST"])
@require_auth
def share_document(doc_id):
    if not owns_document(g.user_id, doc_id):
        abort(403)

    if request.method == "POST":
        target_username = sanitize_input(
            request.form.get("username", "").strip()
        )
        role = request.form.get("role", "viewer")
        if role not in ("viewer", "editor"):
            role = "viewer"

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

        # Guests are always viewer only regardless of submitted role
        if users.get(target_id, {}).get("role") == "guest":
            role = "viewer"

        share_id = str(uuid.uuid4())
        shares   = load_shares()
        shares[share_id] = {
            "share_id":            share_id,
            "doc_id":              doc_id,
            "owner_id":            g.user_id,
            "shared_with_user_id": target_id,
            "role":                role,
            "created_at":          time.time(),
            "granted_by":          g.user_id,
        }
        save_shares(shares)

        doc = _live_doc(doc_id)
        security_logger.log_event(
            SecurityLogger.SHARE_CREATED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "shared_with": target_username,
                     "role": role},
        )
        audit("SHARE_CREATED", doc_id=doc_id,
              doc_name=doc["original_name"] if doc else None,
              details={"shared_with": target_username, "role": role})
        flash(f"Document shared with {target_username} as {role}.")
        return redirect(url_for("dashboard"))

    return render_template("share.html", doc_id=doc_id)

@app.route("/document/<doc_id>/share/<share_id>/revoke", methods=["POST"])
@require_auth
def revoke_share(doc_id, share_id):
    """Owner revokes a specific share.  Writes a SHARE_REVOKED audit entry."""
    if not owns_document(g.user_id, doc_id):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "share_id": share_id, "action": "revoke"},
            severity="WARNING",
        )
        abort(403)

    shares = load_shares()
    share  = shares.pop(share_id, None)
    if share is None:
        abort(404)
    save_shares(shares)

    doc = _live_doc(doc_id)
    security_logger.log_event(
        SecurityLogger.SHARE_REVOKED, g.user_id, g.ip, g.ua,
        details={"doc_id": doc_id, "share_id": share_id,
                 "revoked_user_id": share.get("shared_with_user_id")},
    )
    audit(
        "SHARE_REVOKED",
        doc_id=doc_id,
        doc_name=doc["original_name"] if doc else None,
        details={"share_id": share_id,
                 "revoked_user_id": share.get("shared_with_user_id"),
                 "role": share.get("role")},
    )
    flash("Share revoked.")
    return redirect(url_for("view_document", doc_id=doc_id))

# Routes Audit
@app.route("/document/<doc_id>/audit")
@require_auth
def document_audit(doc_id):
    # load_docs() includes deleted entries
    doc     = load_docs().get(doc_id)
    is_admin = (g.user or {}).get("role") == "admin"
    is_owner = doc is not None and doc.get("owner_id") == g.user_id

    if not doc:
        abort(404)
    if not (is_owner or is_admin):
        security_logger.log_event(
            SecurityLogger.ACCESS_DENIED, g.user_id, g.ip, g.ua,
            details={"doc_id": doc_id, "action": "view_audit"},
            severity="WARNING",
        )
        abort(403)

    entries = [e for e in load_audit() if e.get("doc_id") == doc_id]
    entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    return render_template("document_audit.html", doc=doc, doc_id=doc_id,
                           entries=entries)

# Routes Admin
@app.route("/admin")
@require_role("admin")
def admin_panel():
    all_audit = load_audit()
    all_audit.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
    return render_template("admin.html",
                           users=load_users(),
                           docs=load_docs(),
                           shares=load_shares(),
                           recent_audit=all_audit[:20])

@app.route("/admin/create-guest", methods=["POST"])
@require_role("admin")
def admin_create_guest():
    username = sanitize_input(request.form.get("username", "").strip())
    password = request.form.get("password", "")

    if not validate_username(username):
        flash("Invalid username (3–20 alphanumeric/underscore characters).")
        return redirect(url_for("admin_panel"))

    errors = validate_password(password)
    if errors:
        for e in errors:
            flash(e)
        return redirect(url_for("admin_panel"))

    users = load_users()
    if any(u["username"].lower() == username.lower() for u in users.values()):
        flash("Username already taken.")
        return redirect(url_for("admin_panel"))

    user_id = str(uuid.uuid4())
    users[user_id] = {
        "user_id":         user_id,
        "username":        username,
        "email":           "",
        "password_hash":   hash_password(password),
        "role":            "guest",
        "created_at":      time.time(),
        "failed_attempts": 0,
        "locked_until":    None,
        "last_login":      None,
        "is_active":       True,
    }
    save_users(users)
    security_logger.log_event(
        SecurityLogger.REGISTER_SUCCESS, user_id, g.ip, g.ua,
        details={"username": username, "role": "guest"},
    )
    audit("GUEST_CREATED", details={"username": username})
    flash(f"Guest account '{username}' created.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/audit")
@require_role("admin")
def audit_log():
    all_entries = load_audit()

    filter_user  = request.args.get("user",  "").strip()
    filter_event = request.args.get("event", "").strip()

    entries = all_entries
    if filter_user:
        entries = [e for e in entries
                   if (e.get("username") or "").lower() == filter_user.lower()]
    if filter_event:
        entries = [e for e in entries
                   if e.get("event_type") == filter_event]

    # Dropdown options from the filtered result
    all_users  = sorted({e.get("username") or "" for e in entries
                         if e.get("username")})
    all_events = sorted({e.get("event_type") or "" for e in entries
                         if e.get("event_type")})

    entries = sorted(entries, key=lambda e: e.get("timestamp", ""), reverse=True)

    return render_template(
        "audit.html",
        entries=entries,
        filter_user=filter_user,
        filter_event=filter_event,
        all_users=all_users,
        all_events=all_events,
        total=len(all_entries),
    )

# 
# TLS certificate auto-generation
def ensure_tls_cert() -> tuple[str, str] | None:
    cert_dir = BASE_DIR / app.config["CERT_FOLDER"]
    cert_path = cert_dir / "cert.pem"
    key_path  = cert_dir / "key.pem"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as _dt

        cert_dir.mkdir(parents=True, exist_ok=True)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(cert_path), str(key_path)

    except Exception as exc:
        print(f"[WARNING] Could not generate TLS cert: {exc}. Running over HTTP.")
        return None

# First-run initialisation
def initialize_app() -> None:
    import json

    for directory in ["data", "logs", "uploads", "certs", "static/css", "static/js", "templates"]:
        os.makedirs(directory, exist_ok=True)

    json_files = {
        "data/users.json":    {},
        "data/sessions.json": {},
        "data/documents.json": {},
        "data/shares.json":   {},
        "data/audit.json":    [],
    }
    for filepath, default in json_files.items():
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            with open(filepath, "w") as f:
                json.dump(default, f)

    for log_file in ["logs/security.log", "logs/access.log"]:
        if not os.path.exists(log_file):
            open(log_file, "a").close()

# Entry point
if __name__ == "__main__":
    initialize_app()
    tls = ensure_tls_cert()
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context=tls if tls else None,
        debug=False,
    )
