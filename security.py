"""
security.py — Core security infrastructure for SecureWebApp.
Contains: EncryptedStorage, SecurityLogger, SessionManager, RateLimiter,
          input validation, safe path helpers, and auth decorators.
"""
import os
import json
import time
import html
import logging
import re
import secrets
import hashlib
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename as _secure_filename
from flask import g, request, redirect, url_for, flash, abort, current_app


class EncryptedStorage:

    def __init__(self, key_path: str) -> None:
        self._key_path = Path(key_path)
        self._fernet = self._load_or_create_key()

    # Key management
    def _load_or_create_key(self) -> Fernet:
        if self._key_path.exists():
            try:
                key = self._key_path.read_bytes().strip()
                return Fernet(key)
            except Exception as exc:
                logging.getLogger("security").error(
                    "Failed to load encryption key from %s: %s", self._key_path, exc
                )
                raise
        try:
            key = Fernet.generate_key()
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_bytes(key)
            try:
                os.chmod(self._key_path, 0o600)
            except (AttributeError, NotImplementedError, OSError):
                pass  # Windows chmod is best-effort
            logging.getLogger("security").info(
                "Generated new encryption key at %s", self._key_path
            )
            return Fernet(key)
        except Exception as exc:
            logging.getLogger("security").error(
                "Failed to create encryption key: %s", exc
            )
            raise

    # Raw bytes encryption
    def encrypt_file(self, file_bytes: bytes) -> bytes:
        try:
            return self._fernet.encrypt(file_bytes)
        except Exception as exc:
            logging.getLogger("security").error("encrypt_file failed: %s", exc)
            raise

    def decrypt_file(self, encrypted_bytes: bytes) -> bytes:
        try:
            return self._fernet.decrypt(encrypted_bytes)
        except InvalidToken as exc:
            logging.getLogger("security").error(
                "decrypt_file failed — invalid token: %s", exc
            )
            raise
        except Exception as exc:
            logging.getLogger("security").error("decrypt_file failed: %s", exc)
            raise

    # Plain JSON
    def save_json(self, filepath: str, data) -> None:
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception as exc:
            logging.getLogger("security").error(
                "save_json failed for %s: %s", filepath, exc
            )
            raise

    def load_json(self, filepath: str, default=None):
        _default = default if default is not None else {}
        try:
            path = Path(filepath)
            if not path.exists() or path.stat().st_size == 0:
                return _default
            content = path.read_text(encoding="utf-8").strip()
            if not content:
                return _default
            return json.loads(content)
        except json.JSONDecodeError as exc:
            logging.getLogger("security").error(
                "JSON decode error in %s: %s", filepath, exc
            )
            return _default
        except Exception as exc:
            logging.getLogger("security").error(
                "load_json failed for %s: %s", filepath, exc
            )
            return _default

    # Encrypted JSON
    def save_encrypted_json(self, filepath: str, data) -> None:
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = json.dumps(data, indent=2).encode("utf-8")
            path.write_bytes(self._fernet.encrypt(raw))
        except Exception as exc:
            logging.getLogger("security").error(
                "save_encrypted_json failed for %s: %s", filepath, exc
            )
            raise

    def load_encrypted_json(self, filepath: str, default=None):
        _default = default if default is not None else {}
        try:
            path = Path(filepath)
            if not path.exists() or path.stat().st_size == 0:
                return _default
            file_bytes = path.read_bytes()
            try:
                return json.loads(self._fernet.decrypt(file_bytes).decode("utf-8"))
            except InvalidToken:
                # File may be plaintext JSON (e.g. manually deleted and recreated).
                # Re-encrypt it silently rather than treating it as corruption.
                try:
                    data = json.loads(file_bytes.decode("utf-8"))
                    self.save_encrypted_json(filepath, data)
                    return data
                except (json.JSONDecodeError, UnicodeDecodeError):
                    logging.getLogger("security").error(
                        "load_encrypted_json — unreadable file %s", filepath
                    )
                    return _default
        except json.JSONDecodeError as exc:
            logging.getLogger("security").error(
                "JSON decode error in encrypted file %s: %s", filepath, exc
            )
            return _default
        except Exception as exc:
            logging.getLogger("security").error(
                "load_encrypted_json failed for %s: %s", filepath, exc
            )
            return _default



_EASTERN = ZoneInfo("America/New_York")


def est_timestamp() -> str:
    now = datetime.now(_EASTERN)
    abbr = now.strftime("%Z")  # EST or EDT
    return now.strftime(f"%Y-%m-%d %I:%M:%S %p {abbr}")


class SecurityLogger:

    # Event type
    LOGIN_SUCCESS           = "LOGIN_SUCCESS"
    LOGIN_FAILED            = "LOGIN_FAILED"
    ACCOUNT_LOCKED          = "ACCOUNT_LOCKED"
    LOGOUT                  = "LOGOUT"
    REGISTER_SUCCESS        = "REGISTER_SUCCESS"
    REGISTER_FAILED         = "REGISTER_FAILED"
    ACCESS_DENIED           = "ACCESS_DENIED"
    DATA_ACCESS             = "DATA_ACCESS"
    FILE_UPLOAD             = "FILE_UPLOAD"
    FILE_DOWNLOAD           = "FILE_DOWNLOAD"
    FILE_DELETE             = "FILE_DELETE"
    SHARE_CREATED           = "SHARE_CREATED"
    SHARE_REVOKED           = "SHARE_REVOKED"
    VERSION_UPLOAD          = "VERSION_UPLOAD"
    SESSION_CREATED         = "SESSION_CREATED"
    SESSION_EXPIRED         = "SESSION_EXPIRED"
    SESSION_DESTROYED       = "SESSION_DESTROYED"
    INPUT_VALIDATION_FAILURE = "INPUT_VALIDATION_FAILURE"
    RATE_LIMIT_EXCEEDED     = "RATE_LIMIT_EXCEEDED"
    PATH_TRAVERSAL_ATTEMPT  = "PATH_TRAVERSAL_ATTEMPT"
    SUSPICIOUS_ACTIVITY     = "SUSPICIOUS_ACTIVITY"

    _ACCESS_EVENTS = frozenset({
        LOGIN_SUCCESS, LOGOUT, DATA_ACCESS,
        FILE_UPLOAD, FILE_DOWNLOAD,
    })

    def __init__(self, security_log_path: str, access_log_path: str) -> None:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        fmt.formatTime = lambda record, datefmt=None: est_timestamp()

        self._sec = logging.getLogger("security")
        if not self._sec.handlers:
            Path(security_log_path).parent.mkdir(parents=True, exist_ok=True)
            sh = logging.FileHandler(security_log_path, encoding="utf-8")
            sh.setFormatter(fmt)
            self._sec.addHandler(sh)
            self._sec.setLevel(logging.DEBUG)
            self._sec.propagate = False

        self._acc = logging.getLogger("access")
        if not self._acc.handlers:
            Path(access_log_path).parent.mkdir(parents=True, exist_ok=True)
            ah = logging.FileHandler(access_log_path, encoding="utf-8")
            ah.setFormatter(fmt)
            self._acc.addHandler(ah)
            self._acc.setLevel(logging.DEBUG)
            self._acc.propagate = False

    def log_event(
        self,
        event_type: str,
        user_id,
        ip: str,
        user_agent: str,
        details: dict = None,
        severity: str = "INFO",
    ) -> None:
        entry = json.dumps({
            "timestamp":  est_timestamp(),
            "event_type": event_type,
            "user_id":    user_id,
            "ip":         ip,
            "user_agent": user_agent,
            "details":    details or {},
        })
        sev = severity.upper()
        logger = self._acc if event_type in self._ACCESS_EVENTS else self._sec
        if sev == "CRITICAL":
            self._sec.critical(entry)
        elif sev == "ERROR":
            self._sec.error(entry)
        elif sev == "WARNING":
            self._sec.warning(entry)
        else:
            logger.info(entry)


class SessionManager:
    def __init__(
        self,
        sessions_file: str,
        session_timeout: int,
        storage: EncryptedStorage,
        logger: SecurityLogger,
    ) -> None:
        self._file    = sessions_file
        self._timeout = session_timeout
        self._storage = storage
        self._logger  = logger

    def _load(self) -> dict:
        return self._storage.load_encrypted_json(self._file, default={})

    def _save(self, sessions: dict) -> None:
        self._storage.save_encrypted_json(self._file, sessions)

    def create_session(self, user_id: str, ip: str, user_agent: str) -> str:
        token    = secrets.token_urlsafe(32)
        now      = time.time()
        sessions = self._load()
        sessions[token] = {
            "token":         token,
            "user_id":       user_id,
            "created_at":    now,
            "last_activity": now,
            "ip_address":    ip,
            "user_agent":    user_agent,
        }
        self._save(sessions)
        self._logger.log_event(
            SecurityLogger.SESSION_CREATED, user_id, ip, user_agent,
            details={"token_prefix": token[:8]},
        )
        return token

    _MAX_SESSION_AGE = 8 * 3600  # 8-hour absolute lifetime

    def validate_session(self, token: str) -> dict | None:
        if not token:
            return None
        sessions = self._load()
        sess = sessions.get(token)
        if not sess:
            return None
        now = time.time()
        idle_expired = now - sess.get("last_activity", 0) > self._timeout
        abs_expired  = now - sess.get("created_at", now) > self._MAX_SESSION_AGE
        if idle_expired or abs_expired:
            sessions.pop(token, None)
            self._save(sessions)
            self._logger.log_event(
                SecurityLogger.SESSION_EXPIRED,
                sess.get("user_id"), sess.get("ip_address", ""),
                sess.get("user_agent", ""),
                details={"token_prefix": token[:8],
                         "reason": "absolute_limit" if abs_expired else "idle"},
            )
            return None
        sess["last_activity"] = now
        sessions[token] = sess
        self._save(sessions)
        return sess

    def destroy_session(self, token: str) -> None:
        if not token:
            return
        sessions = self._load()
        sess = sessions.pop(token, None)
        self._save(sessions)
        if sess:
            self._logger.log_event(
                SecurityLogger.SESSION_DESTROYED,
                sess.get("user_id"), sess.get("ip_address", ""),
                sess.get("user_agent", ""),
                details={"token_prefix": token[:8]},
            )

    def cleanup_expired(self) -> None:
        sessions = self._load()
        now      = time.time()
        idle_cut = now - self._timeout
        abs_cut  = now - self._MAX_SESSION_AGE
        expired  = [
            t for t, s in sessions.items()
            if s.get("last_activity", 0) < idle_cut
            or s.get("created_at", 0) < abs_cut
        ]
        if expired:
            for t in expired:
                sessions.pop(t, None)
            self._save(sessions)


# RateLimiter (in-memory) keyed by IP with sliding window logic.
class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max     = max_attempts
        self._window  = window_seconds
        self._store: dict[str, list] = {}

    def _prune(self, ip: str) -> None:
        cutoff = time.time() - self._window
        self._store[ip] = [t for t in self._store.get(ip, []) if t > cutoff]

    def is_allowed(self, ip: str) -> bool:
        self._prune(ip)
        if len(self._store.get(ip, [])) >= self._max:
            return False
        self._store.setdefault(ip, []).append(time.time())
        return True

    def get_remaining(self, ip: str) -> int:
        self._prune(ip)
        return max(0, self._max - len(self._store.get(ip, [])))


# Input Validation
def validate_username(s: str) -> bool:
    """3–20 characters, alphanumeric + underscore only."""
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{3,20}$", s or ""))


def validate_email(s: str) -> bool:
    return bool(
        re.fullmatch(
            r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
            s or "",
        )
    )


def validate_password(s: str) -> list:
    """Returns a list of error strings; empty list means the password is valid."""
    errors = []
    if len(s) < 12:
        errors.append("Password must be at least 12 characters.")
    if not re.search(r"[A-Z]", s):
        errors.append("Password must contain an uppercase letter.")
    if not re.search(r"[a-z]", s):
        errors.append("Password must contain a lowercase letter.")
    if not re.search(r"\d", s):
        errors.append("Password must contain a digit.")
    if not re.search(r"[!@#$%^&*]", s):
        errors.append("Password must contain a special character (!@#$%^&*).")
    return errors


def sanitize_input(s) -> str:
    return html.escape(str(s))


def safe_filename(
    filename: str,
    allowed_extensions: set,
    logger: SecurityLogger = None,
    user_id=None,
    ip: str = "",
    ua: str = "",
) -> str:
    name = _secure_filename(filename)
    if not name or not re.fullmatch(r"^[\w\-\.]+$", name):
        if logger:
            logger.log_event(
                SecurityLogger.INPUT_VALIDATION_FAILURE, user_id, ip, ua,
                details={"filename": filename, "reason": "invalid characters"},
                severity="WARNING",
            )
        raise ValueError(f"Invalid filename: {filename!r}")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in allowed_extensions:
        if logger:
            logger.log_event(
                SecurityLogger.INPUT_VALIDATION_FAILURE, user_id, ip, ua,
                details={"filename": filename, "reason": f"extension .{ext} not allowed"},
                severity="WARNING",
            )
        raise ValueError(f"Extension not allowed: .{ext}")
    return name


def safe_file_path(
    filename: str,
    base_dir: str,
    logger: SecurityLogger = None,
    user_id=None,
    ip: str = "",
    ua: str = "",
) -> str:
    full = os.path.abspath(os.path.join(base_dir, filename))
    base = os.path.abspath(base_dir)
    if not (full == base or full.startswith(base + os.sep)):
        if logger:
            logger.log_event(
                SecurityLogger.PATH_TRAVERSAL_ATTEMPT, user_id, ip, ua,
                details={"filename": filename, "base_dir": base_dir},
                severity="CRITICAL",
            )
        raise ValueError(f"Path traversal detected: {filename!r}")
    return full


#  byte signatures for MIME detection (first 261 bytes)
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x25\x50\x44\x46",                   "application/pdf"),   
    (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", "image/png"),
    (b"\xff\xd8\xff",                        "image/jpeg"),
    (b"\x50\x4b\x03\x04",                   "application/zip"), 
]

_DOCX_MIME = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
)


def _detect_mime(header: bytes) -> str | None:
    for magic, mime in _MAGIC:
        if header.startswith(magic):
            return mime
    return None


def validate_file_upload(
    file_storage_obj,
    allowed_extensions: set,
    allowed_mimes: set,
    max_size: int,
) -> tuple[bool, str]:

    # Validate a Werkzeug FileStorage object
    filename = file_storage_obj.filename or ""
    if not filename:
        return False, "No filename provided."

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in allowed_extensions:
        return False, f"Extension .{ext} is not allowed."

    # Read magic bytes
    header = file_storage_obj.read(261)
    file_storage_obj.seek(0)

    detected = _detect_mime(header)

    # Plain text: no magic signature verify UTF-8 decodability
    if ext == "txt" and detected is None:
        try:
            header.decode("utf-8")
            detected = "text/plain"
        except UnicodeDecodeError:
            return False, "Text file contains non-UTF-8 content."

    # DOCX is ZIP-based remap the MIME
    if ext == "docx" and detected == "application/zip":
        detected = _DOCX_MIME

    if detected not in allowed_mimes:
        return False, f"File content type {detected!r} is not permitted."

    # Size check
    file_storage_obj.seek(0, 2)
    size = file_storage_obj.tell()
    file_storage_obj.seek(0)

    if size > max_size:
        return False, f"File size {size} B exceeds maximum {max_size} B."

    return True, "OK"


# Auth Decorators
def require_auth(f):
    """Redirect to /login if g.user_id is not set."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user_id"):
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def deny_guest(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.get("user_id"):
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        if (g.get("user") or {}).get("role") == "guest":
            try:
                current_app.security_logger.log_event(
                    SecurityLogger.ACCESS_DENIED,
                    g.get("user_id"), g.get("ip", ""), g.get("ua", ""),
                    details={"reason": "guest_write_denied", "path": request.path},
                    severity="WARNING",
                )
            except Exception:
                pass
            abort(403)
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not g.get("user_id"):
                flash("Please log in to continue.")
                return redirect(url_for("login"))
            user_role = (g.get("user") or {}).get("role")
            if user_role not in roles:
                try:
                    current_app.security_logger.log_event(
                        SecurityLogger.ACCESS_DENIED,
                        g.get("user_id"), g.get("ip", ""), g.get("ua", ""),
                        details={
                            "required_roles": list(roles),
                            "user_role": user_role,
                        },
                        severity="WARNING",
                    )
                except Exception:
                    pass
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator
