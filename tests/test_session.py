"""Tests for SessionManager: creation, validation, expiry, invalidation."""
import json
import time
import uuid
import pytest

from security import EncryptedStorage, SecurityLogger, SessionManager
from app import app, hash_password


# ---------------------------------------------------------------------------
# Unit tests for SessionManager directly
# ---------------------------------------------------------------------------

@pytest.fixture
def mgr(tmp_path):
    store  = EncryptedStorage(str(tmp_path / "secret.key"))
    logger = SecurityLogger(
        str(tmp_path / "security.log"),
        str(tmp_path / "access.log"),
    )
    sessions_file = str(tmp_path / "sessions.json")
    (tmp_path / "sessions.json").write_text("{}")
    return SessionManager(
        sessions_file=sessions_file,
        session_timeout=30,
        storage=store,
        logger=logger,
    )


class TestSessionManagerUnit:
    def test_create_session_returns_token(self, mgr):
        token = mgr.create_session("user1", "127.0.0.1", "TestAgent")
        assert isinstance(token, str) and len(token) > 16

    def test_validate_valid_session(self, mgr):
        token = mgr.create_session("user1", "127.0.0.1", "TestAgent")
        sess  = mgr.validate_session(token)
        assert sess is not None
        assert sess["user_id"] == "user1"

    def test_validate_missing_token_returns_none(self, mgr):
        assert mgr.validate_session("nonexistent") is None

    def test_validate_empty_token_returns_none(self, mgr):
        assert mgr.validate_session("") is None
        assert mgr.validate_session(None) is None

    def test_destroy_session_invalidates_token(self, mgr):
        token = mgr.create_session("user1", "127.0.0.1", "TestAgent")
        mgr.destroy_session(token)
        assert mgr.validate_session(token) is None

    def test_expired_session_returns_none(self, tmp_path):
        """Use a 1-second timeout and manually back-date last_activity."""
        store  = EncryptedStorage(str(tmp_path / "secret.key"))
        logger = SecurityLogger(
            str(tmp_path / "security.log"),
            str(tmp_path / "access.log"),
        )
        sessions_file = str(tmp_path / "sessions.json")
        (tmp_path / "sessions.json").write_text("{}")
        mgr2 = SessionManager(sessions_file, session_timeout=1,
                              storage=store, logger=logger)

        token = mgr2.create_session("u1", "127.0.0.1", "UA")
        # Force expiry by manipulating last_activity
        data = store.load_json(sessions_file)
        data[token]["last_activity"] = time.time() - 10
        store.save_json(sessions_file, data)

        assert mgr2.validate_session(token) is None

    def test_cleanup_removes_expired(self, tmp_path):
        store  = EncryptedStorage(str(tmp_path / "secret.key"))
        logger = SecurityLogger(
            str(tmp_path / "security.log"),
            str(tmp_path / "access.log"),
        )
        sessions_file = str(tmp_path / "sessions.json")
        (tmp_path / "sessions.json").write_text("{}")
        mgr2 = SessionManager(sessions_file, session_timeout=1,
                              storage=store, logger=logger)

        token = mgr2.create_session("u1", "127.0.0.1", "UA")
        data  = store.load_json(sessions_file)
        data[token]["last_activity"] = time.time() - 100
        store.save_json(sessions_file, data)

        mgr2.cleanup_expired()
        assert store.load_json(sessions_file) == {}

    def test_validate_updates_last_activity(self, mgr):
        token  = mgr.create_session("u1", "127.0.0.1", "UA")
        before = mgr._load()[token]["last_activity"]
        time.sleep(0.05)
        mgr.validate_session(token)
        after  = mgr._load()[token]["last_activity"]
        assert after >= before


# ---------------------------------------------------------------------------
# Integration tests via Flask routes
# ---------------------------------------------------------------------------

@pytest.fixture
def env(tmp_path):
    user_id = str(uuid.uuid4())
    users = {
        user_id: {
            "username": "sessionuser",
            "password": hash_password("Str0ng!Password#1"),
            "role": "user",
            "created_at": "2024-01-01T00:00:00",
            "failed_logins": 0,
            "locked_until": None,
        }
    }
    for name, content in (
        ("users.json", users), ("sessions.json", {}),
        ("documents.json", {}), ("shares.json", {}), ("audit.json", []),
    ):
        (tmp_path / name).write_text(json.dumps(content))

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER": str(tmp_path),
        "SESSION_TIMEOUT": 1800,
    })
    return {"tmp_path": tmp_path, "user_id": user_id}


class TestSessionIntegration:
    def test_login_creates_server_side_session(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            sessions = json.loads(
                (env["tmp_path"] / "sessions.json").read_text()
            )
            assert len(sessions) == 1

    def test_logout_removes_server_side_session(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            c.get("/logout")
            sessions = json.loads(
                (env["tmp_path"] / "sessions.json").read_text()
            )
            assert len(sessions) == 0

    def test_expired_session_denied(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            # Back-date last_activity to force expiry
            sessions = json.loads(
                (env["tmp_path"] / "sessions.json").read_text()
            )
            for token in sessions:
                sessions[token]["last_activity"] = time.time() - 99999
            (env["tmp_path"] / "sessions.json").write_text(
                json.dumps(sessions)
            )
            r = c.get("/dashboard", follow_redirects=True)
            assert b"login" in r.data.lower()

    def test_cleared_server_session_denies_cookie(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            # Simulate server-side invalidation (e.g. admin revoke)
            (env["tmp_path"] / "sessions.json").write_text("{}")
            r = c.get("/dashboard", follow_redirects=True)
            assert b"login" in r.data.lower()

    def test_session_cookie_config(self, env):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
