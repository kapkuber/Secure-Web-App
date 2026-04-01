"""Tests for SessionManager and session integration."""
import json
import time
import uuid
import pytest

from security import EncryptedStorage, SecurityLogger, SessionManager
from app import app, hash_password


# ---------------------------------------------------------------------------
# Unit tests — SessionManager directly
# ---------------------------------------------------------------------------

@pytest.fixture
def mgr(tmp_path):
    store  = EncryptedStorage(str(tmp_path / "secret.key"))
    logger = SecurityLogger(
        str(tmp_path / "security.log"),
        str(tmp_path / "access.log"),
    )
    sf = str(tmp_path / "sessions.json")
    (tmp_path / "sessions.json").write_text("{}")
    return SessionManager(sf, session_timeout=30, storage=store, logger=logger)


class TestSessionManagerUnit:
    def test_create_returns_token(self, mgr):
        t = mgr.create_session("u1", "127.0.0.1", "UA")
        assert isinstance(t, str) and len(t) > 16

    def test_validate_valid_token(self, mgr):
        t    = mgr.create_session("u1", "127.0.0.1", "UA")
        sess = mgr.validate_session(t)
        assert sess is not None
        assert sess["user_id"] == "u1"

    def test_validate_unknown_token(self, mgr):
        assert mgr.validate_session("bad-token") is None

    def test_validate_none_and_empty(self, mgr):
        assert mgr.validate_session(None) is None
        assert mgr.validate_session("") is None

    def test_destroy_invalidates(self, mgr):
        t = mgr.create_session("u1", "127.0.0.1", "UA")
        mgr.destroy_session(t)
        assert mgr.validate_session(t) is None

    def test_expired_session_returns_none(self, tmp_path):
        store  = EncryptedStorage(str(tmp_path / "sk.key"))
        logger = SecurityLogger(str(tmp_path / "s.log"), str(tmp_path / "a.log"))
        sf = str(tmp_path / "sess.json")
        (tmp_path / "sess.json").write_text("{}")
        mgr2 = SessionManager(sf, session_timeout=1, storage=store, logger=logger)

        t = mgr2.create_session("u1", "127.0.0.1", "UA")
        data = store.load_json(sf)
        data[t]["last_activity"] = time.time() - 100
        store.save_json(sf, data)
        assert mgr2.validate_session(t) is None

    def test_cleanup_removes_expired(self, tmp_path):
        store  = EncryptedStorage(str(tmp_path / "sk.key"))
        logger = SecurityLogger(str(tmp_path / "s.log"), str(tmp_path / "a.log"))
        sf = str(tmp_path / "sess.json")
        (tmp_path / "sess.json").write_text("{}")
        mgr2 = SessionManager(sf, session_timeout=1, storage=store, logger=logger)

        t = mgr2.create_session("u1", "127.0.0.1", "UA")
        data = store.load_json(sf)
        data[t]["last_activity"] = time.time() - 100
        store.save_json(sf, data)

        mgr2.cleanup_expired()
        assert store.load_json(sf) == {}

    def test_validate_updates_last_activity(self, mgr):
        t      = mgr.create_session("u1", "127.0.0.1", "UA")
        before = mgr._load()[t]["last_activity"]
        time.sleep(0.05)
        mgr.validate_session(t)
        assert mgr._load()[t]["last_activity"] >= before

    def test_session_schema_fields(self, mgr):
        t    = mgr.create_session("u1", "10.0.0.1", "TestAgent/1.0")
        sess = mgr._load()[t]
        for field in ("token", "user_id", "created_at",
                      "last_activity", "ip_address", "user_agent"):
            assert field in sess, f"Missing field: {field}"
        assert isinstance(sess["created_at"], float)
        assert isinstance(sess["last_activity"], float)


# ---------------------------------------------------------------------------
# Integration tests via Flask routes
# ---------------------------------------------------------------------------

def _make_user_record(username, password):
    uid = str(uuid.uuid4())
    return uid, {
        "user_id":         uid,
        "username":        username,
        "email":           f"{username}@example.com",
        "password_hash":   hash_password(password),
        "role":            "user",
        "created_at":      time.time(),
        "failed_attempts": 0,
        "locked_until":    None,
        "last_login":      None,
        "is_active":       True,
    }


@pytest.fixture
def env(tmp_path):
    uid, user = _make_user_record("sessionuser", "Str0ng!Password#1")
    for name, content in (
        ("users.json", {uid: user}), ("sessions.json", {}),
        ("documents.json", {}), ("shares.json", {}), ("audit.json", []),
    ):
        (tmp_path / name).write_text(json.dumps(content))

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER":    str(tmp_path),
        "SESSION_TIMEOUT": 1800,
    })
    return {"tmp_path": tmp_path, "user_id": uid}


class TestSessionIntegration:
    def test_login_creates_server_session(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
        sessions = json.loads((env["tmp_path"] / "sessions.json").read_text())
        assert len(sessions) == 1

    def test_logout_removes_server_session(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            c.get("/logout")
        sessions = json.loads((env["tmp_path"] / "sessions.json").read_text())
        assert len(sessions) == 0

    def test_expired_session_denied(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            sessions = json.loads((env["tmp_path"] / "sessions.json").read_text())
            for token in sessions:
                sessions[token]["last_activity"] = time.time() - 99999
            (env["tmp_path"] / "sessions.json").write_text(json.dumps(sessions))
            r = c.get("/dashboard", follow_redirects=True)
            assert b"login" in r.data.lower()

    def test_server_side_revocation_denies_cookie(self, env):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            })
            (env["tmp_path"] / "sessions.json").write_text("{}")
            r = c.get("/dashboard", follow_redirects=True)
            assert b"login" in r.data.lower()

    def test_inactive_user_denied(self, env):
        users = json.loads((env["tmp_path"] / "users.json").read_text())
        for uid in users:
            users[uid]["is_active"] = False
        (env["tmp_path"] / "users.json").write_text(json.dumps(users))
        with app.test_client() as c:
            r = c.post("/login", data={
                "username": "sessionuser", "password": "Str0ng!Password#1",
            }, follow_redirects=True)
            assert b"deactivated" in r.data.lower()

    def test_cookie_config(self, env):
        assert app.config["SESSION_COOKIE_HTTPONLY"] is True
        assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
