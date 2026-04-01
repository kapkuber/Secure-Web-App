"""Tests for authentication: registration, login, lockout, logout."""
import json
import time
import pytest
from app import app, hash_password


@pytest.fixture
def client(tmp_path):
    for name, content in (
        ("users.json", {}), ("sessions.json", {}),
        ("documents.json", {}), ("shares.json", {}), ("audit.json", []),
    ):
        (tmp_path / name).write_text(json.dumps(content))

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER": str(tmp_path),
    })
    with app.test_client() as c:
        yield c


def register(client, username="testuser", password="Str0ng!Password#1",
             email="test@example.com"):
    return client.post("/register", data={
        "username":         username,
        "email":            email,
        "password":         password,
        "confirm_password": password,
    }, follow_redirects=True)


def login(client, username="testuser", password="Str0ng!Password#1"):
    return client.post("/login", data={
        "username": username,
        "password": password,
    }, follow_redirects=True)


class TestRegistration:
    def test_successful_registration(self, client):
        r = register(client)
        assert r.status_code == 200
        assert b"login" in r.data.lower()

    def test_duplicate_username_rejected(self, client):
        register(client)
        r = register(client, email="other@example.com")
        assert b"taken" in r.data.lower()

    def test_duplicate_email_rejected(self, client):
        register(client)
        r = register(client, username="otheruser")
        assert b"email" in r.data.lower()

    def test_weak_password_rejected(self, client):
        r = register(client, password="short")
        assert b"password" in r.data.lower()

    def test_mismatched_passwords(self, client):
        r = client.post("/register", data={
            "username":         "newuser",
            "email":            "new@example.com",
            "password":         "Str0ng!Password#1",
            "confirm_password": "Different!Pass#2",
        }, follow_redirects=True)
        assert b"match" in r.data.lower()

    def test_invalid_username_characters(self, client):
        r = register(client, username="bad user!")
        assert b"username" in r.data.lower()

    def test_invalid_email_rejected(self, client):
        r = register(client, email="not-an-email")
        assert b"email" in r.data.lower()

    def test_user_record_schema(self, tmp_path, client):
        register(client)
        users = json.loads((tmp_path / "users.json").read_text())
        assert len(users) == 1
        u = next(iter(users.values()))
        for field in ("user_id", "username", "email", "password_hash",
                      "role", "created_at", "failed_attempts",
                      "locked_until", "last_login", "is_active"):
            assert field in u, f"Missing field: {field}"
        assert u["is_active"] is True
        assert u["failed_attempts"] == 0
        assert u["last_login"] is None
        assert isinstance(u["created_at"], float)


class TestLogin:
    def test_successful_login(self, client):
        register(client)
        r = login(client)
        assert r.status_code == 200
        assert b"dashboard" in r.data.lower() or b"upload" in r.data.lower()

    def test_wrong_password(self, client):
        register(client)
        r = login(client, password="WrongPassword!1")
        assert b"invalid" in r.data.lower()

    def test_nonexistent_user(self, client):
        r = login(client, username="nobody")
        assert b"invalid" in r.data.lower()

    def test_failed_attempts_incremented(self, tmp_path, client):
        register(client)
        login(client, password="WrongPassword!1")
        users = json.loads((tmp_path / "users.json").read_text())
        u = next(iter(users.values()))
        assert u["failed_attempts"] == 1

    def test_last_login_set_on_success(self, tmp_path, client):
        register(client)
        login(client)
        users = json.loads((tmp_path / "users.json").read_text())
        u = next(iter(users.values()))
        assert u["last_login"] is not None
        assert isinstance(u["last_login"], float)

    def test_account_lockout_after_five_failures(self, client):
        register(client)
        for _ in range(5):
            login(client, password="WrongPassword!1")
        r = login(client, password="Str0ng!Password#1")
        assert b"lock" in r.data.lower() or b"invalid" in r.data.lower()

    def test_locked_until_is_float_timestamp(self, tmp_path, client):
        register(client)
        for _ in range(5):
            login(client, password="WrongPassword!1")
        users = json.loads((tmp_path / "users.json").read_text())
        u = next(iter(users.values()))
        assert u["locked_until"] is not None
        assert isinstance(u["locked_until"], float)
        assert u["locked_until"] > time.time()


class TestLogout:
    def test_logout_clears_session(self, client):
        register(client)
        login(client)
        client.get("/logout", follow_redirects=True)
        r = client.get("/dashboard", follow_redirects=True)
        assert b"login" in r.data.lower()
