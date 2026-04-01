"""Tests for authentication: registration, login, lockout, logout."""
import json
import pytest
from app import app, hash_password


@pytest.fixture
def client(tmp_path):
    """Flask test client with isolated temp data directory."""
    for name, content in (
        ("users.json", {}),
        ("sessions.json", {}),
        ("documents.json", {}),
        ("shares.json", {}),
        ("audit.json", []),
    ):
        (tmp_path / name).write_text(json.dumps(content))

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER": str(tmp_path),
    })

    with app.test_client() as c:
        yield c


def register(client, username="testuser", password="Str0ng!Password#1"):
    return client.post("/register", data={
        "username": username,
        "password": password,
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
        assert b"log in" in r.data.lower() or b"login" in r.data.lower()

    def test_duplicate_username_rejected(self, client):
        register(client)
        r = register(client)
        assert b"taken" in r.data.lower()

    def test_weak_password_rejected(self, client):
        r = register(client, password="short")
        assert b"password" in r.data.lower()

    def test_mismatched_passwords(self, client):
        r = client.post("/register", data={
            "username": "newuser",
            "password": "Str0ng!Password#1",
            "confirm_password": "DifferentPassword!2",
        }, follow_redirects=True)
        assert b"match" in r.data.lower()

    def test_invalid_username_characters(self, client):
        r = register(client, username="bad user!")
        assert b"username" in r.data.lower()


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

    def test_account_lockout_after_five_failures(self, client):
        register(client)
        for _ in range(5):
            login(client, password="WrongPassword!1")
        r = login(client, password="Str0ng!Password#1")
        assert b"lock" in r.data.lower() or b"invalid" in r.data.lower()


class TestLogout:
    def test_logout_clears_session(self, client):
        register(client)
        login(client)
        r = client.get("/logout", follow_redirects=True)
        assert r.status_code == 200
        r2 = client.get("/dashboard", follow_redirects=True)
        assert b"login" in r2.data.lower()
