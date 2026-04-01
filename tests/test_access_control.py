"""Tests for access control: ownership, sharing, IDOR prevention."""
import json
import uuid
import pytest
from app import app, hash_password


@pytest.fixture
def env(tmp_path):
    """Set up two users and the app with isolated data directory."""
    user_a_id = str(uuid.uuid4())
    user_b_id = str(uuid.uuid4())
    users = {
        user_a_id: {
            "username": "alice",
            "password": hash_password("Str0ng!Password#1"),
            "role": "user",
            "created_at": "2024-01-01T00:00:00",
            "failed_logins": 0,
            "locked_until": None,
        },
        user_b_id: {
            "username": "bob",
            "password": hash_password("Str0ng!Password#2"),
            "role": "user",
            "created_at": "2024-01-01T00:00:00",
            "failed_logins": 0,
            "locked_until": None,
        },
    }
    (tmp_path / "users.json").write_text(json.dumps(users))
    (tmp_path / "sessions.json").write_text("{}")
    (tmp_path / "documents.json").write_text("{}")
    (tmp_path / "shares.json").write_text("{}")
    (tmp_path / "audit.json").write_text("[]")

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER": str(tmp_path),
        "UPLOAD_FOLDER": str(tmp_path),
    })

    return {"tmp_path": tmp_path, "user_a_id": user_a_id, "user_b_id": user_b_id}


def login_as(client, username, password):
    client.post("/login", data={"username": username, "password": password})


class TestUnauthenticatedAccess:
    def test_dashboard_redirects_to_login(self, env):
        with app.test_client() as c:
            r = c.get("/dashboard", follow_redirects=False)
            assert r.status_code == 302
            assert "/login" in r.headers["Location"]

    def test_upload_redirects_to_login(self, env):
        with app.test_client() as c:
            r = c.get("/upload", follow_redirects=False)
            assert r.status_code == 302

    def test_admin_redirects_to_login(self, env):
        with app.test_client() as c:
            r = c.get("/admin", follow_redirects=False)
            assert r.status_code == 302


class TestDocumentAccess:
    def _seed_doc(self, env, owner_id):
        doc_id = str(uuid.uuid4())
        docs = {doc_id: {
            "original_name": "secret.txt",
            "enc_filename":  doc_id + ".enc",
            "owner":         owner_id,
            "uploaded_at":   "2024-01-01T00:00:00",
            "size":          10,
            "checksum":      "abc",
        }}
        (env["tmp_path"] / "documents.json").write_text(json.dumps(docs))
        return doc_id

    def test_owner_can_view_own_document(self, env):
        doc_id = self._seed_doc(env, env["user_a_id"])
        with app.test_client() as c:
            login_as(c, "alice", "Str0ng!Password#1")
            r = c.get(f"/document/{doc_id}")
            assert r.status_code == 200

    def test_non_owner_cannot_view_document(self, env):
        doc_id = self._seed_doc(env, env["user_a_id"])
        with app.test_client() as c:
            login_as(c, "bob", "Str0ng!Password#2")
            r = c.get(f"/document/{doc_id}")
            assert r.status_code == 403

    def test_non_owner_cannot_delete_document(self, env):
        doc_id = self._seed_doc(env, env["user_a_id"])
        with app.test_client() as c:
            login_as(c, "bob", "Str0ng!Password#2")
            r = c.post(f"/document/{doc_id}/delete")
            assert r.status_code == 403

    def test_nonexistent_document_returns_404(self, env):
        with app.test_client() as c:
            login_as(c, "alice", "Str0ng!Password#1")
            r = c.get(f"/document/{uuid.uuid4()}")
            assert r.status_code == 404


class TestAdminAccess:
    def test_regular_user_cannot_access_admin(self, env):
        with app.test_client() as c:
            login_as(c, "alice", "Str0ng!Password#1")
            r = c.get("/admin")
            assert r.status_code == 403
