"""Tests for access control: ownership, sharing roles, IDOR prevention."""
import io
import time
import uuid
import pytest
from app import app, hash_password, storage
from helpers import write_json, read_json


def _make_user(username, password, role="user"):
    uid = str(uuid.uuid4())
    return uid, {
        "user_id":         uid,
        "username":        username,
        "email":           f"{username}@example.com",
        "password_hash":   hash_password(password),
        "role":            role,
        "created_at":      time.time(),
        "failed_attempts": 0,
        "locked_until":    None,
        "last_login":      None,
        "is_active":       True,
    }


def _make_doc(owner_id, name="secret.pdf"):
    doc_id = str(uuid.uuid4())
    now    = time.time()
    stored_file = f"{doc_id}_v1.enc"
    return doc_id, {
        "doc_id":          doc_id,
        "original_name":   name,
        "stored_name":     doc_id,
        "owner_id":        owner_id,
        "uploaded_at":     now,
        "size_bytes":      42,
        "mime_type":       "application/pdf",
        "extension":       "pdf",
        "current_version": 1,
        "versions": [
            {
                "version":     1,
                "stored_file": stored_file,
                "uploaded_at": now,
                "uploaded_by": owner_id,
                "size_bytes":  42,
            }
        ],
        "is_deleted": False,
    }


@pytest.fixture
def env(tmp_path):
    alice_id, alice = _make_user("alice", "Str0ng!Password#1")
    bob_id,   bob   = _make_user("bob",   "Str0ng!Password#2")
    guest_id, guest = _make_user("guestuser", "Str0ng!Guest#123", role="guest")
    guest["email"] = ""

    write_json(tmp_path / "users.json", {alice_id: alice, bob_id: bob, guest_id: guest})
    for name, content in (
        ("sessions.json", {}), ("documents.json", {}),
        ("shares.json", {}),   ("audit.json", []),
    ):
        write_json(tmp_path / name, content)

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER":   str(tmp_path),
        "UPLOAD_FOLDER": str(tmp_path),
    })
    return {
        "tmp_path":   tmp_path,
        "alice_id":   alice_id, "alice_pass":   "Str0ng!Password#1",
        "bob_id":     bob_id,   "bob_pass":     "Str0ng!Password#2",
        "guest_id":   guest_id, "guest_pass":   "Str0ng!Guest#123",
    }


def login_as(client, username, password):
    client.post("/login", data={"username": username, "password": password})


class TestUnauthenticatedAccess:
    def test_dashboard_redirects(self, env):
        with app.test_client() as c:
            r = c.get("/dashboard", follow_redirects=False)
            assert r.status_code == 302
            assert "/login" in r.headers["Location"]

    def test_upload_redirects(self, env):
        with app.test_client() as c:
            assert c.get("/upload", follow_redirects=False).status_code == 302

    def test_admin_redirects(self, env):
        with app.test_client() as c:
            assert c.get("/admin", follow_redirects=False).status_code == 302


class TestDocumentOwnership:
    def _seed(self, env, owner_id):
        doc_id, doc = _make_doc(owner_id)
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        return doc_id

    def test_owner_can_view(self, env):
        doc_id = self._seed(env, env["alice_id"])
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            assert c.get(f"/document/{doc_id}").status_code == 200

    def test_non_owner_cannot_view(self, env):
        doc_id = self._seed(env, env["alice_id"])
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            assert c.get(f"/document/{doc_id}").status_code == 403

    def test_non_owner_cannot_delete(self, env):
        doc_id = self._seed(env, env["alice_id"])
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            assert c.post(f"/document/{doc_id}/delete").status_code == 403

    def test_soft_delete_hides_from_dashboard(self, env):
        doc_id = self._seed(env, env["alice_id"])
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            c.post(f"/document/{doc_id}/delete")
            docs = read_json(env["tmp_path"] / "documents.json")
            assert docs[doc_id]["is_deleted"] is True

    def test_missing_doc_returns_404(self, env):
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            assert c.get(f"/document/{uuid.uuid4()}").status_code == 404


def _enc_file(env, doc_id):
    enc = storage.encrypt_file(b"test content")
    (env["tmp_path"] / f"{doc_id}_v1.enc").write_bytes(enc)


class TestSharing:
    def _seed_share(self, env, doc_id, shared_with_id, role="viewer"):
        share_id = str(uuid.uuid4())
        write_json(env["tmp_path"] / "shares.json", {
            share_id: {
                "share_id":            share_id,
                "doc_id":              doc_id,
                "owner_id":            env["alice_id"],
                "shared_with_user_id": shared_with_id,
                "role":                role,
                "created_at":          time.time(),
                "granted_by":          env["alice_id"],
            }
        })

    def test_viewer_can_download(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        (env["tmp_path"] / f"{doc_id}_v1.enc").write_bytes(b"")
        self._seed_share(env, doc_id, env["bob_id"], role="viewer")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            assert c.get(f"/document/{doc_id}").status_code == 200

    def test_editor_can_view_version_upload_form(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        self._seed_share(env, doc_id, env["bob_id"], role="editor")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.get(f"/document/{doc_id}")
            assert b"Upload New Version" in r.data

    def test_viewer_cannot_see_version_upload_form(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        self._seed_share(env, doc_id, env["bob_id"], role="viewer")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.get(f"/document/{doc_id}")
            assert b"Upload New Version" not in r.data

    def test_download_own_document(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        _enc_file(env, doc_id)
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{doc_id}/download")
            assert r.status_code == 200
            assert r.data == b"test content"

    def test_download_shared_document(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        _enc_file(env, doc_id)
        self._seed_share(env, doc_id, env["bob_id"], role="viewer")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.get(f"/document/{doc_id}/download")
            assert r.status_code == 200

    def test_download_unshared_document(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            assert c.get(f"/document/{doc_id}/download").status_code == 403

    def test_editor_can_upload_version(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        self._seed_share(env, doc_id, env["bob_id"], role="editor")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.post(f"/document/{doc_id}/version",
                       data={"file": (io.BytesIO(b"new version"), "doc.txt")},
                       content_type="multipart/form-data")
            assert r.status_code in (200, 302)

    def test_viewer_cannot_upload_version(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        self._seed_share(env, doc_id, env["bob_id"], role="viewer")
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.post(f"/document/{doc_id}/version",
                       data={"file": (io.BytesIO(b"attempt"), "doc.txt")},
                       content_type="multipart/form-data")
            assert r.status_code == 403

    def test_share_schema_fields(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            c.post(f"/document/{doc_id}/share", data={
                "username": "bob",
                "role":     "editor",
            })
        shares = read_json(env["tmp_path"] / "shares.json")
        assert len(shares) == 1
        s = next(iter(shares.values()))
        for field in ("share_id", "doc_id", "owner_id",
                      "shared_with_user_id", "role", "created_at", "granted_by"):
            assert field in s, f"Missing field: {field}"
        assert s["role"] == "editor"
        assert isinstance(s["created_at"], float)


class TestAdminAccess:
    def test_regular_user_cannot_access_admin(self, env):
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            assert c.get("/admin").status_code == 403

    def test_admin_role_user_can_access_admin(self, env):
        users = read_json(env["tmp_path"] / "users.json")
        for uid in users:
            if users[uid]["username"] == "alice":
                users[uid]["role"] = "admin"
        write_json(env["tmp_path"] / "users.json", users)
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            assert c.get("/admin").status_code == 200


class TestGuestPermissions:
    def _seed_doc_with_share(self, env, role="viewer"):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        share_id = str(uuid.uuid4())
        write_json(env["tmp_path"] / "shares.json", {
            share_id: {
                "share_id":            share_id,
                "doc_id":              doc_id,
                "owner_id":            env["alice_id"],
                "shared_with_user_id": env["guest_id"],
                "role":                role,
                "created_at":          time.time(),
                "granted_by":          env["alice_id"],
            }
        })
        return doc_id

    def test_guest_can_view_shared_document(self, env):
        doc_id = self._seed_doc_with_share(env)
        with app.test_client() as c:
            login_as(c, "guestuser", env["guest_pass"])
            assert c.get(f"/document/{doc_id}").status_code == 200

    def test_guest_cannot_upload_document(self, env):
        with app.test_client() as c:
            login_as(c, "guestuser", env["guest_pass"])
            r = c.post("/upload",
                       data={"file": (io.BytesIO(b"data"), "test.txt")},
                       content_type="multipart/form-data")
            assert r.status_code == 403

    def test_guest_cannot_upload_version(self, env):
        doc_id = self._seed_doc_with_share(env, role="viewer")
        with app.test_client() as c:
            login_as(c, "guestuser", env["guest_pass"])
            r = c.post(f"/document/{doc_id}/version",
                       data={"file": (io.BytesIO(b"attempt"), "test.txt")},
                       content_type="multipart/form-data")
            assert r.status_code == 403

    def test_guest_cannot_delete_document(self, env):
        doc_id = self._seed_doc_with_share(env)
        with app.test_client() as c:
            login_as(c, "guestuser", env["guest_pass"])
            assert c.post(f"/document/{doc_id}/delete").status_code == 403

    def test_guest_cannot_access_admin(self, env):
        with app.test_client() as c:
            login_as(c, "guestuser", env["guest_pass"])
            assert c.get("/admin").status_code == 403

    def test_guest_share_as_editor_saved_as_viewer(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        write_json(env["tmp_path"] / "documents.json", {doc_id: doc})
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            c.post(f"/document/{doc_id}/share", data={
                "username": "guestuser",
                "role":     "editor",
            })
        shares = read_json(env["tmp_path"] / "shares.json")
        assert len(shares) == 1
        assert next(iter(shares.values()))["role"] == "viewer"
