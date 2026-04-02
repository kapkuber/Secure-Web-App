"""
Tests for the audit trail system:
- audit() helper writes correct schema
- Per-document audit route (owner, admin, non-owner)
- Admin system audit route with user/event filters
- Share revocation writes SHARE_REVOKED audit entry
"""
import json
import time
import uuid
import pytest
from app import app, hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _make_doc(owner_id, name="test.pdf", deleted=False):
    doc_id = str(uuid.uuid4())
    now    = time.time()
    return doc_id, {
        "doc_id":          doc_id,
        "original_name":   name,
        "stored_name":     doc_id,
        "owner_id":        owner_id,
        "uploaded_at":     now,
        "size_bytes":      10,
        "mime_type":       "application/pdf",
        "extension":       "pdf",
        "current_version": 1,
        "versions": [{"version": 1, "stored_file": f"{doc_id}_v1.enc",
                      "uploaded_at": now, "uploaded_by": owner_id, "size_bytes": 10}],
        "is_deleted": deleted,
    }


def _make_share(doc_id, owner_id, shared_with_id, role="viewer"):
    share_id = str(uuid.uuid4())
    return share_id, {
        "share_id":            share_id,
        "doc_id":              doc_id,
        "owner_id":            owner_id,
        "shared_with_user_id": shared_with_id,
        "role":                role,
        "created_at":          time.time(),
        "granted_by":          owner_id,
    }


def _make_audit_entry(event_type, username="alice", doc_id=None, doc_name=None):
    return {
        "audit_id":   str(uuid.uuid4()),
        "timestamp":  "2024-01-01T12:00:00.000Z",
        "event_type": event_type,
        "user_id":    str(uuid.uuid4()),
        "username":   username,
        "doc_id":     doc_id,
        "doc_name":   doc_name,
        "ip_address": "127.0.0.1",
        "details":    {},
    }


@pytest.fixture
def env(tmp_path):
    alice_id, alice = _make_user("alice", "Str0ng!Password#1")
    bob_id,   bob   = _make_user("bob",   "Str0ng!Password#2")
    admin_id, admin = _make_user("admin", "Str0ng!Admin#123", role="admin")

    (tmp_path / "users.json").write_text(
        json.dumps({alice_id: alice, bob_id: bob, admin_id: admin})
    )
    for name, content in (
        ("sessions.json", {}), ("documents.json", {}),
        ("shares.json", {}),   ("audit.json", []),
    ):
        (tmp_path / name).write_text(json.dumps(content))

    app.config.update({
        "TESTING": True,
        "SESSION_COOKIE_SECURE": False,
        "DATA_FOLDER":   str(tmp_path),
        "UPLOAD_FOLDER": str(tmp_path),
    })
    return {
        "tmp_path":   tmp_path,
        "alice_id":   alice_id,  "alice_pass":   "Str0ng!Password#1",
        "bob_id":     bob_id,    "bob_pass":     "Str0ng!Password#2",
        "admin_id":   admin_id,  "admin_pass":   "Str0ng!Admin#123",
    }


def login_as(client, username, password):
    client.post("/login", data={"username": username, "password": password})


# ---------------------------------------------------------------------------
# Audit schema tests
# ---------------------------------------------------------------------------

class TestAuditSchema:
    def test_register_writes_audit_entry(self, env, tmp_path):
        with app.test_client() as c:
            c.post("/register", data={
                "username": "newuser", "email": "new@example.com",
                "password": "Str0ng!Pass#1", "confirm_password": "Str0ng!Pass#1",
            })
        entries = json.loads((tmp_path / "audit.json").read_text())
        assert len(entries) >= 1
        entry = entries[-1]
        for field in ("audit_id", "timestamp", "event_type", "user_id",
                      "username", "doc_id", "doc_name", "ip_address", "details"):
            assert field in entry, f"Missing audit field: {field}"

    def test_login_writes_audit_entry(self, env, tmp_path):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "alice", "password": "Str0ng!Password#1",
            })
        entries = json.loads((tmp_path / "audit.json").read_text())
        login_entries = [e for e in entries if e["event_type"] == "LOGIN_SUCCESS"]
        assert len(login_entries) >= 1

    def test_timestamp_iso_format(self, env, tmp_path):
        with app.test_client() as c:
            c.post("/login", data={
                "username": "alice", "password": "Str0ng!Password#1",
            })
        entries = json.loads((tmp_path / "audit.json").read_text())
        ts = entries[-1]["timestamp"]
        # Must match ISO8601 with milliseconds and Z suffix
        assert "T" in ts and ts.endswith("Z")
        assert len(ts) >= 20


# ---------------------------------------------------------------------------
# Per-document audit route
# ---------------------------------------------------------------------------

class TestDocumentAuditRoute:
    def _setup_doc(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        (env["tmp_path"] / "documents.json").write_text(
            json.dumps({doc_id: doc})
        )
        entries = [
            _make_audit_entry("FILE_UPLOAD",   "alice", doc_id, doc["original_name"]),
            _make_audit_entry("FILE_DOWNLOAD", "bob",   doc_id, doc["original_name"]),
            _make_audit_entry("LOGIN_SUCCESS", "alice", None,   None),  # unrelated
        ]
        (env["tmp_path"] / "audit.json").write_text(json.dumps(entries))
        return doc_id

    def test_owner_can_view_doc_audit(self, env):
        doc_id = self._setup_doc(env)
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        assert r.status_code == 200
        assert b"FILE_UPLOAD" in r.data
        assert b"FILE_DOWNLOAD" in r.data

    def test_non_owner_non_admin_denied(self, env):
        doc_id = self._setup_doc(env)
        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        assert r.status_code == 403

    def test_admin_can_view_any_doc_audit(self, env):
        doc_id = self._setup_doc(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        assert r.status_code == 200

    def test_only_doc_events_shown(self, env):
        doc_id = self._setup_doc(env)
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        # LOGIN_SUCCESS (no doc_id) must not appear
        assert b"LOGIN_SUCCESS" not in r.data

    def test_entries_sorted_newest_first(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        (env["tmp_path"] / "documents.json").write_text(
            json.dumps({doc_id: doc})
        )
        entries = [
            {**_make_audit_entry("FILE_UPLOAD",   "alice", doc_id, doc["original_name"]),
             "timestamp": "2024-01-01T10:00:00.000Z"},
            {**_make_audit_entry("FILE_DOWNLOAD", "alice", doc_id, doc["original_name"]),
             "timestamp": "2024-01-02T10:00:00.000Z"},
        ]
        (env["tmp_path"] / "audit.json").write_text(json.dumps(entries))
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        body = r.data.decode()
        assert body.index("FILE_DOWNLOAD") < body.index("FILE_UPLOAD")

    def test_missing_doc_returns_404(self, env):
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{uuid.uuid4()}/audit")
        assert r.status_code == 404

    def test_deleted_doc_still_accessible_to_owner(self, env):
        doc_id, doc = _make_doc(env["alice_id"], deleted=True)
        (env["tmp_path"] / "documents.json").write_text(
            json.dumps({doc_id: doc})
        )
        (env["tmp_path"] / "audit.json").write_text(
            json.dumps([_make_audit_entry("FILE_DELETE", "alice", doc_id)])
        )
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.get(f"/document/{doc_id}/audit")
        assert r.status_code == 200

    def test_unauthenticated_redirects(self, env):
        doc_id, doc = _make_doc(env["alice_id"])
        (env["tmp_path"] / "documents.json").write_text(
            json.dumps({doc_id: doc})
        )
        with app.test_client() as c:
            r = c.get(f"/document/{doc_id}/audit", follow_redirects=False)
        assert r.status_code == 302


# ---------------------------------------------------------------------------
# Admin system audit — filtering
# ---------------------------------------------------------------------------

class TestAdminAuditFilter:
    def _seed_entries(self, env):
        entries = [
            _make_audit_entry("FILE_UPLOAD",   "alice", str(uuid.uuid4()), "a.pdf"),
            _make_audit_entry("FILE_DOWNLOAD", "alice", str(uuid.uuid4()), "b.pdf"),
            _make_audit_entry("FILE_UPLOAD",   "bob",   str(uuid.uuid4()), "c.pdf"),
            _make_audit_entry("LOGIN_SUCCESS", "bob",   None,              None),
        ]
        (env["tmp_path"] / "audit.json").write_text(json.dumps(entries))

    def test_no_filter_shows_all(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit")
        assert r.status_code == 200
        assert b"FILE_UPLOAD" in r.data
        assert b"FILE_DOWNLOAD" in r.data
        assert b"LOGIN_SUCCESS" in r.data

    def test_filter_by_user(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit?user=alice")
        assert r.status_code == 200
        assert b"alice" in r.data
        # bob's LOGIN_SUCCESS should not appear
        assert b"LOGIN_SUCCESS" not in r.data

    def test_filter_by_event(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit?event=FILE_UPLOAD")
        assert r.status_code == 200
        assert b"FILE_UPLOAD" in r.data
        assert b"FILE_DOWNLOAD" not in r.data
        assert b"LOGIN_SUCCESS" not in r.data

    def test_filter_by_user_and_event(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit?user=alice&event=FILE_UPLOAD")
        assert r.status_code == 200
        assert b"alice" in r.data
        assert b"bob" not in r.data

    def test_filter_no_match_shows_empty(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit?user=nobody")
        assert r.status_code == 200
        assert b"No events" in r.data

    def test_non_admin_cannot_access(self, env):
        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            assert c.get("/admin/audit").status_code == 403

    def test_dropdown_options_populated(self, env):
        self._seed_entries(env)
        with app.test_client() as c:
            login_as(c, "admin", env["admin_pass"])
            r = c.get("/admin/audit")
        # Dropdowns should contain the known usernames and event types
        assert b"alice" in r.data
        assert b"bob"   in r.data
        assert b"FILE_UPLOAD" in r.data
        assert b"FILE_DOWNLOAD" in r.data


# ---------------------------------------------------------------------------
# Share revocation writes audit entry
# ---------------------------------------------------------------------------

class TestShareRevocationAudit:
    def test_revoke_writes_share_revoked_entry(self, env, tmp_path):
        doc_id,   doc   = _make_doc(env["alice_id"])
        share_id, share = _make_share(doc_id, env["alice_id"], env["bob_id"])
        (tmp_path / "documents.json").write_text(json.dumps({doc_id: doc}))
        (tmp_path / "shares.json").write_text(json.dumps({share_id: share}))

        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            r = c.post(f"/document/{doc_id}/share/{share_id}/revoke",
                       follow_redirects=True)
        assert r.status_code == 200

        entries = json.loads((tmp_path / "audit.json").read_text())
        revoke_entries = [e for e in entries if e["event_type"] == "SHARE_REVOKED"]
        assert len(revoke_entries) == 1
        e = revoke_entries[0]
        assert e["doc_id"] == doc_id
        assert e["details"]["share_id"] == share_id

    def test_revoke_removes_share_from_store(self, env, tmp_path):
        doc_id,   doc   = _make_doc(env["alice_id"])
        share_id, share = _make_share(doc_id, env["alice_id"], env["bob_id"])
        (tmp_path / "documents.json").write_text(json.dumps({doc_id: doc}))
        (tmp_path / "shares.json").write_text(json.dumps({share_id: share}))

        with app.test_client() as c:
            login_as(c, "alice", env["alice_pass"])
            c.post(f"/document/{doc_id}/share/{share_id}/revoke")
        shares = json.loads((tmp_path / "shares.json").read_text())
        assert share_id not in shares

    def test_non_owner_cannot_revoke(self, env, tmp_path):
        doc_id,   doc   = _make_doc(env["alice_id"])
        share_id, share = _make_share(doc_id, env["alice_id"], env["bob_id"])
        (tmp_path / "documents.json").write_text(json.dumps({doc_id: doc}))
        (tmp_path / "shares.json").write_text(json.dumps({share_id: share}))

        with app.test_client() as c:
            login_as(c, "bob", env["bob_pass"])
            r = c.post(f"/document/{doc_id}/share/{share_id}/revoke")
        assert r.status_code == 403
