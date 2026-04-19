"""Tests for EncryptedStorage: encrypt/decrypt, JSON helpers, key management."""
import json
import pytest
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken

from security import EncryptedStorage


@pytest.fixture
def store(tmp_path):
    return EncryptedStorage(str(tmp_path / "secret.key"))


class TestKeyManagement:
    def test_key_file_is_created(self, tmp_path):
        key_file = tmp_path / "secret.key"
        assert not key_file.exists()
        EncryptedStorage(str(key_file))
        assert key_file.exists()

    def test_key_file_reloaded_on_reinit(self, tmp_path):
        key_file = tmp_path / "secret.key"
        s1 = EncryptedStorage(str(key_file))
        s2 = EncryptedStorage(str(key_file))
        # Both instances should decrypt data encrypted by the other
        ct = s1.encrypt_file(b"hello")
        assert s2.decrypt_file(ct) == b"hello"


class TestEncryptDecrypt:
    def test_encrypt_returns_bytes(self, store):
        assert isinstance(store.encrypt_file(b"data"), bytes)

    def test_roundtrip(self, store):
        data = b"sensitive document content"
        assert store.decrypt_file(store.encrypt_file(data)) == data

    def test_encrypted_output_differs_each_call(self, store):
        data = b"same input"
        assert store.encrypt_file(data) != store.encrypt_file(data)

    def test_tampered_ciphertext_raises(self, store):
        ct = store.encrypt_file(b"original")
        tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])
        with pytest.raises(Exception):
            store.decrypt_file(tampered)

    def test_encrypted_file_not_readable_as_plaintext(self, store):
        plaintext = b"sensitive document content"
        ct = store.encrypt_file(plaintext)
        assert plaintext not in ct
        assert b"sensitive" not in ct

    def test_wrong_key_raises(self, tmp_path):
        s1 = EncryptedStorage(str(tmp_path / "key1.key"))
        s2 = EncryptedStorage(str(tmp_path / "key2.key"))
        ct = s1.encrypt_file(b"secret")
        with pytest.raises(InvalidToken):
            s2.decrypt_file(ct)

    def test_empty_payload_roundtrip(self, store):
        assert store.decrypt_file(store.encrypt_file(b"")) == b""

    def test_large_payload_roundtrip(self, store):
        data = b"x" * (5 * 1024 * 1024)
        assert store.decrypt_file(store.encrypt_file(data)) == data


class TestSaveLoadJson:
    def test_save_and_load(self, store, tmp_path):
        path = str(tmp_path / "test.json")
        store.save_json(path, {"key": "value", "list": [1, 2, 3]})
        assert store.load_json(path) == {"key": "value", "list": [1, 2, 3]}

    def test_load_missing_returns_default(self, store, tmp_path):
        assert store.load_json(str(tmp_path / "missing.json"), default={}) == {}

    def test_load_empty_file_returns_default(self, store, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        assert store.load_json(str(p), default=[]) == []

    def test_load_corrupt_returns_default(self, store, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not valid json")
        assert store.load_json(str(p), default={"fallback": True}) == {"fallback": True}


class TestSaveLoadEncryptedJson:
    def test_encrypted_roundtrip(self, store, tmp_path):
        path = str(tmp_path / "enc.json")
        data = {"secret": "value", "users": ["alice", "bob"]}
        store.save_encrypted_json(path, data)
        assert store.load_encrypted_json(path) == data

    def test_encrypted_file_is_binary(self, store, tmp_path):
        path = tmp_path / "enc.json"
        store.save_encrypted_json(str(path), {"x": 1})
        raw = path.read_bytes()
        with pytest.raises(Exception):
            json.loads(raw)  # should not be valid JSON

    def test_wrong_key_returns_default(self, tmp_path):
        s1 = EncryptedStorage(str(tmp_path / "k1.key"))
        s2 = EncryptedStorage(str(tmp_path / "k2.key"))
        path = str(tmp_path / "enc.json")
        s1.save_encrypted_json(path, {"a": 1})
        assert s2.load_encrypted_json(path, default={"fallback": True}) == {"fallback": True}

    def test_load_missing_returns_default(self, store, tmp_path):
        result = store.load_encrypted_json(str(tmp_path / "no.json"), default={})
        assert result == {}


class TestUploadIntegration:
    def test_uploaded_file_stored_encrypted(self, tmp_path):
        import io
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
        from helpers import write_json
        from app import app

        for name, content in (
            ("users.json", {}), ("sessions.json", {}),
            ("documents.json", {}), ("shares.json", {}), ("audit.json", []),
        ):
            write_json(tmp_path / name, content)

        app.config.update({
            "TESTING":              True,
            "SESSION_COOKIE_SECURE": False,
            "DATA_FOLDER":          str(tmp_path),
            "UPLOAD_FOLDER":        str(tmp_path),
        })

        original = b"This is sensitive document content"
        with app.test_client() as c:
            c.post("/register", data={
                "username":         "tester",
                "email":            "t@example.com",
                "password":         "Str0ng!Password#1",
                "confirm_password": "Str0ng!Password#1",
            })
            c.post("/login", data={"username": "tester", "password": "Str0ng!Password#1"})
            c.post("/upload",
                   data={"file": (io.BytesIO(original), "test.txt")},
                   content_type="multipart/form-data")

        enc_files = list(tmp_path.glob("*.enc"))
        assert len(enc_files) == 1
        assert original not in enc_files[0].read_bytes()
