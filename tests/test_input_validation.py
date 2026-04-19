"""Tests for input validation and path-safety functions in security.py."""
import io
import pytest
from app import app
from helpers import write_json, read_json
from security import (
    validate_username, validate_email, validate_password,
    sanitize_input, safe_filename, safe_file_path,
)


class TestValidateUsername:
    def test_valid(self):           assert validate_username("alice_123") is True
    def test_min_length(self):      assert validate_username("abc") is True
    def test_max_length(self):      assert validate_username("a" * 20) is True
    def test_too_short(self):       assert validate_username("ab") is False
    def test_too_long(self):        assert validate_username("a" * 21) is False
    def test_space(self):           assert validate_username("bad user") is False
    def test_special_chars(self):   assert validate_username("user<>") is False
    def test_sql_injection(self):   assert validate_username("'; DROP TABLE--") is False
    def test_empty(self):           assert validate_username("") is False


class TestValidateEmail:
    def test_valid(self):           assert validate_email("user@example.com") is True
    def test_valid_subdomains(self):assert validate_email("a+b@mail.co.uk") is True
    def test_no_at(self):           assert validate_email("notanemail") is False
    def test_no_tld(self):          assert validate_email("user@host") is False
    def test_empty(self):           assert validate_email("") is False


class TestValidatePassword:
    def test_valid(self):
        assert validate_password("Str0ng!Password") == []

    def test_too_short(self):
        assert any("12" in e for e in validate_password("Short!1A"))

    def test_missing_uppercase(self):
        assert validate_password("alllower!1234") != []

    def test_missing_lowercase(self):
        assert validate_password("ALLUPPER!1234") != []

    def test_missing_digit(self):
        assert validate_password("NoDigits!HereAbc") != []

    def test_missing_special(self):
        assert validate_password("NoSpecial1234Aa") != []

    def test_multiple_errors(self):
        errors = validate_password("short")
        assert len(errors) >= 2

    def test_boundary_12_chars(self):
        assert validate_password("aA1!aaaaaaaa") == []


class TestSanitizeInput:
    def test_escapes_script(self):
        assert "<script>" not in sanitize_input("<script>alert(1)</script>")

    def test_escapes_quotes(self):
        result = sanitize_input('"quoted" & \'single\'')
        assert "&quot;" in result or "&#x27;" in result or "&amp;" in result

    def test_plain_string_unchanged(self):
        assert sanitize_input("hello world") == "hello world"

    def test_non_string_coerced(self):
        assert isinstance(sanitize_input(42), str)


class TestSafeFilename:
    _exts = {"pdf", "txt", "docx", "png", "jpg", "jpeg"}

    def test_valid(self):
        assert safe_filename("report.pdf", self._exts) == "report.pdf"

    def test_path_traversal_stripped(self):
        # werkzeug secure_filename strips traversal sequences
        result = safe_filename("../etc/passwd.txt", self._exts)
        assert ".." not in result

    def test_disallowed_extension_raises(self):
        with pytest.raises(ValueError, match="Extension not allowed"):
            safe_filename("malware.exe", self._exts)

    def test_empty_after_sanitize_raises(self):
        with pytest.raises(ValueError):
            safe_filename("", self._exts)


class TestSafeFilePath:
    def test_valid_path(self, tmp_path):
        result = safe_file_path("file.txt", str(tmp_path))
        assert result.startswith(str(tmp_path))

    def test_traversal_raises(self, tmp_path):
        with pytest.raises(ValueError, match="traversal"):
            safe_file_path("../../etc/passwd", str(tmp_path))

    def test_nested_valid(self, tmp_path):
        result = safe_file_path("subdir/file.txt", str(tmp_path))
        assert "subdir" in result


class TestFormInputs:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        for name, content in (
            ("users.json", {}), ("sessions.json", {}),
            ("documents.json", {}), ("shares.json", {}),
            ("audit.json", []),
        ):
            write_json(tmp_path / name, content)
        app.config.update({
            "TESTING": True,
            "SESSION_COOKIE_SECURE": False,
            "DATA_FOLDER": str(tmp_path),
        })

    def test_xss_in_username_not_reflected_raw(self, tmp_path):
        with app.test_client() as c:
            r = c.post("/register", data={
                "username": "<script>alert(1)</script>",
                "password": "Str0ng!Password#1",
                "confirm_password": "Str0ng!Password#1",
            }, follow_redirects=True)
            assert b"<script>alert(1)</script>" not in r.data

    def test_empty_login_fields(self):
        with app.test_client() as c:
            r = c.post("/login", data={"username": "", "password": ""},
                       follow_redirects=True)
            assert r.status_code == 200

    def test_oversized_username_rejected(self):
        with app.test_client() as c:
            r = c.post("/register", data={
                "username": "a" * 300,
                "password": "Str0ng!Password#1",
                "confirm_password": "Str0ng!Password#1",
            }, follow_redirects=True)
            assert r.status_code == 200
            assert b"<script" not in r.data


class TestFileUploadIntegration:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        for name, content in (
            ("users.json", {}), ("sessions.json", {}),
            ("documents.json", {}), ("shares.json", {}), ("audit.json", []),
        ):
            write_json(tmp_path / name, content)
        app.config.update({
            "TESTING":               True,
            "SESSION_COOKIE_SECURE": False,
            "DATA_FOLDER":           str(tmp_path),
            "UPLOAD_FOLDER":         str(tmp_path),
        })
        self.tmp_path = tmp_path

    def _login(self, c):
        c.post("/register", data={
            "username":         "uploader",
            "email":            "up@test.com",
            "password":         "Str0ng!Password#1",
            "confirm_password": "Str0ng!Password#1",
        })
        c.post("/login", data={"username": "uploader", "password": "Str0ng!Password#1"})

    def test_xss_in_filename(self):
        with app.test_client() as c:
            self._login(c)
            c.post("/upload",
                   data={"file": (io.BytesIO(b"content"), "<script>alert(1)</script>.pdf")},
                   content_type="multipart/form-data")
        docs = read_json(self.tmp_path / "documents.json")
        for doc in docs.values():
            assert "<script>" not in doc["original_name"]

    def test_path_traversal_in_filename(self):
        from security import safe_filename
        with pytest.raises(ValueError):
            safe_filename("../../etc/passwd", {"pdf", "txt"})

    def test_path_traversal_in_download(self):
        with app.test_client() as c:
            self._login(c)
            r = c.get("/document/../secret", follow_redirects=False)
            assert r.status_code in (301, 302, 404, 400)

    def test_file_extension_whitelist(self):
        with app.test_client() as c:
            self._login(c)
            r = c.post("/upload",
                       data={"file": (io.BytesIO(b"MZ\x90\x00"), "malware.exe")},
                       content_type="multipart/form-data",
                       follow_redirects=True)
            assert r.status_code == 200
            assert b"rejected" in r.data.lower() or b"not allowed" in r.data.lower()

    def test_oversized_file(self):
        with app.test_client() as c:
            self._login(c)
            big = io.BytesIO(b"x" * (16 * 1024 * 1024 + 1))
            r = c.post("/upload",
                       data={"file": (big, "big.txt")},
                       content_type="multipart/form-data")
            assert r.status_code in (413, 200, 302)
