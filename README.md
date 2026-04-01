# SecureShare — Secure Document Sharing System

## Setup Instructions
1. Python 3.10+ required
2. `pip install -r requirements.txt`
3. Run: `python app.py`
   - TLS cert auto-generated on first run
   - First registered user receives admin role
4. Open: https://localhost:5000
   - Accept self-signed cert warning in browser

## Environment Variables
- `SECRET_KEY` — Flask secret key (auto-generated if not set)
- `FLASK_ENV` — set to `development` to disable HTTPS redirect

## Running Tests
`python -m pytest tests/ -v`

## Security Features
- bcrypt password hashing (cost=12)
- Fernet symmetric encryption for all uploaded files
- Session tokens: 32-byte cryptographically random
- Account lockout after 5 failed attempts (15 min)
- Rate limiting: 10 login attempts/IP/minute
- Role-based access control (admin, user, guest)
- All security events logged to logs/security.log
- Full audit trail in data/audit.json
- Security headers on all responses
- TLS enforced (self-signed cert for development)
- Input sanitization on all user-supplied data
- Path traversal prevention on all file operations

## File Storage
- Uploaded files encrypted with Fernet before writing to disk
- Encryption key stored in secret.key (never commit this file)
- Multiple versions retained; soft-delete only

## Default Roles
| Role  | Upload | Download Own | Download Shared | Admin Panel |
|-------|--------|--------------|-----------------|-------------|
| admin | ✓      | ✓            | ✓ (all)         | ✓           |
| user  | ✓      | ✓            | ✓ (shared only) | ✗           |
| guest | ✗      | ✗            | ✓ (shared only) | ✗           |