# SecureWebApp: Secure Document Sharing System

## Setup Instructions
1. Python 3.10+ required
2. `pip install -r requirements.txt`
3. Run: `python app.py`
   - TLS cert is auto generated on first run
   - Only the first registered user receives admin role
4. Open: https://localhost:5000
   - Accept self signed certificate warning in browser

## Info
- `secret.key` Flask secret key is auto-generated if not set
- Password change available to logged in users
- Uploading new version of a file makes old version no longer viewable in app but it still exists in uploads folder
- Admin user can lockout other users for 1 year using admin page
- I made it so guest users must be created by signing in as admin and creating one from admin dashboard. Since guest account dont need email to register, attacker with distributed IPs could create mass guest accounts if I allow self registration.

## Running Tests
`python -m pytest tests/ -v`

## File Storage
- Uploaded files encrypted with Fernet before writing to disk
- Encryption key stored in secret.key (not committed)
- Multiple versions per document
- Deletion: metadata and audit history preserved in JSON store but all version files on disk are securely overwritten (random bytes, then zeroed) before being unlinked
