# SecureWebApp

A secure document storage and sharing web application built with Flask.

## Features

- User registration and login with bcrypt password hashing
- Account lockout after 5 failed login attempts (15-minute lockout)
- Server-side session management with expiry
- AES-256 (Fernet) file encryption at rest
- Role-based access control (user / admin)
- Time-limited document sharing between users
- Full audit log of all security events
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- TLS via self-signed certificate (auto-generated on startup)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Set as environment variable:
export ENCRYPTION_KEY=<key>
export SECRET_KEY=<random-hex>

# Run (TLS cert auto-generated on first start)
python app.py
```

Visit `https://localhost:5000`

## Running Tests

```bash
pytest tests/ -v --cov=app
```

## Project Structure

```
SecureWebApp/
├── app.py          # Main Flask application
├── config.py       # Configuration
├── requirements.txt
├── data/           # JSON data store
├── logs/           # Security and access logs
├── uploads/        # Encrypted files (.enc)
├── certs/          # TLS certificate and key
├── static/         # CSS and JS
├── templates/      # Jinja2 HTML templates
└── tests/          # Pytest test suite
```

## Security Notes

- Never commit `certs/`, `uploads/`, or `.env` files
- Set `ENCRYPTION_KEY` and `SECRET_KEY` via environment variables in production
- The self-signed certificate will trigger browser warnings — replace with a CA-signed cert for production
