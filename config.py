import os
import secrets

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = 'uploads'
    DATA_FOLDER = 'data'
    LOG_FOLDER = 'logs'
    CERT_FOLDER = 'certs'
    ALLOWED_EXTENSIONS = {'pdf', 'txt', 'docx', 'png', 'jpg', 'jpeg'}
    ALLOWED_MIME_TYPES = {
        'application/pdf', 'text/plain',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'image/png', 'image/jpeg'
    }
    SESSION_TIMEOUT = 1800     # 30 minutes
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    BCRYPT_ROUNDS = 12
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_DURATION = 900     # 15 minutes
    RATE_LIMIT_ATTEMPTS = 10
    RATE_LIMIT_WINDOW = 60      # seconds
    ENV = os.environ.get('FLASK_ENV', 'production')
