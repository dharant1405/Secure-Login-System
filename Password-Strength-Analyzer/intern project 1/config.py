import os
from datetime import timedelta

class Config:
    # SECRET_KEY is used for signing sessions and protecting against tampering.
    # In production, this should be a cryptographically secure random value loaded from environment variables.
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'SECURE_CSRF_TOKEN_SECRET_KEY_9c82b1ea734c56fd'

    # Database configuration
    DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database.db')

    # Secure Session Management Rules
    # Session cookie lifetime is set to 15 minutes to reduce session exposure window.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)

    # Prevent client-side scripts from reading the session cookie (Mitigates XSS-based session hijacking).
    SESSION_COOKIE_HTTPONLY = True

    # SameSite cookie policy helps defend against Cross-Site Request Forgery (CSRF).
    # 'Lax' is a good default that balances usability with security.
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Requires HTTPS to transmit the session cookie.
    # Must be set to True in production. Keep False for local development over HTTP.
    SESSION_COOKIE_SECURE = False
