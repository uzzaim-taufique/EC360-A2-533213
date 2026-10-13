"""
QuickCart Microservices - Authentication Service
Jira Story: QM-5 - Customer Registration with Email Verification
"""
import hashlib
import hmac
import os
import re
import secrets
import time

SECRET_KEY = os.environ.get("QC_SECRET_KEY", "dev-secret-change-me").encode()
TOKEN_TTL_SECONDS = 24 * 60 * 60  # 24-hour verification token
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_users = {}  # in-memory store: email -> user record


def hash_password(password, salt=None):
    """PBKDF2-SHA256 password hashing with a random salt."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


def make_verification_token(email, issued_at=None):
    """Signed HMAC token: email|timestamp|signature."""
    issued_at = int(issued_at if issued_at is not None else time.time())
    msg = f"{email}|{issued_at}".encode()
    sig = hmac.new(SECRET_KEY, msg, hashlib.sha256).hexdigest()
    return f"{email}|{issued_at}|{sig}"


def register_user(email, password):
    """Returns (http_status, payload) mirroring the QM-5 acceptance criteria."""
    if not EMAIL_RE.match(email or ""):
        return 400, {"error": "Invalid email address"}
    if len(password or "") < 12:
        return 400, {"error": "Password must be at least 12 characters"}
    if email in _users:
        return 409, {"error": "An account with this email already exists"}

    _users[email] = {"password": hash_password(password), "verified": False}
    token = make_verification_token(email)
    # In production this is published to the email worker (SendGrid relay).
    return 201, {"status": "pending_verification", "verification_token": token}


def verify_email(token, now=None):
    try:
        email, issued_at, sig = token.split("|")
    except ValueError:
        return 400, {"error": "Malformed token"}
    expected = make_verification_token(email, int(issued_at)).split("|")[2]
    if not hmac.compare_digest(sig, expected):
        return 400, {"error": "Invalid token signature"}
    if (now or time.time()) - int(issued_at) > TOKEN_TTL_SECONDS:
        return 410, {"error": "Verification token expired"}
    if email not in _users:
        return 404, {"error": "User not found"}
    _users[email]["verified"] = True
    return 200, {"status": "verified"}