import secrets
import bcrypt
from datetime import datetime, timedelta, timezone
from jose import jwt

SECRET_KEY = "controltrace-ai-dev-secret-change-in-production"
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, stored_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], stored_password.encode("utf-8"))
    except Exception:
        # fallback for any legacy plaintext rows
        return plain_password == stored_password


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=8)
    payload = {
        "sub": str(user_id),
        "exp": expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


ROLE_LABELS = {
    "org_admin": "Administrator",
    "auditor": "Auditor",
    "viewer": "Viewer",
}

# Which roles may access admin-only pages (user management, org settings)
ADMIN_ROLES = {"org_admin"}
# Which roles may edit records (create/update/delete) vs read-only viewers
EDITOR_ROLES = {"org_admin", "auditor"}
