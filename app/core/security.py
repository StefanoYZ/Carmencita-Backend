from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from pwdlib import PasswordHash

from app.core.config import get_settings

ALGORITHM = "HS256"
password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return password_hash.verify(password, hashed_password)


def create_access_token(user_id: str, *, now: datetime | None = None) -> str:
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    payload = {"sub": user_id, "type": "access", "jti": str(uuid4()), "iat": issued_at, "exp": issued_at + timedelta(seconds=settings.access_token_ttl_seconds)}
    return jwt.encode(payload, settings.require_secure_secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, object]:
    payload = jwt.decode(token, get_settings().require_secure_secret_key(), algorithms=[ALGORITHM], options={"require": ["sub", "type", "jti", "iat", "exp"]})
    if payload.get("type") != "access" or not isinstance(payload.get("sub"), str):
        raise jwt.InvalidTokenError("Invalid access token claims")
    return payload
