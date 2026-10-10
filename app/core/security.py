from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from app.core.config import get_settings

ALGORITHM = "HS256"
password_hash = PasswordHash.recommended()
_DUMMY_PASSWORD_HASH = password_hash.hash("not-a-real-user-password")


def dummy_password_hash() -> str:
    return _DUMMY_PASSWORD_HASH


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    try:
        return password_hash.verify(password, hashed_password)
    except (TypeError, ValueError, UnknownHashError):
        password_hash.verify(password, _DUMMY_PASSWORD_HASH)
        return False


def create_access_token(user_id: str, *, now: datetime | None = None) -> str:
    settings = get_settings()
    issued_at = now or datetime.now(UTC)
    payload = {
        "sub": user_id,
        "type": "access",
        "jti": str(uuid4()),
        "iat": issued_at,
        "exp": issued_at + timedelta(seconds=settings.access_token_ttl_seconds),
    }
    return jwt.encode(payload, settings.require_secure_secret_key(), algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, object]:
    payload = jwt.decode(
        token,
        get_settings().require_secure_secret_key(),
        algorithms=[ALGORITHM],
        options={"require": ["sub", "type", "jti", "iat", "exp"]},
        leeway=0,
    )
    if payload.get("type") != "access" or not isinstance(payload.get("sub"), str):
        raise jwt.InvalidTokenError("Las declaraciones del token de acceso no son válidas.")
    return payload
