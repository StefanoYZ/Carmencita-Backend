import hashlib
import secrets
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from app.core.errors import AUTH_REFRESH_REUSED, AUTH_REFRESH_UNAVAILABLE, AuthError


class RefreshStore(Protocol):
    async def create(self, token_hash: str, record: dict[str, str | int], ttl: int) -> None: ...
    async def get(self, token_hash: str) -> dict[str, str | int] | None: ...
    async def delete(self, token_hash: str) -> None: ...
    async def mark_family_revoked(self, family_id: str, ttl: int) -> None: ...
    async def is_family_revoked(self, family_id: str) -> bool: ...
    async def get_epoch(self, user_id: str) -> int: ...
    async def increment_epoch(self, user_id: str) -> int: ...
    async def rotate_atomically(self, old_hash: str, new_hash: str, new_record: dict[str, str | int], ttl: int) -> dict[str, str | int] | None: ...


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class IssuedRefreshToken:
    token: str
    family_id: str
    user_id: str
    refresh_epoch: int


class RefreshTokenService:
    def __init__(self, store: RefreshStore, ttl_seconds: int = 604800) -> None:
        self.store = store
        self.ttl_seconds = ttl_seconds

    async def issue(self, user_id: str, family_id: str | None = None) -> IssuedRefreshToken:
        token = secrets.token_urlsafe(48)
        family = family_id or str(uuid4())
        epoch = await self.store.get_epoch(user_id)
        await self.store.create(hash_refresh_token(token), {"user_id": user_id, "family_id": family, "refresh_epoch": epoch}, self.ttl_seconds)
        return IssuedRefreshToken(token, family, user_id, epoch)

    async def rotate(self, token: str) -> IssuedRefreshToken:
        token_hash = hash_refresh_token(token)
        try:
            record = await self.store.get(token_hash)
        except Exception as exc:
            raise AuthError(AUTH_REFRESH_UNAVAILABLE, "Refresh service unavailable") from exc
        if record is None:
            raise AuthError(AUTH_REFRESH_REUSED, "Refresh token is invalid or already used")
        family_id = str(record["family_id"])
        if await self.store.is_family_revoked(family_id):
            raise AuthError(AUTH_REFRESH_REUSED, "Refresh token family is revoked")
        current_epoch = await self.store.get_epoch(str(record["user_id"]))
        if record.get("used") is True:
            await self.store.mark_family_revoked(family_id, self.ttl_seconds)
            raise AuthError(AUTH_REFRESH_REUSED, "Refresh token has been reused")
        if int(record["refresh_epoch"]) != current_epoch:
            raise AuthError(AUTH_REFRESH_REUSED, "Refresh token has been revoked")
        new_token = secrets.token_urlsafe(48)
        new_hash = hash_refresh_token(new_token)
        new_record = {"user_id": str(record["user_id"]), "family_id": family_id, "refresh_epoch": current_epoch}
        rotated = await self.store.rotate_atomically(token_hash, new_hash, new_record, self.ttl_seconds)
        if rotated is None:
            raise AuthError(AUTH_REFRESH_REUSED, "Refresh token is invalid or already used")
        return IssuedRefreshToken(new_token, family_id, str(record["user_id"]), current_epoch)

    async def revoke_user(self, user_id: str) -> int:
        return await self.store.increment_epoch(user_id)

    async def revoke_family(self, family_id: str) -> None:
        await self.store.mark_family_revoked(family_id, self.ttl_seconds)
