import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

from redis.asyncio import Redis

from app.core.errors import (
    AUTH_REFRESH_REUSED,
    AUTH_REFRESH_UNAVAILABLE,
    AuthError,
)


class RefreshStore(Protocol):
    async def create(self, token_hash: str, record: dict[str, str | int | bool], ttl: int) -> None: ...
    async def get(self, token_hash: str) -> dict[str, str | int | bool] | None: ...
    async def mark_family_revoked(self, family_id: str, ttl: int) -> None: ...
    async def get_epoch(self, user_id: str) -> int: ...
    async def increment_epoch(self, user_id: str, ttl: int) -> int: ...
    async def rotate_atomically(
        self,
        old_hash: str,
        new_hash: str,
        new_record: dict[str, str | int | bool],
        ttl: int,
    ) -> dict[str, str | int | bool] | None: ...


class RedisRefreshStore:
    """Redis adapter used exclusively by refresh-token rotation."""

    def __init__(self, client: Redis) -> None:
        self.client = client

    @staticmethod
    def _token_key(token_hash: str) -> str:
        return f"auth:refresh:{token_hash}"

    @staticmethod
    def _family_key(family_id: str) -> str:
        return f"auth:refresh:family:{family_id}"

    @staticmethod
    def _epoch_key(user_id: str) -> str:
        return f"auth:user:{user_id}:refreshEpoch"

    async def create(self, token_hash: str, record: dict[str, str | int | bool], ttl: int) -> None:
        await self.client.set(self._token_key(token_hash), json.dumps(record), ex=ttl)

    async def get(self, token_hash: str) -> dict[str, Any] | None:
        value = await self.client.get(self._token_key(token_hash))
        return json.loads(value) if value else None

    async def mark_family_revoked(self, family_id: str, ttl: int) -> None:
        await self.client.set(self._family_key(family_id), "revoked", ex=ttl)

    async def get_epoch(self, user_id: str) -> int:
        value = await self.client.get(self._epoch_key(user_id))
        return int(value or 0)

    async def increment_epoch(self, user_id: str, ttl: int) -> int:
        script = """
        local epoch = redis.call('INCR', KEYS[1])
        redis.call('EXPIRE', KEYS[1], ARGV[1])
        return epoch
        """
        return int(await self.client.eval(script, 1, self._epoch_key(user_id), ttl))

    async def rotate_atomically(
        self,
        old_hash: str,
        new_hash: str,
        new_record: dict[str, str | int | bool],
        ttl: int,
    ) -> dict[str, Any] | None:
        script = """
        local old = redis.call('GET', KEYS[1])
        if not old then return 'MISSING' end
        local record = cjson.decode(old)
        if record['used'] == true then
            redis.call('SET', KEYS[2], 'revoked', 'EX', ARGV[2])
            return 'REUSED'
        end
        if redis.call('EXISTS', KEYS[2]) == 1 then return 'REVOKED' end
        local epoch = tonumber(redis.call('GET', KEYS[4]) or '0')
        if tonumber(record['refresh_epoch']) ~= epoch then return 'REVOKED' end
        record['used'] = true
        local old_ttl = redis.call('TTL', KEYS[1])
        if old_ttl < 1 then return 'MISSING' end
        redis.call('SET', KEYS[1], cjson.encode(record), 'EX', old_ttl)
        redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
        return old
        """
        result = await self.client.eval(
            script,
            4,
            self._token_key(old_hash),
            self._family_key(str(new_record["family_id"])),
            self._token_key(new_hash),
            self._epoch_key(str(new_record["user_id"])),
            json.dumps(new_record),
            ttl,
        )
        if result in (False, None, b"MISSING", "MISSING", b"REVOKED", "REVOKED", b"REUSED", "REUSED"):
            if result in (b"REUSED", "REUSED"):
                return {"_status": "reused"}
            return None
        if isinstance(result, bytes):
            result = result.decode()
        return json.loads(result)


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
        await self.store.create(
            hash_refresh_token(token),
            {"user_id": user_id, "family_id": family, "refresh_epoch": epoch, "used": False},
            self.ttl_seconds,
        )
        return IssuedRefreshToken(token, family, user_id, epoch)

    async def rotate(self, token: str) -> IssuedRefreshToken:
        token_hash = hash_refresh_token(token)
        try:
            record = await self.store.get(token_hash)
        except Exception as exc:
            raise AuthError(
                AUTH_REFRESH_UNAVAILABLE,
                "El servicio de renovación no está disponible temporalmente.",
                status_code=503,
            ) from exc
        if record is None:
            raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
        family_id = str(record["family_id"])
        try:
            current_epoch = await self.store.get_epoch(str(record["user_id"]))
            if record.get("used") is True:
                await self.store.mark_family_revoked(family_id, self.ttl_seconds)
                raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
            if int(record["refresh_epoch"]) != current_epoch:
                raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
            new_token = secrets.token_urlsafe(48)
            new_hash = hash_refresh_token(new_token)
            new_record = {"user_id": str(record["user_id"]), "family_id": family_id, "refresh_epoch": current_epoch, "used": False}
            rotated = await self.store.rotate_atomically(token_hash, new_hash, new_record, self.ttl_seconds)
        except Exception as exc:
            if isinstance(exc, AuthError):
                raise
            raise AuthError(AUTH_REFRESH_UNAVAILABLE, "El servicio de renovación no está disponible temporalmente.", status_code=503) from exc
        if rotated is not None and rotated.get("_status") == "reused":
            raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
        if rotated is None:
            raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
        return IssuedRefreshToken(new_token, family_id, str(record["user_id"]), current_epoch)

    async def get_subject(self, token: str) -> str:
        try:
            record = await self.store.get(hash_refresh_token(token))
        except Exception as exc:
            raise AuthError(
                AUTH_REFRESH_UNAVAILABLE,
                "El servicio de renovación no está disponible temporalmente.",
                status_code=503,
            ) from exc
        if record is None:
            raise AuthError(AUTH_REFRESH_REUSED, "La sesión de renovación no es válida; inicia sesión nuevamente.", status_code=401)
        return str(record["user_id"])

    async def revoke_user(self, user_id: str) -> int:
        return await self.store.increment_epoch(user_id, self.ttl_seconds)

    async def revoke_token(self, token: str) -> None:
        record = await self.store.get(hash_refresh_token(token))
        if record is None:
            return
        await self.store.mark_family_revoked(str(record["family_id"]), self.ttl_seconds)
