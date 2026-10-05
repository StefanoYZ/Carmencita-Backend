from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import json
from typing import Any

from redis.asyncio import Redis

from app.core.config import get_settings


def create_redis_client() -> Redis:
    return Redis.from_url(get_settings().redis_url, decode_responses=True)


@asynccontextmanager
async def redis_client() -> AsyncIterator[Redis]:
    client = create_redis_client()
    try:
        yield client
    finally:
        await client.aclose()


class RedisRefreshStore:
    """Redis-backed refresh store; token rotation is performed in one Lua operation."""

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

    async def create(self, token_hash: str, record: dict[str, str | int], ttl: int) -> None:
        await self.client.set(self._token_key(token_hash), json.dumps(record), ex=ttl)

    async def get(self, token_hash: str) -> dict[str, Any] | None:
        value = await self.client.get(self._token_key(token_hash))
        return json.loads(value) if value else None

    async def delete(self, token_hash: str) -> None:
        await self.client.delete(self._token_key(token_hash))

    async def mark_family_revoked(self, family_id: str, ttl: int) -> None:
        await self.client.set(self._family_key(family_id), "revoked", ex=ttl)

    async def is_family_revoked(self, family_id: str) -> bool:
        return bool(await self.client.exists(self._family_key(family_id)))

    async def get_epoch(self, user_id: str) -> int:
        value = await self.client.get(self._epoch_key(user_id))
        return int(value or 0)

    async def increment_epoch(self, user_id: str) -> int:
        return int(await self.client.incr(self._epoch_key(user_id)))

    async def rotate_atomically(
        self,
        old_hash: str,
        new_hash: str,
        new_record: dict[str, str | int],
        ttl: int,
    ) -> dict[str, Any] | None:
        script = """
        local old = redis.call('GET', KEYS[1])
        if not old then return false end
        local record = cjson.decode(old)
        if record['used'] == true then
            redis.call('SET', KEYS[2], 'revoked', 'EX', ARGV[2])
            return 'REUSED'
        end
        if redis.call('EXISTS', KEYS[2]) == 1 then return 'REVOKED' end
        record['used'] = true
        redis.call('SET', KEYS[1], cjson.encode(record), 'EX', ARGV[2])
        redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
        return old
        """
        result = await self.client.eval(
            script,
            3,
            self._token_key(old_hash),
            self._family_key(str(new_record["family_id"])),
            self._token_key(new_hash),
            json.dumps(new_record),
            ttl,
        )
        if result in (False, None, b"REVOKED", "REVOKED", b"REUSED", "REUSED"):
            return None
        if isinstance(result, bytes):
            result = result.decode()
        return json.loads(result)
