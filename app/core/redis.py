from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

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
