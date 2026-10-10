"""Unit tests for password, access-token, and refresh-token primitives."""

import asyncio
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.errors import AUTH_REFRESH_REUSED, AUTH_REFRESH_UNAVAILABLE, AuthError
from app.core.security import create_access_token, decode_access_token, hash_password, verify_password
from app.modules.identity.token_service import RefreshTokenService, hash_refresh_token


class FakeStore:
    def __init__(self):
        self.tokens = {}
        self.revoked = set()
        self.epochs = {}
        self.epoch_ttls = {}

    async def create(self, token_hash, record, ttl):
        self.tokens[token_hash] = ({**record, "used": False}, ttl)

    async def get(self, token_hash):
        return self.tokens.get(token_hash, (None,))[0]

    async def mark_family_revoked(self, family_id, ttl):
        self.revoked.add(family_id)

    async def get_epoch(self, user_id):
        return self.epochs.get(user_id, 0)

    async def increment_epoch(self, user_id, ttl):
        self.epochs[user_id] = await self.get_epoch(user_id) + 1
        self.epoch_ttls[user_id] = ttl
        return self.epochs[user_id]

    async def rotate_atomically(self, old_hash, new_hash, new_record, ttl):
        current = self.tokens.get(old_hash, (None,))[0]
        if current is None or new_record["family_id"] in self.revoked:
            return None
        if current.get("used") is True:
            self.revoked.add(current["family_id"])
            return {"_status": "reused"}
        if current["refresh_epoch"] != self.epochs.get(current["user_id"], 0):
            return None
        self.tokens[old_hash] = ({**current, "used": True}, ttl)
        self.tokens[new_hash] = ({**new_record, "used": False}, ttl)
        return current


def test_password_hash_is_not_reversible():
    hashed = hash_password("secret")
    assert hashed != "secret"
    assert verify_password("secret", hashed)
    assert not verify_password("wrong", hashed)


def test_access_token_claims_and_expiry(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("SECRET_KEY", "x" * 32)
    get_settings.cache_clear()
    now = datetime.now(UTC)
    token = create_access_token("user-1", now=now)
    assert decode_access_token(token)["sub"] == "user-1"
    expired = create_access_token("user-1", now=now - timedelta(seconds=601))
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired)
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(f"{token[:-1]}x")
    get_settings.cache_clear()


def test_refresh_rotation_and_family_reuse():
    async def run():
        store = FakeStore()
        service = RefreshTokenService(store, ttl_seconds=100)
        issued = await service.issue("user-1")
        rotated = await service.rotate(issued.token)
        assert rotated.family_id == issued.family_id
        with pytest.raises(AuthError) as error:
            await service.rotate(issued.token)
        assert error.value.code == AUTH_REFRESH_REUSED
        assert issued.family_id in store.revoked

    asyncio.run(run())


def test_refresh_hash_is_one_way_shape():
    assert hash_refresh_token("token") != "token"


def test_refresh_only_stores_hash_with_seven_day_ttl():
    async def run():
        store = FakeStore()
        service = RefreshTokenService(store, ttl_seconds=604800)
        issued = await service.issue("user-1")
        digest = hash_refresh_token(issued.token)

        assert digest in store.tokens
        assert issued.token not in store.tokens
        assert store.tokens[digest][1] == 604800
        assert store.tokens[digest][0]["used"] is False

    asyncio.run(run())


def test_global_epoch_revocation_invalidates_all_refresh_tokens():
    async def run():
        store = FakeStore()
        service = RefreshTokenService(store, ttl_seconds=604800)
        first = await service.issue("user-1")
        second = await service.issue("user-1")
        assert await service.revoke_user("user-1") == 1
        assert store.epoch_ttls["user-1"] == 604800

        for token in (first.token, second.token):
            with pytest.raises(AuthError) as error:
                await service.rotate(token)
            assert error.value.code == AUTH_REFRESH_REUSED

    asyncio.run(run())


def test_reuse_revokes_the_entire_refresh_family():
    async def run():
        store = FakeStore()
        service = RefreshTokenService(store, ttl_seconds=604800)
        first = await service.issue("user-1")
        rotated = await service.rotate(first.token)

        with pytest.raises(AuthError) as reuse_error:
            await service.rotate(first.token)
        assert reuse_error.value.code == AUTH_REFRESH_REUSED
        assert first.family_id in store.revoked

        with pytest.raises(AuthError) as successor_error:
            await service.rotate(rotated.token)
        assert successor_error.value.code == AUTH_REFRESH_REUSED

    asyncio.run(run())


def test_redis_failure_fails_refresh_closed():
    async def run():
        class UnavailableStore(FakeStore):
            async def get(self, token_hash):
                raise ConnectionError("Redis unavailable")

        service = RefreshTokenService(UnavailableStore(), ttl_seconds=604800)
        with pytest.raises(AuthError) as error:
            await service.rotate("opaque-token")
        assert error.value.code == AUTH_REFRESH_UNAVAILABLE
        assert error.value.status_code == 503

    asyncio.run(run())
