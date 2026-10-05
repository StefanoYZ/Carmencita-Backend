import asyncio
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.errors import AUTH_REFRESH_REUSED, AuthError
from app.core.security import create_access_token, decode_access_token, hash_password, verify_password
from app.modules.identity.token_service import RefreshTokenService, hash_refresh_token


class FakeStore:
    def __init__(self):
        self.tokens = {}
        self.revoked = set()
        self.epochs = {}

    async def create(self, token_hash, record, ttl):
        self.tokens[token_hash] = ({**record, "used": False}, ttl)

    async def get(self, token_hash):
        return self.tokens.get(token_hash, (None,))[0]

    async def delete(self, token_hash):
        self.tokens.pop(token_hash, None)

    async def mark_family_revoked(self, family_id, ttl):
        self.revoked.add(family_id)

    async def is_family_revoked(self, family_id):
        return family_id in self.revoked

    async def get_epoch(self, user_id):
        return self.epochs.get(user_id, 0)

    async def increment_epoch(self, user_id):
        self.epochs[user_id] = await self.get_epoch(user_id) + 1
        return self.epochs[user_id]

    async def rotate_atomically(self, old_hash, new_hash, new_record, ttl):
        current = self.tokens.get(old_hash, (None,))[0]
        if current is None or new_record["family_id"] in self.revoked:
            return None
        if current.get("used") is True:
            self.revoked.add(current["family_id"])
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
