from collections.abc import AsyncIterator, Callable
from typing import Annotated

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import get_settings
from app.core.database import DbSession
from app.core.errors import AUTHENTICATION_REQUIRED, AUTH_FORBIDDEN, AUTH_INVALID_TOKEN, AuthError
from app.core.redis import redis_client
from app.core.security import decode_access_token
from app.modules.identity.service import get_active_user
from app.modules.identity.token_service import RedisRefreshStore, RefreshTokenService

bearer_scheme = HTTPBearer(auto_error=False)


async def get_refresh_token_service() -> AsyncIterator[RefreshTokenService]:
    settings = get_settings()
    async with redis_client() as client:
        yield RefreshTokenService(RedisRefreshStore(client), settings.refresh_token_ttl_seconds)


RefreshService = Annotated[RefreshTokenService, Depends(get_refresh_token_service)]


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DbSession,
):
    get_settings().require_secure_secret_key()
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AuthError(AUTHENTICATION_REQUIRED, "Se requiere un token de acceso Bearer válido.", status_code=401)
    try:
        payload = decode_access_token(credentials.credentials)
        return get_active_user(session, str(payload["sub"]))
    except jwt.InvalidTokenError as exc:
        raise AuthError(AUTH_INVALID_TOKEN, "El token de acceso no es válido o ha vencido.", status_code=401) from exc
    except AuthError as exc:
        raise AuthError(AUTH_INVALID_TOKEN, "El token de acceso no es válido o ha vencido.", status_code=401) from exc


CurrentUser = Annotated[object, Depends(get_current_user)]


def require_permission(permission_code: str) -> Callable:
    def dependency(current_user=Depends(get_current_user)):
        role = current_user.role
        if role is None or not role.is_active:
            raise AuthError(
                AUTH_FORBIDDEN,
                "Tu cuenta no tiene el permiso necesario para esta operación.",
                status_code=403,
            )
        allowed_permissions = {
            permission.permission_name
            for permission in role.permissions
            if permission.is_active
        }
        if permission_code not in allowed_permissions:
            raise AuthError(
                AUTH_FORBIDDEN,
                "Tu cuenta no tiene el permiso necesario para esta operación.",
                status_code=403,
            )
        return current_user

    return dependency


def require_role(role_name: str) -> Callable:
    def dependency(current_user=Depends(get_current_user)):
        role = current_user.role
        if role is None or not role.is_active or role.role_name != role_name:
            raise AuthError(
                AUTH_FORBIDDEN,
                "Tu cuenta no tiene el rol necesario para esta operación.",
                status_code=403,
            )
        return current_user

    return dependency
