from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.errors import AuthError
from app.core.security import decode_access_token
from app.modules.identity.service import get_active_user

bearer_scheme = HTTPBearer(auto_error=False)
DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    session: DbSession,
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = decode_access_token(credentials.credentials)
        return get_active_user(session, str(payload["sub"]))
    except (jwt.InvalidTokenError, ValueError, AuthError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication token") from None


def require_permission(permission_code: str):
    def dependency(current_user=Depends(get_current_user)):
        if current_user.role is not None and current_user.role.role_name == "ADMIN" and current_user.role.is_active:
            return current_user
        permissions = {permission.permission_name for permission in current_user.role.permissions if permission.is_active} if current_user.role and current_user.role.is_active else set()
        if permission_code not in permissions:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return current_user

    return dependency


def require_role(role_name: str):
    def dependency(current_user=Depends(get_current_user)):
        if current_user.role is None or current_user.role.role_name != role_name or not current_user.role.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return current_user

    return dependency
