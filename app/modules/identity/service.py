from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.errors import (
    AUTH_INVALID_CREDENTIALS,
    AUTH_REFRESH_UNAVAILABLE,
    AuthError,
)
from app.core.security import (
    create_access_token,
    dummy_password_hash,
    verify_password,
)
from app.modules.identity.models import InternalUser
from app.modules.identity.repository import find_user_by_login, get_user_with_access
from app.modules.identity.schemas import AuthUserResponse
from app.modules.identity.token_service import IssuedRefreshToken, RefreshTokenService


async def authenticate(
    session: Session,
    login: str,
    password: str,
    refresh_service: RefreshTokenService,
) -> InternalUser:
    user = find_user_by_login(session, login)
    stored_hash = user.password_hash if user is not None else dummy_password_hash()
    password_matches = verify_password(password, stored_hash)

    if user is not None and not user.is_active:
        try:
            await refresh_service.revoke_user(str(user.user_id))
        except Exception:
            # The inactive database flag already blocks protected requests and refresh.
            # Re-enabling the account performs another epoch increment before changing status.
            pass
        raise AuthError(
            AUTH_INVALID_CREDENTIALS,
            "El usuario o la contraseña no son válidos.",
            status_code=401,
        )

    if user is None or not password_matches or user.role is None or not user.role.is_active:
        raise AuthError(
            AUTH_INVALID_CREDENTIALS,
            "El usuario o la contraseña no son válidos.",
            status_code=401,
        )

    user.last_login_at = datetime.now(UTC)
    user.updated_at = user.last_login_at
    session.commit()
    return user


def user_response(user: InternalUser) -> AuthUserResponse:
    role = user.role
    permissions = (
        sorted(
            permission.permission_name
            for permission in role.permissions
            if role.is_active and permission.is_active
        )
        if role
        else []
    )
    roles = [role.role_name] if role and role.is_active else []
    return AuthUserResponse(
        user_id=user.user_id,
        agency_id=user.agency_id,
        username=user.username,
        full_name=user.full_name,
        roles=roles,
        permissions=permissions,
    )


def get_active_user(session: Session, user_id: str | int) -> InternalUser:
    try:
        parsed_id = int(user_id)
    except (TypeError, ValueError) as exc:
        raise AuthError(
            AUTH_INVALID_CREDENTIALS,
            "El token de autenticación no es válido.",
            status_code=401,
        ) from exc

    user = get_user_with_access(session, parsed_id)
    if user is None or not user.is_active or user.role is None or not user.role.is_active:
        raise AuthError(
            AUTH_INVALID_CREDENTIALS,
            "El token de autenticación no es válido.",
            status_code=401,
        )
    return user


async def issue_access_and_refresh(
    user: InternalUser,
    refresh_service: RefreshTokenService,
) -> tuple[str, IssuedRefreshToken]:
    refresh_token = await refresh_service.issue(str(user.user_id))
    access_token = create_access_token(str(user.user_id))
    return access_token, refresh_token
