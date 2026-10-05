from sqlalchemy.orm import Session

from app.core.errors import AUTH_INVALID_CREDENTIALS, AuthError
from app.core.security import create_access_token, verify_password
from app.modules.identity.repository import find_user_by_login, get_user_with_access
from app.modules.identity.schemas import AuthUserResponse
from app.modules.identity.token_service import IssuedRefreshToken, RefreshTokenService


def authenticate(session: Session, login: str, password: str):
    user = find_user_by_login(session, login)
    if user is None or not user.is_active or not verify_password(password, user.password_hash):
        raise AuthError(AUTH_INVALID_CREDENTIALS, "Invalid credentials")
    return user


def user_response(user) -> AuthUserResponse:
    role = user.role
    permissions = sorted({permission.permission_name for permission in role.permissions if role.is_active and permission.is_active}) if role else []
    roles = [role.role_name] if role and role.is_active else []
    return AuthUserResponse(
        user_id=user.user_id,
        username=user.username,
        full_name=user.full_name,
        phone=user.phone,
        is_active=user.is_active,
        roles=roles,
        permissions=permissions,
    )


def get_active_user(session: Session, user_id: str):
    try:
        parsed_id = int(user_id)
    except ValueError as exc:
        raise AuthError(AUTH_INVALID_CREDENTIALS, "Invalid user identity") from exc
    user = get_user_with_access(session, parsed_id)
    if user is None or not user.is_active:
        raise AuthError(AUTH_INVALID_CREDENTIALS, "User is inactive or unavailable")
    return user


async def issue_access_and_refresh(user, refresh_service: RefreshTokenService) -> tuple[str, IssuedRefreshToken]:
    return create_access_token(str(user.user_id)), await refresh_service.issue(str(user.user_id))
