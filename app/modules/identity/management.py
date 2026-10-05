from datetime import UTC, datetime
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.security import hash_password
from app.modules.identity.models import InternalUser, Permission, Role
from app.modules.identity.schemas import PermissionCreate, PermissionResponse, RoleCreate, RoleResponse, UserCreate, UserResponse, UserUpdate


def _now() -> datetime:
    return datetime.now(UTC)


def _normalize_text(value: str) -> str:
    normalized = " ".join(value.strip().split())
    if not normalized:
        raise ValueError("Text fields cannot be empty")
    return normalized


def _user_response(user: InternalUser) -> UserResponse:
    role = user.role
    return UserResponse(user_id=user.user_id, username=user.username, full_name=user.full_name, phone=user.phone, is_active=user.is_active, roles=[role.role_name] if role and role.is_active else [], permissions=sorted({permission.permission_name for permission in role.permissions if role.is_active and permission.is_active}) if role else [])


def _role_response(role: Role) -> RoleResponse:
    return RoleResponse(role_id=role.role_id, role_name=role.role_name, description=role.description, is_active=role.is_active, permissions=sorted(permission.permission_name for permission in role.permissions if permission.is_active))


def create_user(session: Session, payload: UserCreate) -> UserResponse:
    username = payload.username.strip().lower()
    if not username or len(payload.password) < 8:
        raise ValueError("Username is required and password must contain at least 8 characters")
    if session.scalar(select(InternalUser).where(InternalUser.username == username)):
        raise ValueError("Username already exists")
    if session.scalar(select(InternalUser).where(InternalUser.phone == payload.phone.strip())):
        raise ValueError("Phone already exists")
    now = _now()
    user = InternalUser(username=username, password_hash=hash_password(payload.password), full_name=_normalize_text(payload.full_name), phone=payload.phone.strip(), is_active=True, created_at=now, updated_at=now)
    session.add(user)
    session.commit()
    return _user_response(user)


def list_users(session: Session) -> list[UserResponse]:
    users = session.scalars(select(InternalUser).options(selectinload(InternalUser.role).selectinload(Role.permissions))).all()
    return [_user_response(user) for user in users]


def get_user(session: Session, user_id: int) -> UserResponse | None:
    user = session.get(InternalUser, user_id)
    if user is None:
        return None
    return _user_response(user)


def update_user(session: Session, user_id: int, payload: UserUpdate) -> UserResponse | None:
    user = session.get(InternalUser, user_id)
    if user is None:
        return None
    if payload.phone is not None:
        user.phone = payload.phone.strip()
    if payload.password is not None:
        if len(payload.password) < 8:
            raise ValueError("Password must contain at least 8 characters")
        user.password_hash = hash_password(payload.password)
    if payload.full_name is not None:
        user.full_name = _normalize_text(payload.full_name)
    if payload.is_active is not None:
        user.is_active = payload.is_active
    user.updated_at = _now()
    session.commit()
    return _user_response(user)


def create_role(session: Session, payload: RoleCreate) -> RoleResponse:
    name = _normalize_text(payload.role_name).upper()
    if name not in {"ADMIN", "SECRETARY", "LOADER", "DRIVER"}:
        raise ValueError("Role is not defined in the ER catalog")
    if session.scalar(select(Role).where(Role.role_name == name)):
        raise ValueError("Role already exists")
    now = _now()
    role = Role(role_name=name, description=_normalize_text(payload.description or ""), is_active=True, created_at=now, updated_at=now)
    session.add(role)
    session.commit()
    return _role_response(role)


def list_roles(session: Session) -> list[RoleResponse]:
    roles = session.scalars(select(Role).options(selectinload(Role.permissions))).all()
    return [_role_response(role) for role in roles]


def assign_role(session: Session, user_id: int, role_id: int) -> UserResponse | None:
    user = session.get(InternalUser, user_id)
    role = session.get(Role, role_id)
    if user is None or role is None:
        return None
    user.role = role
    user.updated_at = _now()
    session.commit()
    return _user_response(user)


def assign_permission(session: Session, role_id: int, permission_id: int) -> RoleResponse | None:
    role = session.get(Role, role_id)
    permission = session.get(Permission, permission_id)
    if role is None or permission is None:
        return None
    if permission not in role.permissions:
        role.permissions.append(permission)
    role.updated_at = _now()
    session.commit()
    return _role_response(role)


def create_permission(session: Session, payload: PermissionCreate) -> PermissionResponse:
    name = payload.permission_name.strip().upper()
    if not name or session.scalar(select(Permission).where(Permission.permission_name == name)):
        raise ValueError("Permission code is empty or already exists")
    now = _now()
    permission = Permission(permission_name=name, description=_normalize_text(payload.description or ""), is_active=True, created_at=now, updated_at=now)
    session.add(permission)
    session.commit()
    return PermissionResponse(permission_id=permission.permission_id, permission_name=permission.permission_name, description=permission.description)
