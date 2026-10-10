from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.errors import (
    AUTH_CONFLICT,
    AUTH_FORBIDDEN,
    AUTH_RESOURCE_NOT_FOUND,
    VALIDATION_ERROR,
    AuthError,
)
from app.core.security import hash_password
from app.modules.identity.authorization import (
    OPERATIONAL_ROLE_NAMES,
    PERMISSION_ASSIGNABLE_ROLES,
    PERMISSION_CATALOG,
    ROLE_CATALOG,
)
from app.modules.identity.models import InternalUser, Permission, Role
from app.modules.identity.repository import get_user_with_access
from app.modules.identity.schemas import PermissionResponse, RoleResponse, UserCreate, UserResponse, UserUpdate
from app.modules.identity.service import user_response

def _now() -> datetime:
    return datetime.now(UTC)


def _user_response(user: InternalUser) -> UserResponse:
    auth_data = user_response(user)
    return UserResponse(
        user_id=user.user_id,
        agency_id=user.agency_id,
        username=user.username,
        full_name=user.full_name,
        phone=user.phone,
        is_active=user.is_active,
        roles=auth_data.roles,
        permissions=auth_data.permissions,
    )


def _role_response(role: Role) -> RoleResponse:
    return RoleResponse(
        role_id=role.role_id,
        role_name=role.role_name,
        description=role.description,
        is_active=role.is_active,
        permissions=sorted(
            permission.permission_name
            for permission in role.permissions
            if permission.is_active
        ),
    )


def _permission_response(permission: Permission) -> PermissionResponse:
    return PermissionResponse(
        permission_id=permission.permission_id,
        permission_name=permission.permission_name,
        description=permission.description,
        is_active=permission.is_active,
    )


def _get_user(session: Session, user_id: int) -> InternalUser:
    user = get_user_with_access(session, user_id)
    if user is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró el usuario solicitado.", status_code=404)
    return user


def create_user(session: Session, payload: UserCreate) -> UserResponse:
    username = payload.username.lower()
    phone = payload.phone
    if session.scalar(select(InternalUser.user_id).where(InternalUser.username == username)):
        raise AuthError(AUTH_CONFLICT, "Ya existe un usuario con ese nombre de acceso.", status_code=409)
    if session.scalar(select(InternalUser.user_id).where(InternalUser.phone == phone)):
        raise AuthError(AUTH_CONFLICT, "Ya existe un usuario con ese teléfono.", status_code=409)
    role = session.get(Role, payload.role_id)
    if role is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró el rol solicitado.", status_code=404)
    if role.role_name not in OPERATIONAL_ROLE_NAMES:
        raise AuthError(
            AUTH_FORBIDDEN,
            "Solo se pueden crear usuarios con roles operativos aprobados; ADMIN y AGENCY_ADMIN usan flujos controlados.",
            status_code=403,
        )
    if not role.is_active:
        raise AuthError(AUTH_CONFLICT, "No se puede asignar un rol inactivo.", status_code=409)
    agency_exists = session.execute(
        text("SELECT 1 FROM agencies WHERE agency_id = :agency_id"),
        {"agency_id": payload.agency_id},
    ).scalar_one_or_none()
    if agency_exists is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró la agencia solicitada.", status_code=404)
    now = _now()
    user = InternalUser(
        username=username,
        phone=phone,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        agency_id=payload.agency_id,
        role=role,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise AuthError(AUTH_CONFLICT, "El nombre de acceso o teléfono ya está registrado.", status_code=409) from exc
    return _user_response(get_user_with_access(session, user.user_id))


def list_users(session: Session) -> list[UserResponse]:
    statement = (
        select(InternalUser)
        .options(selectinload(InternalUser.role).selectinload(Role.permissions))
        .order_by(InternalUser.user_id)
    )
    return [_user_response(user) for user in session.scalars(statement).all()]


def get_user(session: Session, user_id: int) -> UserResponse:
    return _user_response(_get_user(session, user_id))


def update_user(session: Session, user_id: int, payload: UserUpdate) -> UserResponse:
    user = _get_user(session, user_id)
    if payload.is_active is False and user.role and user.role.role_name == "ADMIN":
        raise AuthError(AUTH_FORBIDDEN, "La cuenta raíz no se puede desactivar mediante la API.", status_code=403)

    if payload.phone is not None:
        duplicate = session.scalar(
            select(InternalUser.user_id).where(
                InternalUser.phone == payload.phone,
                InternalUser.user_id != user_id,
            )
        )
        if duplicate:
            raise AuthError(AUTH_CONFLICT, "Ya existe un usuario con ese teléfono.", status_code=409)
        user.phone = payload.phone
    if payload.password is not None:
        user.password_hash = hash_password(payload.password)
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
    user.updated_at = _now()
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise AuthError(AUTH_CONFLICT, "El teléfono ya está registrado para otra cuenta.", status_code=409) from exc
    return _user_response(get_user_with_access(session, user_id))

def list_roles(session: Session) -> list[RoleResponse]:
    statement = select(Role).options(selectinload(Role.permissions)).order_by(Role.role_id)
    return [_role_response(role) for role in session.scalars(statement).all()]


def list_permissions(session: Session) -> list[PermissionResponse]:
    permissions = session.scalars(select(Permission).order_by(Permission.permission_id)).all()
    return [_permission_response(permission) for permission in permissions]


def get_permission(session: Session, permission_id: int) -> PermissionResponse:
    permission = session.get(Permission, permission_id)
    if permission is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró el permiso solicitado.", status_code=404)
    return _permission_response(permission)


def _get_assignable_role_permission(
    session: Session,
    role_id: int,
    permission_id: int,
) -> tuple[Role, Permission]:
    role = session.scalar(
        select(Role)
        .where(Role.role_id == role_id)
        .options(selectinload(Role.permissions))
    )
    permission = session.get(Permission, permission_id)
    if role is None or permission is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró el rol o permiso solicitado.", status_code=404)
    if role.role_name == "ADMIN":
        raise AuthError(
            AUTH_FORBIDDEN,
            "Los permisos del rol ADMIN no se pueden modificar mediante la API.",
            status_code=403,
        )
    if role.role_name not in ROLE_CATALOG or permission.permission_name not in PERMISSION_CATALOG:
        raise AuthError(
            AUTH_FORBIDDEN,
            "Solo se pueden administrar asignaciones del catálogo aprobado.",
            status_code=403,
        )
    if role.role_name not in PERMISSION_ASSIGNABLE_ROLES.get(permission.permission_name, frozenset()):
        raise AuthError(
            AUTH_FORBIDDEN,
            "El permiso no está aprobado para el rol seleccionado.",
            status_code=403,
        )
    if not role.is_active or not permission.is_active:
        raise AuthError(AUTH_CONFLICT, "No se pueden asignar roles o permisos inactivos.", status_code=409)
    return role, permission


def assign_permission_to_role(session: Session, role_id: int, permission_id: int) -> RoleResponse:
    role, permission = _get_assignable_role_permission(session, role_id, permission_id)
    if permission not in role.permissions:
        role.permissions.append(permission)
        role.updated_at = _now()
        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            raise AuthError(AUTH_CONFLICT, "La asignación del permiso entró en conflicto.", status_code=409) from exc
    return _role_response(role)


def remove_permission_from_role(session: Session, role_id: int, permission_id: int) -> RoleResponse:
    role, permission = _get_assignable_role_permission(session, role_id, permission_id)
    if permission in role.permissions:
        role.permissions.remove(permission)
        role.updated_at = _now()
        session.commit()
    return _role_response(role)


def assign_role(session: Session, user_id: int, role_id: int) -> UserResponse:
    user = _get_user(session, user_id)
    role = session.get(Role, role_id)
    if role is None:
        raise AuthError(AUTH_RESOURCE_NOT_FOUND, "No se encontró el rol solicitado.", status_code=404)
    if user.role is not None and user.role.role_name == "ADMIN":
        raise AuthError(AUTH_FORBIDDEN, "El rol de la cuenta raíz no se puede cambiar mediante la API.", status_code=403)
    if role.role_name not in OPERATIONAL_ROLE_NAMES:
        raise AuthError(
            AUTH_FORBIDDEN,
            "Solo se pueden asignar roles operativos aprobados; ADMIN y AGENCY_ADMIN usan flujos controlados.",
            status_code=403,
        )
    if user.agency_id is None:
        raise AuthError(AUTH_CONFLICT, "El usuario debe pertenecer a una agencia antes de asignarle un rol operativo.", status_code=409)
    if not role.is_active:
        raise AuthError(AUTH_CONFLICT, "No se puede asignar un rol inactivo.", status_code=409)
    user.role = role
    user.updated_at = _now()
    session.commit()
    return _user_response(get_user_with_access(session, user_id))
