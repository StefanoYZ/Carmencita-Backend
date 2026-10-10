from fastapi import APIRouter, Depends, status

from app.core.database import DbSession
from app.core.errors import AUTH_FORBIDDEN, AUTH_REFRESH_UNAVAILABLE, AuthError
from app.modules.identity.dependencies import RefreshService, require_permission
from app.modules.identity.repository import get_user_with_access
from app.modules.identity.schemas import (
    ErrorResponse,
    PermissionResponse,
    RoleResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.modules.identity import management

users_router = APIRouter(prefix="/users", tags=["users"])
roles_router = APIRouter(prefix="/roles", tags=["roles"])
permissions_router = APIRouter(prefix="/permissions", tags=["permissions"])
MANAGEMENT_ERROR_RESPONSES = {
    401: {
        "model": ErrorResponse,
        "description": "Se requiere autenticación válida.",
    },
    403: {
        "model": ErrorResponse,
        "description": "La cuenta no tiene autorización para esta operación.",
    },
    404: {
        "model": ErrorResponse,
        "description": "No se encontró el recurso solicitado.",
    },
    409: {
        "model": ErrorResponse,
        "description": "La operación entra en conflicto con el estado actual.",
    },
    422: {
        "model": ErrorResponse,
        "description": "Uno o más campos de la solicitud no son válidos.",
    },
    503: {
        "model": ErrorResponse,
        "description": "El servicio de autenticación no está disponible.",
    },
}


@users_router.post(
    "",
    summary="Crear usuario con rol",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def create_user_endpoint(
    payload: UserCreate,
    session: DbSession,
    _current_user=Depends(require_permission("USERS_CREATE")),
    _role_assignment=Depends(require_permission("USERS_ASSIGN_ROLE")),
) -> UserResponse:
    return management.create_user(session, payload)


@users_router.get(
    "",
    summary="Listar usuarios internos",
    response_model=list[UserResponse],
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def list_users_endpoint(
    session: DbSession,
    _current_user=Depends(require_permission("USERS_READ")),
) -> list[UserResponse]:
    return management.list_users(session)


@users_router.get(
    "/{user_id}",
    summary="Consultar usuario interno",
    response_model=UserResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def get_user_endpoint(
    user_id: int,
    session: DbSession,
    _current_user=Depends(require_permission("USERS_READ")),
) -> UserResponse:
    return management.get_user(session, user_id)


@users_router.patch(
    "/{user_id}",
    summary="Actualizar usuario interno",
    response_model=UserResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
async def update_user_endpoint(
    user_id: int,
    payload: UserUpdate,
    session: DbSession,
    refresh_service: RefreshService,
    _current_user=Depends(require_permission("USERS_UPDATE")),
) -> UserResponse:
    target = get_user_with_access(session, user_id)
    if target is None:
        return management.get_user(session, user_id)
    if payload.is_active is False and target.role and target.role.role_name == "ADMIN":
        raise AuthError(
            AUTH_FORBIDDEN,
            "La cuenta raíz no se puede desactivar mediante la API.",
            status_code=403,
        )
    status_changed = payload.is_active is not None and payload.is_active != target.is_active
    password_changed = payload.password is not None
    if status_changed or password_changed:
        try:
            await refresh_service.revoke_user(str(user_id))
        except Exception as exc:
            raise AuthError(
                AUTH_REFRESH_UNAVAILABLE,
                "El servicio de autenticación no está disponible; la cuenta no se modificó.",
                status_code=503,
            ) from exc
    return management.update_user(session, user_id, payload)


@users_router.post(
    "/{user_id}/roles/{role_id}",
    summary="Asignar o cambiar rol",
    response_model=UserResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def assign_role_endpoint(
    user_id: int,
    role_id: int,
    session: DbSession,
    _current_user=Depends(require_permission("USERS_ASSIGN_ROLE")),
) -> UserResponse:
    return management.assign_role(session, user_id, role_id)


@roles_router.get(
    "",
    summary="Listar roles disponibles",
    response_model=list[RoleResponse],
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def list_roles_endpoint(
    session: DbSession,
    _current_user=Depends(require_permission("ROLES_READ")),
) -> list[RoleResponse]:
    return management.list_roles(session)


@roles_router.put(
    "/{role_id}/permissions/{permission_id}",
    summary="Asignar permiso al rol",
    response_model=RoleResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def assign_permission_to_role_endpoint(
    role_id: int,
    permission_id: int,
    session: DbSession,
    _current_user=Depends(require_permission("ROLES_PERMISSIONS_MANAGE")),
) -> RoleResponse:
    return management.assign_permission_to_role(session, role_id, permission_id)


@roles_router.delete(
    "/{role_id}/permissions/{permission_id}",
    summary="Retirar permiso del rol",
    response_model=RoleResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def remove_permission_from_role_endpoint(
    role_id: int,
    permission_id: int,
    session: DbSession,
    _current_user=Depends(require_permission("ROLES_PERMISSIONS_MANAGE")),
) -> RoleResponse:
    return management.remove_permission_from_role(session, role_id, permission_id)


@permissions_router.get(
    "",
    summary="Listar permisos disponibles",
    response_model=list[PermissionResponse],
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def list_permissions_endpoint(
    session: DbSession,
    _current_user=Depends(require_permission("PERMISSIONS_READ")),
) -> list[PermissionResponse]:
    return management.list_permissions(session)


@permissions_router.get(
    "/{permission_id}",
    summary="Consultar permiso disponible",
    response_model=PermissionResponse,
    responses=MANAGEMENT_ERROR_RESPONSES,
)
def get_permission_endpoint(
    permission_id: int,
    session: DbSession,
    _current_user=Depends(require_permission("PERMISSIONS_READ")),
) -> PermissionResponse:
    return management.get_permission(session, permission_id)
