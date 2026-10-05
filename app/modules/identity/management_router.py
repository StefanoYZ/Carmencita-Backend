from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import require_permission
from app.modules.identity.management import assign_permission, assign_role, create_permission, create_role, create_user, get_user, list_roles, list_users, update_user
from app.modules.identity.schemas import PermissionCreate, PermissionResponse, RoleCreate, RoleResponse, UserCreate, UserResponse, UserUpdate

users_router = APIRouter(prefix="/users", tags=["users"])
roles_router = APIRouter(prefix="/roles", tags=["roles"])
permissions_router = APIRouter(prefix="/permissions", tags=["permissions"])


@users_router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user_endpoint(payload: UserCreate, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    try:
        return create_user(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@users_router.get("", response_model=list[UserResponse])
def list_users_endpoint(session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    return list_users(session)


@users_router.get("/{user_id}", response_model=UserResponse)
def get_user_endpoint(user_id: int, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    user = get_user(session, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@users_router.patch("/{user_id}", response_model=UserResponse)
def update_user_endpoint(user_id: int, payload: UserUpdate, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    try:
        user = update_user(session, user_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@users_router.post("/{user_id}/roles/{role_id}", response_model=UserResponse)
def assign_role_endpoint(user_id: int, role_id: int, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    user = assign_role(session, user_id, role_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User or role not found")
    return user


@roles_router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_role_endpoint(payload: RoleCreate, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    try:
        return create_role(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@roles_router.get("", response_model=list[RoleResponse])
def list_roles_endpoint(session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    return list_roles(session)


@roles_router.post("/{role_id}/permissions/{permission_id}", response_model=RoleResponse)
def assign_permission_endpoint(role_id: int, permission_id: int, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    role = assign_permission(session, role_id, permission_id)
    if role is None:
        raise HTTPException(status_code=404, detail="Role or permission not found")
    return role


@permissions_router.post("", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
def create_permission_endpoint(payload: PermissionCreate, session: Session = Depends(get_db), _=Depends(require_permission("MANAGE_USERS"))):
    try:
        return create_permission(session, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
