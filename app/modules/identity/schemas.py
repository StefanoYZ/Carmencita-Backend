from pydantic import BaseModel


class AccessTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RefreshTokenRecord(BaseModel):
    token_hash: str
    family_id: str
    user_id: str
    refresh_epoch: int


class LoginRequest(BaseModel):
    username: str
    password: str


class AuthUserResponse(BaseModel):
    user_id: int
    username: str
    full_name: str
    phone: str
    is_active: bool
    roles: list[str]
    permissions: list[str]


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: AuthUserResponse


class MeResponse(BaseModel):
    user: AuthUserResponse


class UserCreate(BaseModel):
    username: str
    phone: str
    password: str
    full_name: str


class UserUpdate(BaseModel):
    phone: str | None = None
    password: str | None = None
    full_name: str | None = None
    is_active: bool | None = None


class UserResponse(AuthUserResponse):
    pass


class RoleCreate(BaseModel):
    role_name: str
    description: str | None = None


class PermissionCreate(BaseModel):
    permission_name: str
    description: str | None = None


class RoleResponse(BaseModel):
    role_id: int
    role_name: str
    description: str | None
    is_active: bool
    permissions: list[str]


class PermissionResponse(BaseModel):
    permission_id: int
    permission_name: str
    description: str | None
