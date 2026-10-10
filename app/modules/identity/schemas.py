from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator


def to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class ApiSchema(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=False,
        str_strip_whitespace=False,
    )


class ApiResponseSchema(ApiSchema):
    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        validate_by_name=True,
    )


Username = Annotated[str, Field(min_length=1, max_length=30, pattern=r"^[A-Za-z0-9]+$")]
Phone = Annotated[str, Field(min_length=1, max_length=15, pattern=r"^[0-9+() -]+$")]
FullName = Annotated[str, Field(min_length=1, max_length=100)]
Password = Annotated[str, Field(min_length=8, max_length=30)]
RoleId = Annotated[int, Field(ge=1)]
AgencyId = Annotated[int, Field(ge=1, le=32767)]


class LoginRequest(ApiSchema):
    username: Username
    password: Annotated[str, Field(min_length=1, max_length=30)]


class AuthUserResponse(ApiResponseSchema):
    user_id: int
    agency_id: int | None
    username: str
    full_name: str
    roles: list[str]
    permissions: list[str]


class AuthResponse(ApiResponseSchema):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user: AuthUserResponse


class AccessTokenResponse(ApiResponseSchema):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class MeResponse(ApiResponseSchema):
    user: AuthUserResponse


class UserCreate(ApiSchema):
    username: Username
    phone: Phone
    password: Password
    full_name: FullName
    role_id: RoleId
    agency_id: AgencyId

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        return value.lower()

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("El teléfono es obligatorio.")
        return normalized

    @field_validator("full_name")
    @classmethod
    def normalize_full_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("El nombre completo es obligatorio.")
        return normalized


class UserUpdate(ApiSchema):
    phone: Phone | None = None
    password: Password | None = None
    full_name: FullName | None = None
    is_active: bool | None = None

    @field_validator("phone")
    @classmethod
    def normalize_optional_phone(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("El teléfono es obligatorio.")
        return normalized

    @field_validator("full_name")
    @classmethod
    def normalize_optional_full_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("El nombre completo es obligatorio.")
        return normalized


class UserResponse(ApiResponseSchema):
    user_id: int
    agency_id: int | None
    username: str
    full_name: str
    phone: str
    is_active: bool
    roles: list[str]
    permissions: list[str]

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        validate_by_name=True,
        from_attributes=True,
    )


class RoleResponse(ApiResponseSchema):
    role_id: int
    role_name: str
    description: str
    is_active: bool
    permissions: list[str]


class PermissionResponse(ApiResponseSchema):
    permission_id: int
    permission_name: str
    description: str
    is_active: bool


class ErrorDetail(ApiResponseSchema):
    field: str | None = None
    code: str
    message: str


class ErrorBody(ApiResponseSchema):
    code: str
    message: str
    details: list[ErrorDetail] | dict[str, str] | None = None
    request_id: str


class ErrorResponse(ApiResponseSchema):
    error: ErrorBody

    model_config = ConfigDict(
        alias_generator=to_camel,
        extra="forbid",
        populate_by_name=True,
        validate_by_name=True,
        json_schema_extra={
            "example": {
                "error": {
                    "code": "AUTH_INVALID_CREDENTIALS",
                    "message": "El usuario o la contraseña no son válidos.",
                    "details": [],
                    "requestId": "8d8aab9e-36e3-4b14-9d73-9af8b2f7c60a",
                }
            }
        },
    )
