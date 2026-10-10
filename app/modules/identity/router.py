from fastapi import APIRouter, Depends, Request, Response, status

from app.core.config import get_settings
from app.core.database import DbSession
from app.core.errors import (
    AUTHENTICATION_REQUIRED,
    AUTH_REFRESH_UNAVAILABLE,
    AUTH_FORBIDDEN,
    AuthError,
)
from app.modules.identity.dependencies import RefreshService, get_current_user
from app.core.security import create_access_token
from app.modules.identity.schemas import (
    AccessTokenResponse,
    AuthResponse,
    ErrorResponse,
    LoginRequest,
    MeResponse,
)
from app.modules.identity.service import (
    authenticate,
    get_active_user,
    issue_access_and_refresh,
    user_response,
)

router = APIRouter(prefix="/auth", tags=["auth"])
AUTH_ERROR_RESPONSES = {
    401: {
        "model": ErrorResponse,
        "description": "La autenticación no fue aceptada.",
    },
    403: {
        "model": ErrorResponse,
        "description": "El origen de la solicitud no está autorizado.",
    },
    422: {
        "model": ErrorResponse,
        "description": "La validación de la solicitud falló.",
    },
    503: {
        "model": ErrorResponse,
        "description": "Un servicio necesario para autenticarse no está disponible.",
    },
}
REFRESH_COOKIE_PARAMETER = {
    "name": "refresh_token",
    "in": "cookie",
    "required": True,
    "description": "Cookie HttpOnly y Secure emitida por login o refresh.",
    "schema": {"type": "string"},
}
REFRESH_COOKIE_HEADER = {
    "Set-Cookie": {
        "description": (
            "Cookie HttpOnly, Secure y SameSite=Lax que contiene el refresh "
            "token opaco."
        ),
        "schema": {"type": "string"},
    }
}


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_same_site,
        path=f"{settings.api_prefix}/auth",
        domain=settings.refresh_cookie_domain,
    )


def _clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=settings.refresh_cookie_name,
        path=f"{settings.api_prefix}/auth",
        domain=settings.refresh_cookie_domain,
        secure=settings.refresh_cookie_secure,
        httponly=True,
        samesite=settings.refresh_cookie_same_site,
    )


def _require_allowed_origin(request: Request) -> None:
    settings = get_settings()
    origin = request.headers.get("origin")
    if origin is not None and not settings.is_allowed_browser_origin(origin):
        raise AuthError(
            AUTH_FORBIDDEN,
            "El origen de este navegador no está autorizado.",
            status_code=403,
        )


@router.post(
    "/login",
    response_model=AuthResponse,
    responses={**AUTH_ERROR_RESPONSES, 200: {"headers": REFRESH_COOKIE_HEADER}},
    summary="Autenticar usuario interno",
    description=(
        "Autentica a una cuenta interna activa. El refresh token opaco se "
        "entrega únicamente en una cookie protegida."
    ),
)
async def login(
    payload: LoginRequest,
    response: Response,
    session: DbSession,
    refresh_service: RefreshService,
) -> AuthResponse:
    settings = get_settings()
    settings.validate_security_settings()
    user = await authenticate(session, payload.username, payload.password, refresh_service)
    try:
        access_token, refresh_token = await issue_access_and_refresh(user, refresh_service)
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError(
            AUTH_REFRESH_UNAVAILABLE,
            "El servicio de autenticación no está disponible temporalmente.",
            status_code=503,
        ) from exc
    _set_refresh_cookie(response, refresh_token.token)
    return AuthResponse(
        access_token=access_token,
        expires_in=get_settings().access_token_ttl_seconds,
        user=user_response(user),
    )


@router.post(
    "/refresh",
    response_model=AccessTokenResponse,
    responses={**AUTH_ERROR_RESPONSES, 200: {"headers": REFRESH_COOKIE_HEADER}},
    openapi_extra={"parameters": [REFRESH_COOKIE_PARAMETER]},
    summary="Renovar token de acceso",
    description="Rota el refresh token opaco recibido en la cookie HttpOnly y devuelve un nuevo access token.",
)
async def refresh(
    request: Request,
    response: Response,
    session: DbSession,
    refresh_service: RefreshService,
) -> AccessTokenResponse:
    _require_allowed_origin(request)
    settings = get_settings()
    settings.validate_security_settings()
    token = request.cookies.get(settings.refresh_cookie_name)
    if not token:
        raise AuthError(
            AUTHENTICATION_REQUIRED,
            "Se requiere la cookie de renovación de autenticación.",
            status_code=401,
        )
    try:
        user_id = await refresh_service.get_subject(token)
    except AuthError as exc:
        if exc.status_code == 401:
            _clear_refresh_cookie(response)
        raise
    try:
        user = get_active_user(session, user_id)
    except AuthError:
        _clear_refresh_cookie(response)
        try:
            await refresh_service.revoke_user(user_id)
        except Exception as exc:
            raise AuthError(
                AUTH_REFRESH_UNAVAILABLE,
                "El servicio de autenticación no está disponible temporalmente.",
                status_code=503,
            ) from exc
        raise
    except Exception as exc:
        raise AuthError(
            AUTH_REFRESH_UNAVAILABLE,
            "El servicio de autenticación no está disponible temporalmente.",
            status_code=503,
        ) from exc
    try:
        rotated = await refresh_service.rotate(token)
    except AuthError as exc:
        if exc.status_code == 401:
            _clear_refresh_cookie(response)
        raise
    access_token = create_access_token(str(user.user_id))
    _set_refresh_cookie(response, rotated.token)
    return AccessTokenResponse(
        access_token=access_token,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={403: AUTH_ERROR_RESPONSES[403]},
    openapi_extra={
        "parameters": [{**REFRESH_COOKIE_PARAMETER, "required": False}]
    },
    summary="Revocar familia de tokens",
    description=(
        "Revoca la familia del refresh token si Redis está disponible y siempre "
        "elimina la cookie del navegador."
    ),
)
async def logout(
    request: Request,
    response: Response,
    refresh_service: RefreshService,
) -> Response:
    _require_allowed_origin(request)
    settings = get_settings()
    token = request.cookies.get(settings.refresh_cookie_name)
    if token:
        try:
            await refresh_service.revoke_token(token)
        except Exception:
            # BD-018 requires the client cookie to be cleared even if Redis is unavailable.
            pass
    _clear_refresh_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get(
    "/me",
    response_model=MeResponse,
    responses={401: AUTH_ERROR_RESPONSES[401], 403: AUTH_ERROR_RESPONSES[403]},
    summary="Consultar usuario autenticado",
)
def me(current_user=Depends(get_current_user)) -> MeResponse:
    return MeResponse(user=user_response(current_user))
