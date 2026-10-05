from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.config import get_settings
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.errors import AuthError, AUTH_INVALID_CREDENTIALS, AUTH_REFRESH_REUSED, AUTH_REFRESH_UNAVAILABLE
from app.core.redis import RedisRefreshStore, redis_client
from app.core.security import create_access_token
from app.modules.identity.schemas import AuthResponse, LoginRequest, MeResponse
from app.modules.identity.service import authenticate, get_active_user, issue_access_and_refresh, user_response
from app.modules.identity.token_service import RefreshTokenService

router = APIRouter(prefix="/auth", tags=["auth"])


def set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=settings.refresh_cookie_name,
        value=token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_same_site,
        path=f"{settings.api_prefix}/auth",
    )


@router.post("/login", response_model=AuthResponse)
async def login(payload: LoginRequest, response: Response, session=Depends(get_db)):
    try:
        user = authenticate(session, payload.username, payload.password)
        async with redis_client() as client:
            access_token, refresh = await issue_access_and_refresh(user, RefreshTokenService(RedisRefreshStore(client), get_settings().refresh_token_ttl_seconds))
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.as_dict()) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=AUTH_REFRESH_UNAVAILABLE) from exc
    set_refresh_cookie(response, refresh.token)
    return AuthResponse(access_token=access_token, user=user_response(user))


@router.post("/refresh", response_model=AuthResponse)
async def refresh(request: Request, response: Response, session=Depends(get_db)):
    settings = get_settings()
    token = request.cookies.get(settings.refresh_cookie_name)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=AUTH_REFRESH_REUSED)
    try:
        async with redis_client() as client:
            service = RefreshTokenService(RedisRefreshStore(client), settings.refresh_token_ttl_seconds)
            refreshed = await service.rotate(token)
            user = get_active_user(session, refreshed.user_id)
            access_token = create_access_token(refreshed.user_id)
    except AuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=exc.as_dict()) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=AUTH_REFRESH_UNAVAILABLE) from exc
    set_refresh_cookie(response, refreshed.token)
    return AuthResponse(access_token=access_token, user=user_response(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response):
    settings = get_settings()
    token = request.cookies.get(settings.refresh_cookie_name)
    if token:
        try:
            async with redis_client() as client:
                await RefreshTokenService(RedisRefreshStore(client), settings.refresh_token_ttl_seconds).revoke_token(token)
        except Exception:
            # Logout remains useful when Redis is unavailable: always clear the client cookie.
            pass
    response.delete_cookie(settings.refresh_cookie_name, path=f"{settings.api_prefix}/auth")


@router.get("/me", response_model=MeResponse)
def me(current_user=Depends(get_current_user)):
    return MeResponse(user=user_response(current_user))
