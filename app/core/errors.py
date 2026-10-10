import logging
import re
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
AUTH_INVALID_TOKEN = "AUTH_INVALID_TOKEN"
AUTH_REFRESH_UNAVAILABLE = "AUTH_REFRESH_UNAVAILABLE"
AUTH_REFRESH_REUSED = "AUTH_REFRESH_REUSED"
AUTH_FORBIDDEN = "AUTH_FORBIDDEN"
AUTH_RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
AUTH_CONFLICT = "RESOURCE_CONFLICT"
VALIDATION_ERROR = "VALIDATION_ERROR"
INTERNAL_ERROR = "INTERNAL_ERROR"

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


@dataclass(slots=True)
class AuthError(Exception):
    """Safe, client-facing application error with a stable machine code."""

    code: str
    message: str
    details: Any = None
    status_code: int = 400


def get_request_id(request: Request) -> str:
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        return request_id
    incoming = request.headers.get("X-Request-ID", "")
    request_id = incoming if _REQUEST_ID_PATTERN.fullmatch(incoming) else str(uuid4())
    request.state.request_id = request_id
    return request_id


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: Any = None,
) -> JSONResponse:
    request_id = get_request_id(request)
    return JSONResponse(
        status_code=status_code,
        headers={"X-Request-ID": request_id},
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details,
                "requestId": request_id,
            }
        },
    )


def register_error_handlers(application: FastAPI) -> None:
    @application.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        get_request_id(request)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @application.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        return error_response(
            request,
            status_code=exc.status_code,
            code=exc.code,
            message=exc.message,
            details=exc.details,
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        status_code = exc.status_code
        if status_code == 401:
            code, message = AUTHENTICATION_REQUIRED, "Se requiere una autenticación válida para continuar."
        elif status_code == 403:
            code, message = AUTH_FORBIDDEN, "No tienes autorización para realizar esta operación."
        elif status_code == 404:
            code, message = AUTH_RESOURCE_NOT_FOUND, "No se encontró el recurso solicitado."
        elif status_code == 409:
            code, message = AUTH_CONFLICT, "La solicitud entra en conflicto con el estado actual del recurso."
        else:
            code, message = f"HTTP_{status_code}", "No se pudo completar la solicitud."
        return error_response(request, status_code=status_code, code=code, message=message)

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = []
        for error in exc.errors():
            ignored_locations = {"body", "query", "path", "header", "cookie"}
            location = [
                str(part)
                for part in error.get("loc", ())
                if part not in ignored_locations
            ]
            details.append(
                {
                    "field": ".".join(location) if location else None,
                    "code": str(error.get("type", "invalid")),
                    "message": "El valor enviado no es válido.",
                }
            )
        return error_response(
            request,
            status_code=422,
            code=VALIDATION_ERROR,
            message="Uno o más campos de la solicitud no son válidos.",
            details=details,
        )

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = get_request_id(request)
        logger.error(
            "Fallo interno de solicitud; request_id=%s; error_type=%s",
            request_id,
            type(exc).__name__,
        )
        return error_response(
            request,
            status_code=500,
            code=INTERNAL_ERROR,
            message="Ocurrió un error inesperado en el servidor.",
        )
