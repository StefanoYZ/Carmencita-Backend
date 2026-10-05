from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class AuthError(Exception):
    code: str
    message: str
    details: Any = None

    def as_dict(self, request_id: str | None = None) -> dict[str, object]:
        return {"error": {"code": self.code, "message": self.message, "details": self.details, "requestId": request_id}}


AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
AUTH_INVALID_TOKEN = "AUTH_INVALID_TOKEN"
AUTH_REFRESH_UNAVAILABLE = "AUTH_REFRESH_UNAVAILABLE"
AUTH_REFRESH_REUSED = "AUTH_REFRESH_REUSED"
AUTH_FORBIDDEN = "AUTH_FORBIDDEN"
VALIDATION_ERROR = "VALIDATION_ERROR"
