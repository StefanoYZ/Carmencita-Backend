from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Carmencita Express Backend"
    api_prefix: str = "/api/v1"
    environment: Literal["development", "test", "production"] = "development"
    secret_key: SecretStr | None = None
    jwt_secret_key: SecretStr | None = None
    redis_url: str = "redis://localhost:6379/0"
    access_token_ttl_seconds: int = 600
    refresh_token_ttl_seconds: int = 604800
    refresh_cookie_name: str = "refresh_token"
    refresh_cookie_secure: bool = True
    refresh_cookie_same_site: Literal["lax", "strict", "none"] = "lax"
    refresh_cookie_domain: str | None = None
    cors_origins: str = "http://localhost:5173"
    database_url: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def require_secure_secret_key(self) -> str:
        if (
            self.jwt_secret_key is not None
            and self.secret_key is not None
            and self.jwt_secret_key.get_secret_value() != self.secret_key.get_secret_value()
        ):
            raise ValueError("JWT_SECRET_KEY y SECRET_KEY no pueden contener valores diferentes.")
        configured = self.jwt_secret_key or self.secret_key
        if configured is None:
            raise ValueError("Se debe configurar JWT_SECRET_KEY antes de usar operaciones protegidas.")
        value = configured.get_secret_value()
        if len(value) < 32:
            raise ValueError("JWT_SECRET_KEY debe contener al menos 32 caracteres.")
        insecure_examples = {
            "change_me",
            "changeme",
            "password",
            "secret",
            "replace-with-at-least-32-random-characters",
        }
        if value.lower() in insecure_examples:
            raise ValueError("JWT_SECRET_KEY debe reemplazarse por un secreto aleatorio.")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [
            origin.strip().rstrip("/")
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]

    def is_allowed_browser_origin(self, origin: str | None) -> bool:
        if origin is None:
            return False
        normalized = origin.rstrip("/")
        return normalized in self.cors_origin_list

    def validate_security_settings(self) -> None:
        self.require_secure_secret_key()
        if self.refresh_cookie_same_site == "none" and not self.refresh_cookie_secure:
            raise ValueError("SameSite=None requiere cookies Secure.")
        if self.environment == "production" and not self.refresh_cookie_secure:
            raise ValueError("Las cookies de refresh deben usar Secure en producción.")
        parsed = urlsplit(self.redis_url)
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("REDIS_URL debe usar redis:// o rediss:// e incluir un host.")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
