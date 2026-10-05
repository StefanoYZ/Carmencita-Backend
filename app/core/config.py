from functools import lru_cache
from typing import Literal

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
    database_url: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def require_secure_secret_key(self) -> str:
        if self.jwt_secret_key is not None and self.secret_key is not None and self.jwt_secret_key.get_secret_value() != self.secret_key.get_secret_value():
            raise ValueError("JWT_SECRET_KEY and SECRET_KEY cannot contain different values")
        configured = self.jwt_secret_key or self.secret_key
        if configured is None:
            raise ValueError("JWT_SECRET_KEY must be configured before security operations")
        value = configured.get_secret_value()
        if len(value) < 32:
            raise ValueError("SECRET_KEY must contain at least 32 characters")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
