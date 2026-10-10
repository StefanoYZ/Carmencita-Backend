from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.errors import register_error_handlers


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="Carmencita Express Cargo internal API.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)
register_error_handlers(app)

app.include_router(api_router, prefix=settings.api_prefix)


@app.get("/health", tags=["system"], summary="Verificar estado del servicio")
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="localhost", port=8000, reload=False)
