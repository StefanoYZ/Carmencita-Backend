from fastapi import FastAPI

from app.api.router import api_router
from app.core.config import settings
from app.integrations.registry import register_integrations
from app.modules.registry import register_module_routers


app = FastAPI(title=settings.app_name)

app.include_router(api_router, prefix=settings.api_prefix)
register_module_routers(app)
register_integrations(app)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
