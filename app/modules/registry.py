from fastapi import FastAPI
from fastapi.routing import APIRouter

from app.core.config import get_settings

from app.modules.identity.management_router import permissions_router, roles_router, users_router
from app.modules.identity.router import router as identity_router


module_routers: tuple[APIRouter, ...] = (identity_router, users_router, roles_router, permissions_router)


def register_module_routers(application: FastAPI) -> None:
    """Register business routers when approved modules are added."""
    for router in module_routers:
        application.include_router(router, prefix=get_settings().api_prefix)
