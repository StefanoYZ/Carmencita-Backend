from fastapi import FastAPI
from fastapi.routing import APIRouter


module_routers: tuple[APIRouter, ...] = ()


def register_module_routers(application: FastAPI) -> None:
    """Register business routers when approved modules are added."""
    for router in module_routers:
        application.include_router(router)
