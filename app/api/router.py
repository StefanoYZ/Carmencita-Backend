from fastapi import APIRouter

from app.modules.identity.management_router import permissions_router, roles_router, users_router
from app.modules.identity.router import router as identity_router


api_router = APIRouter()
api_router.include_router(identity_router)
api_router.include_router(users_router)
api_router.include_router(roles_router)
api_router.include_router(permissions_router)
