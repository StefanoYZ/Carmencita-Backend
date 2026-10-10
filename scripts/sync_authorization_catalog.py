from argparse import ArgumentParser
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.database import get_session_factory
from app.modules.identity.authorization import PERMISSION_CATALOG, ROLE_CATALOG
from app.modules.identity.models import Permission, Role


def sync_authorization_catalog(session: Session) -> dict[str, Role]:
    """Synchronize the approved catalog during an explicit administrative operation."""
    now = datetime.now(UTC)
    roles: dict[str, Role] = {}
    for role_name, description in ROLE_CATALOG.items():
        role = session.scalar(select(Role).where(Role.role_name == role_name))
        if role is None:
            role = Role(
                role_name=role_name,
                description=description,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            session.add(role)
        else:
            role.description = description
            role.is_active = True
            role.updated_at = now
        roles[role_name] = role

    permissions: dict[str, Permission] = {}
    for permission_name, description in PERMISSION_CATALOG.items():
        permission = session.scalar(select(Permission).where(Permission.permission_name == permission_name))
        if permission is None:
            permission = Permission(
                permission_name=permission_name,
                description=description,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            session.add(permission)
        else:
            permission.description = description
            permission.is_active = True
            permission.updated_at = now
        permissions[permission_name] = permission

    session.flush()
    # ADMIN keeps the full approved catalog. Other role-permission assignments
    # are managed in the database by authorized administrators and must survive sync.
    admin_role = roles["ADMIN"]
    admin_permissions = list(permissions.values())
    current_permission_ids = {permission.permission_id for permission in admin_role.permissions}
    catalog_permission_ids = {permission.permission_id for permission in admin_permissions}
    if current_permission_ids != catalog_permission_ids:
        admin_role.permissions = admin_permissions
        admin_role.updated_at = now
    return roles


def apply_authorization_catalog() -> None:
    session = get_session_factory()()
    try:
        with session.begin():
            session.execute(text("SELECT pg_advisory_xact_lock(7162439102242)"))
            sync_authorization_catalog(session)
    finally:
        session.close()


if __name__ == "__main__":
    ArgumentParser(description="Sincronizar el catalogo de autorizacion aprobado.").parse_args()
    apply_authorization_catalog()
    print("El catalogo de autorizacion se sincronizo correctamente.")
