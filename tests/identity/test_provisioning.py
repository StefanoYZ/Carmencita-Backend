from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import Base
from app.modules.identity.authorization import PERMISSION_ASSIGNABLE_ROLES, PERMISSION_CATALOG, ROLE_CATALOG
from app.modules.identity.models import Permission, Role
from scripts.provision_admin import _validate_mode, validate_identity
from scripts.sync_authorization_catalog import sync_authorization_catalog


def test_provisioning_normalizes_identity_and_enforces_password_strength() -> None:
    identity = validate_identity(
        " RootUser01 ",
        "+51999111222",
        "  Administradora   Raíz ",
        "a-strong-phrase-2026",
    )

    assert identity == ("rootuser01", "+51999111222", "Administradora Raíz")
    with pytest.raises(ValueError):
        validate_identity("root!", "51999111222", "Administradora", "a-strong-phrase-2026")
    with pytest.raises(ValueError):
        validate_identity("root01", "51999111222", "Administradora", "short")


def test_deployment_provisioning_requires_production_and_secret(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("ADMIN_PROVISIONING_TOKEN", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="ADMIN_PROVISIONING_TOKEN"):
            _validate_mode("deployment")
        monkeypatch.setenv("ADMIN_PROVISIONING_TOKEN", "deployment-token-" + "x" * 40)
        _validate_mode("deployment")
    finally:
        get_settings.cache_clear()


def test_development_provisioning_cannot_run_in_production(monkeypatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="development"):
            _validate_mode("development")
    finally:
        get_settings.cache_clear()


def test_provisioning_catalog_includes_the_agency_administrator() -> None:
    assert "AGENCY_ADMIN" in ROLE_CATALOG


def test_authorization_catalog_has_only_known_role_permissions() -> None:
    assert set(PERMISSION_ASSIGNABLE_ROLES) == set(PERMISSION_CATALOG)
    assert all(role_names <= set(ROLE_CATALOG) for role_names in PERMISSION_ASSIGNABLE_ROLES.values())
    assert all(
        role_names == frozenset({"ADMIN"})
        for role_names in PERMISSION_ASSIGNABLE_ROLES.values()
    )


def test_catalog_sync_preserves_database_managed_role_permission_assignments() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            now = datetime.now(UTC)
            for role_id, (role_name, description) in enumerate(ROLE_CATALOG.items(), start=1):
                session.add(
                    Role(
                        role_id=role_id,
                        role_name=role_name,
                        description=description,
                        is_active=True,
                        created_at=now,
                        updated_at=now,
                    )
                )
            for permission_id, (permission_name, description) in enumerate(PERMISSION_CATALOG.items(), start=1):
                session.add(
                    Permission(
                        permission_id=permission_id,
                        permission_name=permission_name,
                        description=description,
                        is_active=True,
                        created_at=now,
                        updated_at=now,
                    )
                )
            session.flush()
            secretary = session.scalar(select(Role).where(Role.role_name == "SECRETARY"))
            permission = session.scalar(select(Permission).where(Permission.permission_name == "USERS_READ"))
            secretary.permissions.append(permission)
            session.commit()

            sync_authorization_catalog(session)
            session.commit()

            secretary = session.scalar(
                select(Role)
                .where(Role.role_name == "SECRETARY")
                .options(selectinload(Role.permissions))
            )
            assert [assigned.permission_name for assigned in secretary.permissions] == ["USERS_READ"]

            admin = session.scalar(
                select(Role)
                .where(Role.role_name == "ADMIN")
                .options(selectinload(Role.permissions))
            )
            assert {assigned.permission_name for assigned in admin.permissions} == set(PERMISSION_CATALOG)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
