from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base, get_db
from app.modules.identity.dependencies import get_refresh_token_service
from app.core.security import hash_password
from app.main import app
from app.modules.identity import management
from app.modules.identity.models import InternalUser, Permission, Role
from app.modules.identity.token_service import RefreshTokenService


class FakeRefreshStore:
    def __init__(self) -> None:
        self.tokens: dict[str, tuple[dict[str, str | int | bool], int]] = {}
        self.revoked_families: set[str] = set()
        self.epochs: dict[str, int] = {}
        self.epoch_ttls: dict[str, int] = {}
        self.fail = False

    def _raise_if_unavailable(self) -> None:
        if self.fail:
            raise ConnectionError("fake Redis unavailable")

    async def create(self, token_hash, record, ttl) -> None:
        self._raise_if_unavailable()
        self.tokens[token_hash] = ({**record}, ttl)

    async def get(self, token_hash):
        self._raise_if_unavailable()
        value = self.tokens.get(token_hash)
        return dict(value[0]) if value else None

    async def mark_family_revoked(self, family_id, ttl) -> None:
        self._raise_if_unavailable()
        self.revoked_families.add(family_id)

    async def get_epoch(self, user_id) -> int:
        self._raise_if_unavailable()
        return self.epochs.get(user_id, 0)

    async def increment_epoch(self, user_id, ttl) -> int:
        self._raise_if_unavailable()
        self.epochs[user_id] = self.epochs.get(user_id, 0) + 1
        self.epoch_ttls[user_id] = ttl
        return self.epochs[user_id]

    async def rotate_atomically(self, old_hash, new_hash, new_record, ttl):
        self._raise_if_unavailable()
        current_pair = self.tokens.get(old_hash)
        if current_pair is None:
            return None
        current = current_pair[0]
        family = str(current["family_id"])
        if current.get("used"):
            self.revoked_families.add(family)
            return {"_status": "reused"}
        if family in self.revoked_families:
            return None
        if int(current["refresh_epoch"]) != self.epochs.get(str(current["user_id"]), 0):
            return None
        current["used"] = True
        self.tokens[old_hash] = (current, current_pair[1])
        self.tokens[new_hash] = ({**new_record}, ttl)
        return dict(current)


@pytest.fixture
def api_client() -> Iterator[tuple[TestClient, sessionmaker[Session], FakeRefreshStore]]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    # Isolated test-only schema; deployments use the explicit versioned SQL runner.
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE agencies (agency_id SMALLINT PRIMARY KEY)")
        connection.exec_driver_sql("INSERT INTO agencies (agency_id) VALUES (1)")
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    store = FakeRefreshStore()
    refresh_service = RefreshTokenService(store, ttl_seconds=604800)

    def override_database() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_database
    app.dependency_overrides[get_refresh_token_service] = lambda: refresh_service
    with TestClient(app, base_url="https://localhost") as client:
        yield client, session_factory, store
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def create_account(session_factory, *, active: bool = True) -> InternalUser:
    session = session_factory()
    role = Role(
        role_id=1,
        role_name="ADMIN",
        description="Administrador raíz",
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    permission_names = (
        "USERS_READ",
        "USERS_CREATE",
        "USERS_UPDATE",
        "USERS_ASSIGN_ROLE",
        "ROLES_READ",
        "ROLES_PERMISSIONS_MANAGE",
        "PERMISSIONS_READ",
    )
    role.permissions = [
        Permission(
            permission_id=index,
            permission_name=permission_name,
            description=f"Permiso de prueba {permission_name}",
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        for index, permission_name in enumerate(permission_names, start=1)
    ]
    user = InternalUser(
        username="root01",
        password_hash=hash_password("correct horse battery staple"),
        full_name="Administradora Raíz",
        phone="51999111222",
        is_active=active,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        role=role,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    session.close()
    return user


def test_login_returns_camel_case_and_sets_protected_cookie(api_client) -> None:
    client, session_factory, _ = api_client
    create_account(session_factory)

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accessToken"]
    assert body["tokenType"] == "Bearer"
    assert body["expiresIn"] == 600
    assert body["user"]["userId"] == 1
    assert body["user"]["fullName"] == "Administradora Raíz"
    assert "phone" not in body["user"]
    assert "passwordHash" not in body["user"]
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=lax" in cookie
    assert "refreshToken" not in body


def test_login_error_is_spanish_uniform_and_does_not_echo_credentials(api_client) -> None:
    client, _, _ = api_client

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "missinguser", "password": "my-private-password"},
        headers={"X-Request-ID": "test-request-42"},
    )

    assert response.status_code == 401
    assert response.headers["x-request-id"] == "test-request-42"
    assert response.json() == {
        "error": {
            "code": "AUTH_INVALID_CREDENTIALS",
            "message": "El usuario o la contraseña no son válidos.",
            "details": None,
            "requestId": "test-request-42",
        }
    }
    assert "my-private-password" not in response.text
    assert "missinguser" not in response.text


def test_validation_error_uses_camel_case_fields_and_spanish_message(api_client) -> None:
    client, _, _ = api_client

    response = client.post("/api/v1/auth/login", json={"username": "root01"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert "español" in error["message"] or "campos" in error["message"]
    assert all("input" not in item for item in error["details"])


def test_me_refresh_rotation_and_logout(api_client) -> None:
    client, session_factory, _ = api_client
    create_account(session_factory)
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    first_refresh_cookie = client.cookies.get("refresh_token")
    access_token = login.json()["accessToken"]

    me_response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["user"]["username"] == "root01"

    refresh_response = client.post("/api/v1/auth/refresh")
    assert refresh_response.status_code == 200
    assert refresh_response.json()["accessToken"] != access_token
    assert client.cookies.get("refresh_token") != first_refresh_cookie

    logout_response = client.post("/api/v1/auth/logout")
    assert logout_response.status_code == 204
    assert client.cookies.get("refresh_token") is None


def test_refresh_preserves_cookie_when_database_is_temporarily_unavailable(api_client, monkeypatch) -> None:
    client, session_factory, _ = api_client
    create_account(session_factory)
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    refresh_token = client.cookies.get("refresh_token")

    def unavailable_user_lookup(*args, **kwargs):
        raise OperationalError("SELECT", {}, ConnectionError("database unavailable"))

    monkeypatch.setattr("app.modules.identity.router.get_active_user", unavailable_user_lookup)
    unavailable = client.post("/api/v1/auth/refresh")

    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["code"] == "AUTH_REFRESH_UNAVAILABLE"
    assert client.cookies.get("refresh_token") == refresh_token

    monkeypatch.undo()
    recovered = client.post("/api/v1/auth/refresh")
    assert recovered.status_code == 200


def test_inactive_user_is_rejected_and_refresh_epoch_revoked(api_client) -> None:
    client, session_factory, store = api_client
    user = create_account(session_factory, active=False)

    response = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"
    assert store.epochs[str(user.user_id)] == 1


def test_management_requires_permission_and_rejects_admin_role_assignment(api_client) -> None:
    client, session_factory, _ = api_client
    root = create_account(session_factory)
    second = InternalUser(
        username="staff01",
        password_hash=hash_password("another secure password"),
        full_name="Personal Operativo",
        phone="51999111223",
        is_active=True,
        agency_id=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    session = session_factory()
    agency_admin_role = Role(
        role_id=2,
        role_name="AGENCY_ADMIN",
        description="Administrador de agencia",
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    secretary_role = Role(
        role_id=3,
        role_name="SECRETARY",
        description="Operaciones de agencia",
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    session.add(agency_admin_role)
    session.add(secretary_role)
    second.role = secretary_role
    session.add(second)
    session.commit()
    session.refresh(second)
    second_id = second.user_id
    session.close()

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    access_token = login.json()["accessToken"]
    headers = {"Authorization": f"Bearer {access_token}"}

    response = client.post(f"/api/v1/users/{second_id}/roles/1", headers=headers)
    assert response.status_code == 403
    assert "ADMIN" in response.json()["error"]["message"]

    agency_admin_assignment = client.post(f"/api/v1/users/{second_id}/roles/2", headers=headers)
    assert agency_admin_assignment.status_code == 403
    assert "AGENCY_ADMIN" in agency_admin_assignment.json()["error"]["message"]

    agency_admin_permission = client.put("/api/v1/roles/2/permissions/1", headers=headers)
    assert agency_admin_permission.status_code == 403

    root_permission_update = client.put("/api/v1/roles/1/permissions/1", headers=headers)
    assert root_permission_update.status_code == 403
    assert "ADMIN" in root_permission_update.json()["error"]["message"]

    user_list = client.get("/api/v1/users", headers=headers)
    assert user_list.status_code == 200
    assert user_list.json()[0]["userId"] == root.user_id
    assert "fullName" in user_list.json()[0]
    assert "full_name" not in user_list.json()[0]

    missing_user = client.get("/api/v1/users/99999", headers=headers)
    assert missing_user.status_code == 404
    assert missing_user.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


def test_admin_can_assign_and_revoke_catalog_permission_for_an_eligible_role(api_client, monkeypatch) -> None:
    client, session_factory, _ = api_client
    create_account(session_factory)
    secretary = Role(
        role_id=2,
        role_name="SECRETARY",
        description="Operaciones de agencia",
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    session = session_factory()
    session.add(secretary)
    session.commit()
    session.close()

    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    headers = {"Authorization": f"Bearer {login.json()['accessToken']}"}

    disallowed = client.put("/api/v1/roles/2/permissions/1", headers=headers)
    assert disallowed.status_code == 403

    monkeypatch.setitem(
        management.PERMISSION_ASSIGNABLE_ROLES,
        "USERS_READ",
        frozenset({"ADMIN", "SECRETARY"}),
    )
    assigned = client.put("/api/v1/roles/2/permissions/1", headers=headers)
    assert assigned.status_code == 200
    assert assigned.json()["permissions"] == ["USERS_READ"]

    listed_roles = client.get("/api/v1/roles", headers=headers)
    assert listed_roles.status_code == 200
    secretary_response = next(role for role in listed_roles.json() if role["roleId"] == 2)
    assert secretary_response["permissions"] == ["USERS_READ"]

    removed = client.delete("/api/v1/roles/2/permissions/1", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["permissions"] == []

    repeated_removal = client.delete("/api/v1/roles/2/permissions/1", headers=headers)
    assert repeated_removal.status_code == 200
    assert repeated_removal.json()["permissions"] == []


def test_management_payloads_use_camel_case_and_responses_hide_password_hash(api_client) -> None:
    client, session_factory, _ = api_client
    create_account(session_factory)
    session = session_factory()
    session.add_all(
        [
            Role(
                role_id=2,
                role_name="SECRETARY",
                description="Operaciones de agencia",
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            ),
            Role(
                role_id=3,
                role_name="LOADER",
                description="Operaciones de carga",
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            ),
        ]
    )
    session.commit()
    session.close()
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    headers = {"Authorization": f"Bearer {login.json()['accessToken']}"}

    missing_role = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff02",
            "phone": "51999111224",
            "password": "another secure password",
            "fullName": "Personal sin rol",
            "agencyId": 1,
        },
    )
    assert missing_role.status_code == 422

    missing_agency = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff03",
            "phone": "51999111225",
            "password": "another secure password",
            "fullName": "Personal sin agencia",
            "roleId": 2,
        },
    )
    assert missing_agency.status_code == 422

    root_role_creation = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "admin02",
            "phone": "51999111226",
            "password": "another secure password",
            "fullName": "Administrador adicional",
            "roleId": 1,
            "agencyId": 1,
        },
    )
    assert root_role_creation.status_code == 403

    invalid_agency = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff04",
            "phone": "51999111227",
            "password": "another secure password",
            "fullName": "Personal de agencia inexistente",
            "roleId": 2,
            "agencyId": 999,
        },
    )
    assert invalid_agency.status_code == 404

    created = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff01",
            "phone": "51999111223",
            "password": "pass-123",
            "fullName": "Personal Operativo",
            "roleId": 2,
            "agencyId": 1,
        },
    )
    assert created.status_code == 201
    assert created.json()["fullName"] == "Personal Operativo"
    assert created.json()["roles"] == ["SECRETARY"]
    assert created.json()["agencyId"] == 1
    assert "password" not in created.json()
    assert "passwordHash" not in created.json()

    changed_role = client.post(
        f"/api/v1/users/{created.json()['userId']}/roles/3",
        headers=headers,
    )
    assert changed_role.status_code == 200
    assert changed_role.json()["roles"] == ["LOADER"]
    assert changed_role.json()["agencyId"] == 1

    too_short_password = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff05",
            "phone": "51999111228",
            "password": "short7",
            "fullName": "Clave corta",
            "roleId": 2,
            "agencyId": 1,
        },
    )
    assert too_short_password.status_code == 422

    too_long_password = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff06",
            "phone": "51999111229",
            "password": "x" * 31,
            "fullName": "Clave larga",
            "roleId": 2,
            "agencyId": 1,
        },
    )
    assert too_long_password.status_code == 422

    invalid_legacy_case = client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": "staff02",
            "phone": "51999111224",
            "password": "another secure password",
            "full_name": "Personal Operativo",
            "roleId": 2,
            "agencyId": 1,
        },
    )
    assert invalid_legacy_case.status_code == 422
    assert invalid_legacy_case.json()["error"]["code"] == "VALIDATION_ERROR"


def test_deactivating_user_revokes_all_refresh_tokens(api_client) -> None:
    client, session_factory, store = api_client
    root = create_account(session_factory)
    staff = InternalUser(
        username="staff01",
        password_hash=hash_password("another secure password"),
        full_name="Personal Operativo",
        phone="51999111223",
        is_active=True,
        agency_id=1,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    session = session_factory()
    secretary_role = Role(
        role_id=2,
        role_name="SECRETARY",
        description="Operaciones de agencia",
        is_active=True,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    staff.role = secretary_role
    session.add(secretary_role)
    session.add(staff)
    session.commit()
    session.refresh(staff)
    staff_id = staff.user_id
    session.close()

    staff_login = client.post(
        "/api/v1/auth/login",
        json={"username": "staff01", "password": "another secure password"},
    )
    staff_access_token = staff_login.json()["accessToken"]
    staff_refresh_token = client.cookies.get("refresh_token")

    root_login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    headers = {"Authorization": f"Bearer {root_login.json()['accessToken']}"}
    response = client.patch(
        f"/api/v1/users/{staff_id}",
        headers=headers,
        json={"isActive": False},
    )

    assert response.status_code == 200
    assert response.json()["isActive"] is False
    assert store.epochs[str(staff_id)] == 1
    assert root.user_id == 1

    inactive_access = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {staff_access_token}"},
    )
    assert inactive_access.status_code == 401
    assert inactive_access.json()["error"]["code"] == "AUTH_INVALID_TOKEN"

    client.cookies.set("refresh_token", staff_refresh_token)
    inactive_refresh = client.post("/api/v1/auth/refresh")
    assert inactive_refresh.status_code == 401
    assert inactive_refresh.json()["error"]["code"] == "AUTH_INVALID_CREDENTIALS"


def test_logout_clears_cookie_even_when_redis_is_unavailable(api_client) -> None:
    client, session_factory, store = api_client
    create_account(session_factory)
    login = client.post(
        "/api/v1/auth/login",
        json={"username": "root01", "password": "correct horse battery staple"},
    )
    assert login.status_code == 200
    store.fail = True

    logout = client.post("/api/v1/auth/logout")

    assert logout.status_code == 204
    assert "max-age=0" in logout.headers["set-cookie"].lower()
