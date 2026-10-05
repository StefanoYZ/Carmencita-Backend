from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_application_imports() -> None:
    assert app.title == "Carmencita Express Backend"


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Carmencita Express Backend",
    }


def test_auth_and_management_routes_are_registered() -> None:
    paths = set(app.openapi()["paths"])
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/auth/refresh" in paths
    assert "/api/v1/auth/me" in paths
    assert "/api/v1/users" in paths
    assert "/api/v1/roles" in paths
    assert "/api/v1/permissions" in paths
