from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health_check_does_not_open_database_or_redis_connections(monkeypatch) -> None:
    def unexpected_connection(*args, **kwargs):
        raise AssertionError("Health check must not connect to external services")

    monkeypatch.setattr("app.core.database.get_engine", unexpected_connection)
    monkeypatch.setattr("app.core.redis.create_redis_client", unexpected_connection)
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
    assert "/api/v1/permissions/{permission_id}" in paths
    assert "/api/v1/users/{user_id}/roles/{role_id}" in paths
    assert "delete" not in app.openapi()["paths"]["/api/v1/users/{user_id}/roles/{role_id}"]
    assert "/api/v1/roles/{role_id}" not in paths
    assert "/api/v1/roles/{role_id}/permissions/{permission_id}" in paths


def test_every_openapi_operation_has_a_valid_spanish_summary() -> None:
    expected_summaries = {
        ("post", "/api/v1/auth/login"): "Autenticar usuario interno",
        ("post", "/api/v1/auth/refresh"): "Renovar token de acceso",
        ("post", "/api/v1/auth/logout"): "Revocar familia de tokens",
        ("get", "/api/v1/auth/me"): "Consultar usuario autenticado",
        ("get", "/api/v1/users"): "Listar usuarios internos",
        ("post", "/api/v1/users"): "Crear usuario con rol",
        ("get", "/api/v1/users/{user_id}"): "Consultar usuario interno",
        ("patch", "/api/v1/users/{user_id}"): "Actualizar usuario interno",
        ("post", "/api/v1/users/{user_id}/roles/{role_id}"): "Asignar o cambiar rol",
        ("get", "/api/v1/roles"): "Listar roles disponibles",
        ("put", "/api/v1/roles/{role_id}/permissions/{permission_id}"): "Asignar permiso al rol",
        ("delete", "/api/v1/roles/{role_id}/permissions/{permission_id}"): "Retirar permiso del rol",
        ("get", "/api/v1/permissions"): "Listar permisos disponibles",
        ("get", "/api/v1/permissions/{permission_id}"): "Consultar permiso disponible",
        ("get", "/health"): "Verificar estado del servicio",
    }
    actual_summaries = {
        (method.lower(), path): operation.get("summary")
        for path, path_item in app.openapi()["paths"].items()
        for method, operation in path_item.items()
        if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
    }

    assert actual_summaries == expected_summaries
    assert all(len(summary.split()) <= 4 for summary in actual_summaries.values())
    assert all("endpoint" not in summary.casefold() for summary in actual_summaries.values())
