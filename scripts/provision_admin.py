from argparse import ArgumentParser
from getpass import getpass
import os
import re
from datetime import UTC, datetime

from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.database import get_session_factory
from app.core.security import hash_password
from app.modules.identity.models import InternalUser
from scripts.sync_authorization_catalog import sync_authorization_catalog


def validate_identity(username: str, phone: str, full_name: str, password: str) -> tuple[str, str, str]:
    normalized_username = username.strip().lower()
    normalized_phone = phone.strip()
    normalized_name = " ".join(full_name.split())
    if re.fullmatch(r"[a-z0-9]{1,30}", normalized_username) is None:
        raise ValueError("El nombre de usuario debe contener entre 1 y 30 letras o números.")
    if re.fullmatch(r"[0-9+() -]{1,15}", normalized_phone) is None:
        raise ValueError("El teléfono debe tener hasta 15 caracteres numéricos o de formato telefónico.")
    if not normalized_name or len(normalized_name) > 100:
        raise ValueError("El nombre completo debe contener entre 1 y 100 caracteres.")
    if len(password) < 12 or len(password) > 128:
        raise ValueError("La contraseña del administrador debe contener entre 12 y 128 caracteres.")
    return normalized_username, normalized_phone, normalized_name


def provision_admin(
    username: str,
    phone: str,
    full_name: str,
    password: str,
    *,
    mode: str = "development",
) -> None:
    _validate_mode(mode)
    username, phone, full_name = validate_identity(username, phone, full_name, password)
    session = get_session_factory()()
    try:
        with session.begin():
            # Serialize concurrent attempts so only one provisioning operation can pass the empty-DB check.
            session.execute(text("SELECT pg_advisory_xact_lock(7162439102241)"))
            existing_users = session.scalar(select(func.count()).select_from(InternalUser))
            if existing_users:
                raise ValueError("El provisionamiento es de una sola ejecución: la base ya contiene un usuario interno.")

            now = datetime.now(UTC)
            roles = sync_authorization_catalog(session)

            root_user = InternalUser(
                username=username,
                phone=phone,
                full_name=full_name,
                password_hash=hash_password(password),
                is_active=True,
                created_at=now,
                updated_at=now,
                role=roles["ADMIN"],
            )
            session.add(root_user)
    finally:
        session.close()


def _validate_mode(mode: str) -> None:
    settings = get_settings()
    if mode == "development":
        if settings.environment != "development":
            raise ValueError("El provisionamiento de desarrollo solo se permite con ENVIRONMENT=development.")
        return
    if settings.environment != "production":
        raise ValueError("El provisionamiento de despliegue requiere ENVIRONMENT=production.")
    token = os.environ.get("ADMIN_PROVISIONING_TOKEN", "")
    if len(token) < 32:
        raise ValueError("El despliegue requiere el secreto protegido ADMIN_PROVISIONING_TOKEN.")


if __name__ == "__main__":
    parser = ArgumentParser(description="Provisionar una sola vez la cuenta administradora raíz inicial.")
    parser.add_argument("--mode", choices=("development", "deployment"), default="development")
    parser.add_argument("--username", required=True)
    parser.add_argument("--phone", required=True)
    parser.add_argument("--full-name", required=True)
    arguments = parser.parse_args()

    _validate_mode(arguments.mode)
    if arguments.mode == "deployment":
        password = os.environ.get("ADMIN_INITIAL_PASSWORD", "")
        if len(password) < 32:
            raise SystemExit("El despliegue requiere ADMIN_INITIAL_PASSWORD generado aleatoriamente con al menos 32 caracteres.")
    else:
        password = getpass("Contraseña del administrador inicial: ")
        confirmation = getpass("Repita la contraseña del administrador: ")
        if password != confirmation:
            raise SystemExit("Las contraseñas no coinciden.")
    provision_admin(
        arguments.username,
        arguments.phone,
        arguments.full_name,
        password,
        mode=arguments.mode,
    )
    print("La cuenta administradora raíz inicial se provisionó correctamente.")
