from argparse import ArgumentParser
from getpass import getpass
from sqlalchemy import select

from app.core.database import get_session_factory
from app.core.security import hash_password
from app.modules.identity.models import InternalUser, Role


def provision_admin(username: str, phone: str, full_name: str, password: str) -> None:
    if len(password) < 12:
        raise ValueError("The administrator password must contain at least 12 characters")
    session = get_session_factory()()
    try:
        existing = session.scalar(select(InternalUser).where(InternalUser.username == username.lower()))
        if existing is not None:
            raise ValueError("The administrator username already exists")
        role = session.scalar(select(Role).where(Role.role_name == "ADMIN"))
        if role is None:
            from datetime import UTC, datetime

            now = datetime.now(UTC)
            role = Role(role_name="ADMIN", description="Administrador del sistema", is_active=True, created_at=now, updated_at=now)
            session.add(role)
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        user = InternalUser(
            username=username.strip().lower(),
            phone=phone.strip(),
            password_hash=hash_password(password),
            full_name=" ".join(full_name.split()),
            is_active=True,
            created_at=now,
            updated_at=now,
            role=role,
        )
        session.add(user)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == "__main__":
    parser = ArgumentParser(description="Provision the explicit root administrator")
    parser.add_argument("--username", required=True)
    parser.add_argument("--phone", required=True)
    parser.add_argument("--full-name", required=True)
    args = parser.parse_args()
    first = getpass("Administrator password: ")
    confirmation = getpass("Repeat administrator password: ")
    if first != confirmation:
        raise SystemExit("Passwords do not match")
    provision_admin(args.username, args.phone, args.full_name, first)
