from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.modules.identity.models import InternalUser, Role


def find_user_by_login(session: Session, login: str) -> InternalUser | None:
    normalized = login.strip().lower()
    statement = (
        select(InternalUser)
        .where(InternalUser.username == normalized)
        .options(selectinload(InternalUser.role).selectinload(Role.permissions))
    )
    return session.scalar(statement)


def get_user_with_access(session: Session, user_id: int) -> InternalUser | None:
    statement = (
        select(InternalUser)
        .where(InternalUser.user_id == user_id)
        .options(selectinload(InternalUser.role).selectinload(Role.permissions))
    )
    user = session.scalar(statement)
    if user is not None:
        if user.role is not None:
            user.role.permissions
    return user
