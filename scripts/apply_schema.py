from argparse import ArgumentParser
from pathlib import Path
import re

import psycopg

from app.core.config import get_settings


def database_dsn() -> str:
    url = get_settings().database_url
    if not url:
        raise ValueError("DATABASE_URL must be configured")
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def apply_schema(schema_dir: Path) -> None:
    files = sorted(schema_dir.glob("*.sql"))
    if not files:
        raise FileNotFoundError(f"No SQL schema files found in {schema_dir}")
    if any(re.fullmatch(r"\d{3}_[a-z0-9_]+\.sql", path.name) is None for path in files):
        raise ValueError("Schema files must use the NNN_lower_snake_case.sql naming convention")

    with psycopg.connect(database_dsn()) as connection:
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)")
            cursor.execute("SELECT pg_advisory_xact_lock(7162439102240)")
            cursor.execute("SELECT version FROM schema_version")
            applied = {row[0] for row in cursor.fetchall()}
            for schema_file in files:
                version = int(schema_file.name.split("_", 1)[0])
                if version in applied:
                    continue
                cursor.execute(schema_file.read_text(encoding="utf-8"), prepare=False)
                cursor.execute("INSERT INTO schema_version (version) VALUES (%s)", (version,))
        connection.commit()


if __name__ == "__main__":
    parser = ArgumentParser(description="Apply versioned PostgreSQL schema files")
    parser.add_argument("--schema-dir", type=Path, default=Path("sql"))
    args = parser.parse_args()
    apply_schema(args.schema_dir)
