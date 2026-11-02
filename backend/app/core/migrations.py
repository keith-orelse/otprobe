from __future__ import annotations

from pathlib import Path

from alembic.config import Config

from alembic import command

BACKEND = Path(__file__).resolve().parents[2]


def alembic_config(database_url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def upgrade(database_url: str) -> None:
    command.upgrade(alembic_config(database_url), "head")
