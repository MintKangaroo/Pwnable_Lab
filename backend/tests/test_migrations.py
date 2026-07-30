"""Alembic Phase 1 migration smoke tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config

from pwnable_lab.config import get_settings


def test_phase1_migration_upgrades_legacy_sqlite(tmp_path, monkeypatch):
    database_path = tmp_path / "legacy.db"
    connection = sqlite3.connect(database_path)
    connection.executescript("""
        CREATE TABLE binaries (
            sha256 VARCHAR(64) PRIMARY KEY,
            filename VARCHAR(255) NOT NULL,
            size INTEGER NOT NULL,
            machine VARCHAR(32) NOT NULL,
            bits INTEGER NOT NULL,
            created_at DATETIME NOT NULL
        );
        CREATE TABLE submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug VARCHAR(64) NOT NULL,
            correct INTEGER NOT NULL,
            created_at DATETIME NOT NULL
        );
        """)
    connection.close()

    monkeypatch.setenv("PLAB_DATABASE_URL", f"sqlite:///{database_path}")
    get_settings.cache_clear()
    config = Config(str(Path(__file__).parents[1] / "alembic.ini"))
    command.upgrade(config, "head")
    get_settings.cache_clear()

    migrated = sqlite3.connect(database_path)
    tables = {
        row[0]
        for row in migrated.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    columns = {row[1] for row in migrated.execute("PRAGMA table_info(binaries)")}
    migrated.close()

    assert {"analysis_jobs", "audit_logs", "alembic_version"} <= tables
    assert {"analysis_status", "updated_at"} <= columns
