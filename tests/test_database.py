from __future__ import annotations

from pathlib import Path

from database.db import Database


def _columns(conn, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
    return {r["name"] for r in rows}


def test_schema_tables_and_columns(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    with db.session() as conn:
        tables = {
            r["name"]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            ).fetchall()
        }

        assert "vault_entries" in tables
        assert "audit_log" in tables
        assert "settings" in tables
        assert "key_store" in tables

        vault_cols = _columns(conn, "vault_entries")
        for c in [
            "id",
            "title",
            "username",
            "encrypted_password",
            "url",
            "notes",
            "created_at",
            "updated_at",
            "tags",
        ]:
            assert c in vault_cols

        audit_cols = _columns(conn, "audit_log")
        for c in ["id", "action", "timestamp", "entry_id", "details", "signature"]:
            assert c in audit_cols

    db.close()
