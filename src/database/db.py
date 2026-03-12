import base64
import os
import queue
import sqlite3
import stat
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from database.models import SCHEMA


def b64_text(value: object) -> str:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode("utf-8")
    if isinstance(value, str):
        return value
    raise TypeError("Неподдерживаемый тип для base64-текста")


def decode_key_payload(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return base64.b64decode(value.encode("utf-8"), validate=True)
        except Exception:
            return value.encode("utf-8")
    raise TypeError("Неподдерживаемый тип key_data")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    SCHEMA_VERSION = 4

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self.pool: "queue.Queue[sqlite3.Connection]" = queue.Queue()
        self.pool_size = 4
        self.initialized = False

    def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self.lock:
            if self.initialized:
                return

            for _ in range(self.pool_size):
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA busy_timeout = 5000;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                self.pool.put(conn)

            self.initialized = True

            try:
                self.apply_permissions()
                self.ensure_schema()
            except Exception:
                self.close()
                raise

    def close(self) -> None:
        with self.lock:
            while not self.pool.empty():
                try:
                    conn = self.pool.get_nowait()
                except queue.Empty:
                    break
                try:
                    conn.close()
                except Exception:
                    pass
            self.initialized = False

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:
        if not self.initialized:
            raise RuntimeError("База данных не подключена. Вызови connect().")

        conn = self.pool.get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.put(conn)

    def ensure_schema(self) -> None:
        with self.session() as conn:
            current_version = int(conn.execute("PRAGMA user_version;").fetchone()[0])

            if current_version == 0:
                conn.executescript(SCHEMA)
                conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")
                return

            if current_version in (1, 2, 3):
                self.migrate_legacy_to_v4(conn)
                return

            if current_version != self.SCHEMA_VERSION:
                raise RuntimeError(
                    f"Несовместимая версия схемы БД: {current_version} (ожидается {self.SCHEMA_VERSION})."
                )

    @staticmethod
    def table_exists(conn: sqlite3.Connection, table: str) -> bool:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
            (table,),
        ).fetchone()
        return row is not None

    @staticmethod
    def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
        rows = conn.execute(f"PRAGMA table_info({table});").fetchall()
        return {str(r["name"]) for r in rows}

    def migrate_legacy_to_v4(self, conn: sqlite3.Connection) -> None:
        tables = ["vault_entries", "audit_log", "settings", "key_store"]
        old_tables: dict[str, str] = {}

        for name in tables:
            if self.table_exists(conn, name):
                old_name = f"{name}_old"
                if self.table_exists(conn, old_name):
                    conn.execute(f"DROP TABLE {old_name};")
                conn.execute(f"ALTER TABLE {name} RENAME TO {old_name};")
                old_tables[name] = old_name

        conn.executescript(SCHEMA)

        if "vault_entries" in old_tables:
            rows = conn.execute(
                """
                SELECT id, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries_old
                """
            ).fetchall()
            for row in rows:
                enc_password = b64_text(row["encrypted_password"])
                enc_notes = b64_text(row["notes"]) if row["notes"] is not None else None
                conn.execute(
                    """
                    INSERT INTO vault_entries (id, title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["id"],
                        row["title"],
                        row["username"],
                        enc_password,
                        row["url"],
                        enc_notes,
                        row["created_at"],
                        row["updated_at"],
                        row["tags"],
                    ),
                )

        if "audit_log" in old_tables:
            rows = conn.execute(
                """
                SELECT id, action, timestamp, entry_id, details, signature
                FROM audit_log_old
                """
            ).fetchall()
            for row in rows:
                signature = b64_text(row["signature"]) if row["signature"] is not None else None
                conn.execute(
                    """
                    INSERT INTO audit_log (id, action, timestamp, entry_id, details, signature)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (row["id"], row["action"], row["timestamp"], row["entry_id"], row["details"], signature),
                )

        if "settings" in old_tables:
            rows = conn.execute(
                """
                SELECT id, setting_key, setting_value, encrypted
                FROM settings_old
                """
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    INSERT INTO settings (id, setting_key, setting_value, encrypted)
                    VALUES (?, ?, ?, ?)
                    """,
                    (row["id"], row["setting_key"], row["setting_value"], row["encrypted"]),
                )

        if "key_store" in old_tables:
            columns = self.table_columns(conn, "key_store_old")
            rows = conn.execute("SELECT * FROM key_store_old").fetchall()

            for row in rows:
                if {"key_type", "key_data", "version", "created_at"}.issubset(columns):
                    conn.execute(
                        """
                        INSERT INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(key_type, version)
                        DO UPDATE SET key_data = excluded.key_data, created_at = excluded.created_at
                        """,
                        (
                            row["key_type"],
                            decode_key_payload(row["key_data"]),
                            int(row["version"]),
                            row["created_at"] or now_iso(),
                        ),
                    )
                    continue

                key_type = str(row["key_type"]) if "key_type" in columns else "legacy"
                created = now_iso()

                if "salt" in columns and row["salt"] is not None:
                    conn.execute(
                        """
                        INSERT INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(key_type, version)
                        DO UPDATE SET key_data = excluded.key_data, created_at = excluded.created_at
                        """,
                        (
                            f"legacy:{key_type}:salt",
                            decode_key_payload(row["salt"]),
                            1,
                            created,
                        ),
                    )

                if "hash" in columns and row["hash"] is not None:
                    conn.execute(
                        """
                        INSERT INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(key_type, version)
                        DO UPDATE SET key_data = excluded.key_data, created_at = excluded.created_at
                        """,
                        (
                            f"legacy:{key_type}:hash",
                            decode_key_payload(row["hash"]),
                            1,
                            created,
                        ),
                    )

                if "params" in columns and row["params"] is not None:
                    params_val = row["params"]
                    if isinstance(params_val, str):
                        raw_params = params_val.encode("utf-8")
                    else:
                        raw_params = decode_key_payload(params_val)
                    conn.execute(
                        """
                        INSERT INTO key_store (key_type, key_data, version, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(key_type, version)
                        DO UPDATE SET key_data = excluded.key_data, created_at = excluded.created_at
                        """,
                        (
                            f"legacy:{key_type}:params",
                            raw_params,
                            1,
                            created,
                        ),
                    )

        for name in old_tables.values():
            conn.execute(f"DROP TABLE {name};")

        conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")

    def apply_permissions(self) -> None:
        try:
            if os.name != "nt" and self.db_path.exists():
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    def backup(self, backup_path: Path) -> None:
        raise NotImplementedError("Backup будет реализован в следующих спринтах.")

    def restore(self, backup_path: Path) -> None:
        raise NotImplementedError("Restore будет реализован в следующих спринтах.")
