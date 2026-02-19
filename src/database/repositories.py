
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, List, Callable

from database.db import Database
from core.crypto.abstract import EncryptionService


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class VaultEntry:
    id: int
    title: str
    username: str
    url: str
    tags: str
    updated_at: str


class VaultRepository:

    def __init__(self, db: Database, crypto: EncryptionService, key_provider: Callable[[], bytes]):
        self._db = db
        self._crypto = crypto
        self._key_provider = key_provider

    def add(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
    ) -> int:
        if not title.strip():
            raise ValueError("Название не может быть пустым")

        key = self._key_provider()

        enc_password = self._crypto.encrypt(password.encode("utf-8"), key)
        enc_notes = self._crypto.encrypt(notes.encode("utf-8"), key) if notes else None
        created_at = _now_iso()
        updated_at = created_at

        with self._db.session() as conn:
            cur = conn.execute(
                """
                INSERT INTO vault_entries (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, enc_password, url, enc_notes, created_at, updated_at, tags),
            )
            return int(cur.lastrowid)

    def list(self) -> List[VaultEntry]:
        with self._db.session() as conn:
            rows = conn.execute(
                """
                SELECT id, title, username, url, tags, updated_at
                FROM vault_entries
                ORDER BY updated_at DESC
                """
            ).fetchall()

        return [
            VaultEntry(
                id=int(r["id"]),
                title=r["title"] or "",
                username=r["username"] or "",
                url=r["url"] or "",
                tags=r["tags"] or "",
                updated_at=r["updated_at"] or "",
            )
            for r in rows
        ]
    def get_by_id(self, entry_id: int) -> Optional[dict]:
        with self._db.session() as conn:
            row = conn.execute(
                """
                SELECT id, title, username, encrypted_password, url, notes, tags, created_at, updated_at
                FROM vault_entries
                WHERE id = ?
                """,
                (entry_id,),
            ).fetchone()
        if not row:
            return None

        key = self._key_provider()
        password = self._crypto.decrypt(row["encrypted_password"], key).decode("utf-8", errors="replace")
        notes = ""
        if row["notes"] is not None:
            notes = self._crypto.decrypt(row["notes"], key).decode("utf-8", errors="replace")

        return {
            "id": int(row["id"]),
            "title": row["title"] or "",
            "username": row["username"] or "",
            "password": password,
            "url": row["url"] or "",
            "notes": notes,
            "tags": row["tags"] or "",
            "created_at": row["created_at"] or "",
            "updated_at": row["updated_at"] or "",
        }

    def update(
        self,
        entry_id: int,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
    ) -> None:
        if not title.strip():
            raise ValueError("Название не может быть пустым")

        key = self._key_provider()
        enc_password = self._crypto.encrypt(password.encode("utf-8"), key)
        enc_notes = self._crypto.encrypt(notes.encode("utf-8"), key) if notes else None
        updated_at = _now_iso()

        with self._db.session() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, tags = ?, updated_at = ?
                WHERE id = ?
                """,
                (title, username, enc_password, url, enc_notes, tags, updated_at, entry_id),
            )

    def delete(self, entry_id: int) -> None:
        with self._db.session() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))


class SettingsRepository:
    def __init__(self, db: Database, crypto: EncryptionService, key_provider: Callable[[], bytes]):
        self._db = db
        self._crypto = crypto
        self._key_provider = key_provider

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._db.session() as conn:
            row = conn.execute(
                "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
        if not row:
            return default

        val = row["setting_value"]
        if int(row["encrypted"] or 0) == 1 and val is not None:
            key_bytes = self._key_provider()
            raw = self._crypto.decrypt(val, key_bytes)
            return raw.decode("utf-8", errors="replace")
        return val

    def set(self, key: str, value: str, encrypted: bool = False) -> None:
        if not key.strip():
            raise ValueError("Ключ настройки не может быть пустым")

        store_val = value
        enc_flag = 1 if encrypted else 0
        if encrypted:
            key_bytes = self._key_provider()
            store_val = self._crypto.encrypt(value.encode("utf-8"), key_bytes)

        with self._db.session() as conn:
            conn.execute(
                """
                INSERT INTO settings (setting_key, setting_value, encrypted)
                VALUES (?, ?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, encrypted=excluded.encrypted
                """,
                (key, store_val, enc_flag),
            )


@dataclass(frozen=True)
class AuditRecord:
    id: int
    action: str
    details: str
    timestamp: str


class AuditRepository:
    def __init__(self, db: Database):
        self._db = db

    def write(self, action: str, details: dict, entry_id: Optional[int] = None) -> None:
        with self._db.session() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action, _now_iso(), entry_id, json.dumps(details, ensure_ascii=False), None),
            )

    def last(self, limit: int = 50) -> List[AuditRecord]:
        with self._db.session() as conn:
            rows = conn.execute(
                """
                SELECT id, action, details, timestamp
                FROM audit_log
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            AuditRecord(
                id=int(r["id"]),
                action=r["action"] or "",
                details=r["details"] or "",
                timestamp=r["timestamp"] or "",
            )
            for r in rows
        ]