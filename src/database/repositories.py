import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from core.crypto.abstract import EncryptionService
from database.db import Database


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64_decode(value: object) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return base64.b64decode(value)
    raise TypeError("Неподдерживаемый тип для base64-декодирования")


@dataclass(frozen=True)
class VaultEntry:
    id: int
    title: str
    username: str
    url: str
    tags: str
    updated_at: str


class VaultRepository:
    def __init__(self, db: Database, crypto: EncryptionService):
        self.db = db
        self.crypto = crypto

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

        enc_password = b64_encode(self.crypto.encrypt(password.encode("utf-8")))
        enc_notes = b64_encode(self.crypto.encrypt(notes.encode("utf-8"))) if notes else None
        created_at = now_iso()
        updated_at = created_at

        with self.db.session() as conn:
            cur = conn.execute(
                """
                INSERT INTO vault_entries (title, username, encrypted_password, url, notes, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, username, enc_password, url, enc_notes, created_at, updated_at, tags),
            )
            return int(cur.lastrowid)

    def list(self) -> List[VaultEntry]:
        with self.db.session() as conn:
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
        with self.db.session() as conn:
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

        password = self.crypto.decrypt(b64_decode(row["encrypted_password"])).decode("utf-8", errors="replace")
        notes = ""
        if row["notes"] is not None:
            notes = self.crypto.decrypt(b64_decode(row["notes"])).decode("utf-8", errors="replace")

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

        enc_password = b64_encode(self.crypto.encrypt(password.encode("utf-8")))
        enc_notes = b64_encode(self.crypto.encrypt(notes.encode("utf-8"))) if notes else None
        updated_at = now_iso()

        with self.db.session() as conn:
            conn.execute(
                """
                UPDATE vault_entries
                SET title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, tags = ?, updated_at = ?
                WHERE id = ?
                """,
                (title, username, enc_password, url, enc_notes, tags, updated_at, entry_id),
            )

    def delete(self, entry_id: int) -> None:
        with self.db.session() as conn:
            conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))

    def reencrypt_all_entries(
        self,
        old_key: bytes,
        new_key: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        with self.db.session() as conn:
            rows = conn.execute(
                """
                SELECT id, encrypted_password, notes
                FROM vault_entries
                ORDER BY id
                """
            ).fetchall()
            total = len(rows)
            if progress_callback is not None:
                progress_callback(0, total)

            for index, row in enumerate(rows, start=1):
                plain_password = self.crypto.decrypt_with_key(b64_decode(row["encrypted_password"]), old_key)
                new_enc_password = b64_encode(self.crypto.encrypt_with_key(plain_password, new_key))

                notes_value = row["notes"]
                new_enc_notes = None
                if notes_value is not None:
                    plain_notes = self.crypto.decrypt_with_key(b64_decode(notes_value), old_key)
                    new_enc_notes = b64_encode(self.crypto.encrypt_with_key(plain_notes, new_key))

                conn.execute(
                    """
                    UPDATE vault_entries
                    SET encrypted_password = ?, notes = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (new_enc_password, new_enc_notes, now_iso(), int(row["id"])),
                )
                if progress_callback is not None:
                    progress_callback(index, total)


class SettingsRepository:
    def __init__(self, db: Database, crypto: EncryptionService):
        self.db = db
        self.crypto = crypto

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self.db.session() as conn:
            row = conn.execute(
                "SELECT setting_value, encrypted FROM settings WHERE setting_key = ?",
                (key,),
            ).fetchone()
        if not row:
            return default

        val = row["setting_value"]
        if int(row["encrypted"] or 0) == 1 and val is not None:
            try:
                ct = base64.b64decode(val)
                raw = self.crypto.decrypt(ct)
            except Exception:
                raw = self.crypto.decrypt(val)
            return raw.decode("utf-8", errors="replace")
        return val

    def set(self, key: str, value: str, encrypted: bool = False) -> None:
        if not key.strip():
            raise ValueError("Ключ настройки не может быть пустым")

        store_val = value
        enc_flag = 1 if encrypted else 0
        if encrypted:
            ct = self.crypto.encrypt(value.encode("utf-8"))
            store_val = base64.b64encode(ct).decode("utf-8")
        with self.db.session() as conn:
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
        self.db = db

    def write(self, action: str, details: dict, entry_id: Optional[int] = None) -> None:
        with self.db.session() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (action, timestamp, entry_id, details, signature)
                VALUES (?, ?, ?, ?, ?)
                """,
                (action, now_iso(), entry_id, json.dumps(details, ensure_ascii=False), None),
            )

    def last(self, limit: int = 50) -> List[AuditRecord]:
        with self.db.session() as conn:
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
