import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, List, Optional

from core.crypto.abstract import EncryptionService
from core.events import EventBus
from core.vault.entry_manager import EntryManager
from core.vault.password_generator import PasswordGenerator
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
    password: str
    url: str
    tags: str
    updated_at: str


class VaultRepository:
    def __init__(self, db: Database, crypto: EncryptionService, bus: Optional[EventBus] = None):
        self.db = db
        self.crypto = crypto
        self.entry_manager = EntryManager(
            db=db,
            key_manager=crypto.key_manager,
            bus=bus,
            legacy_crypto=crypto,
        )
        self.password_generator = PasswordGenerator()

    def add(
        self,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
        category: str = "General",
    ) -> int:
        result = self.entry_manager.create_entry(
            {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "tags": tags,
                "category": category,
            }
        )
        return int(result["id"])

    def list(self) -> List[VaultEntry]:
        return self.make_entry_list(
            self.entry_manager.get_all_entries(
                include_sensitive=False,
                include_notes=False,
            )
        )

    def make_entry_list(self, rows: List[dict]) -> List[VaultEntry]:
        return [
            VaultEntry(
                id=int(row["id"]),
                title=str(row.get("title") or ""),
                username=str(row.get("username") or ""),
                password=str(row.get("password") or ""),
                url=str(row.get("url") or ""),
                tags=str(row.get("tags") or ""),
                updated_at=str(row.get("updated_at") or ""),
            )
            for row in rows
        ]

    def search(
        self,
        query: str = "",
        tags: Optional[List[str]] = None,
        category: str = "",
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
        min_password_strength: int = 0,
    ) -> List[VaultEntry]:
        rows = self.entry_manager.search_entries(
            query=query,
            tags=tags,
            date_from=date_from,
            date_to=date_to,
        )
        normalized_category = str(category or "").strip().lower()
        min_strength = max(0, min(4, int(min_password_strength)))

        filtered: list[dict] = []
        for row in rows:
            if normalized_category and normalized_category != "all":
                row_category = str(row.get("category") or "").strip().lower()
                if row_category != normalized_category:
                    continue
            if min_strength > 0:
                password_value = self.get_password(int(row.get("id", 0) or 0)) or ""
                score = self.password_generator.estimate_strength_score(password_value)
                if score < min_strength:
                    continue
            filtered.append(row)
        return self.make_entry_list(filtered)

    def get_by_id(self, entry_id: int) -> Optional[dict]:
        try:
            row = self.entry_manager.get_entry(int(entry_id))
        except Exception:
            return None

        return row

    def get_password(self, entry_id: int) -> Optional[str]:
        payload = self.get_by_id(int(entry_id))
        if payload is None:
            return None
        return str(payload.get("password") or "")

    def update(
        self,
        entry_id: int,
        title: str,
        username: str,
        password: str,
        url: str = "",
        notes: str = "",
        tags: str = "",
        category: str = "General",
    ) -> None:
        self.entry_manager.update_entry(
            int(entry_id),
            {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "tags": tags,
                "category": category,
            },
        )

    def delete(self, entry_id: int) -> None:
        self.entry_manager.delete_entry(int(entry_id), soft_delete=True)

    def reencrypt_all_entries(
        self,
        old_key: bytes,
        new_key: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self.entry_manager.reencrypt_all_entries(
            old_key=old_key,
            new_key=new_key,
            progress_callback=progress_callback,
            legacy_crypto=self.crypto,
        )


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
