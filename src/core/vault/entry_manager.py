from __future__ import annotations

import base64
import difflib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from core.crypto.abstract import EncryptionService
from core.events import EntryCreated, EntryDeleted, EntryUpdated, EventBus
from core.key_manager import KeyManager
from core.vault.encryption_service import VaultEncryptionService
from database.db import Database


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def utc_iso_after_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=int(days))).isoformat(timespec="seconds")


def domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
    except Exception:
        return ""
    return parsed.netloc.lower().strip()


class EntryManager:
    field_filter_pattern = re.compile(r'([a-zA-Z]+):"([^"]+)"')

    def __init__(
        self,
        db: Database,
        key_manager: KeyManager,
        bus: Optional[EventBus] = None,
        encryption_service: Optional[VaultEncryptionService] = None,
        legacy_crypto: Optional[EncryptionService] = None,
        soft_delete_retention_days: int = 30,
    ):
        self.db = db
        self.key_manager = key_manager
        self.bus = bus
        self.encryption_service = encryption_service or VaultEncryptionService()
        self.legacy_crypto = legacy_crypto
        self.soft_delete_retention_days = max(1, int(soft_delete_retention_days))

    def normalize_text(self, value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def normalize_tags(self, value: object) -> str:
        if isinstance(value, list):
            out: list[str] = []
            seen: set[str] = set()
            for raw in value:
                item = self.normalize_text(raw)
                if not item:
                    continue
                low = item.lower()
                if low in seen:
                    continue
                seen.add(low)
                out.append(item)
            return ",".join(out)
        text = self.normalize_text(value)
        if not text:
            return ""
        parts = [item.strip() for item in text.split(",")]
        out: list[str] = []
        seen: set[str] = set()
        for part in parts:
            if not part:
                continue
            low = part.lower()
            if low in seen:
                continue
            seen.add(low)
            out.append(part)
        return ",".join(out)

    def validate_required_fields(self, payload: dict[str, Any]) -> None:
        if not self.normalize_text(payload.get("title")):
            raise ValueError("Поле title обязательно.")
        if not self.normalize_text(payload.get("password")):
            raise ValueError("Поле password обязательно.")

    def normalize_entry_payload(
        self,
        data_dict: dict[str, Any],
        existing_payload: Optional[dict[str, Any]] = None,
        created_at: Optional[str] = None,
    ) -> dict[str, Any]:
        source = existing_payload or {}
        payload = {
            "title": self.normalize_text(data_dict.get("title", source.get("title", ""))),
            "username": self.normalize_text(data_dict.get("username", source.get("username", ""))),
            "password": self.normalize_text(data_dict.get("password", source.get("password", ""))),
            "url": self.normalize_text(data_dict.get("url", source.get("url", ""))),
            "notes": self.normalize_text(data_dict.get("notes", source.get("notes", ""))),
            "category": self.normalize_text(data_dict.get("category", source.get("category", "General"))) or "General",
            "version": int(data_dict.get("version", source.get("version", 1)) or 1),
            "created_at": created_at or self.normalize_text(source.get("created_at")) or utc_now_iso(),
            "totp_secret": self.normalize_text(data_dict.get("totp_secret", source.get("totp_secret", ""))),
            "sharing_metadata": data_dict.get("sharing_metadata", source.get("sharing_metadata", {})),
        }
        if not isinstance(payload["sharing_metadata"], dict):
            payload["sharing_metadata"] = {}
        self.validate_required_fields(payload)
        return payload

    def encode_with_active_key(self, payload: dict[str, Any]) -> str:
        key = self.key_manager.get_active_key(key_type="vault_encryption")
        return self.encryption_service.encrypt_payload(payload, key)

    def decode_with_active_key(self, encrypted_data: str) -> dict[str, Any]:
        key = self.key_manager.get_active_key(key_type="vault_encryption")
        return self.encryption_service.decrypt_payload(encrypted_data, key)

    def decode_base64_text(self, value: object) -> bytes:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            return base64.b64decode(value.encode("utf-8"))
        raise ValueError("Некорректный формат поля с зашифрованными данными.")

    def decode_legacy_row_payload_with_key(self, row, key: bytes, legacy_crypto: EncryptionService) -> dict[str, Any]:
        enc_password = row["encrypted_password"]
        if not isinstance(enc_password, str) or not enc_password:
            raise ValueError("Legacy-запись не содержит encrypted_password.")

        password_plain = legacy_crypto.decrypt_with_key(
            self.decode_base64_text(enc_password),
            key,
        ).decode("utf-8", errors="replace")
        notes_plain = ""
        notes_raw = row["notes"]
        if isinstance(notes_raw, str) and notes_raw:
            notes_plain = legacy_crypto.decrypt_with_key(
                self.decode_base64_text(notes_raw),
                key,
            ).decode("utf-8", errors="replace")

        return {
            "title": self.normalize_text(row["title"]),
            "username": self.normalize_text(row["username"]),
            "password": password_plain,
            "url": self.normalize_text(row["url"]),
            "notes": notes_plain,
            "category": "General",
            "version": 1,
            "created_at": self.normalize_text(row["created_at"]) or utc_now_iso(),
            "totp_secret": "",
            "sharing_metadata": {},
        }

    def decode_row_payload_with_key(
        self,
        row,
        key: bytes,
        legacy_crypto: Optional[EncryptionService] = None,
    ) -> dict[str, Any]:
        encrypted_data = self.normalize_text(row["encrypted_data"])
        if encrypted_data:
            return self.encryption_service.decrypt_payload(encrypted_data, key)
        chosen_legacy_crypto = legacy_crypto or self.legacy_crypto
        if chosen_legacy_crypto is None:
            raise ValueError("Legacy-формат записи не поддерживается без legacy_crypto.")
        return self.decode_legacy_row_payload_with_key(row, key, chosen_legacy_crypto)

    def decode_row_payload(self, row) -> dict[str, Any]:
        key = self.key_manager.get_active_key(key_type="vault_encryption")
        return self.decode_row_payload_with_key(row, key)

    def build_entry_dict(
        self,
        row,
        payload: dict[str, Any],
        include_sensitive: bool = True,
        include_notes: bool = True,
    ) -> dict[str, Any]:
        tags = self.normalize_tags(row["tags"])
        password_value = self.normalize_text(payload.get("password")) if include_sensitive else ""
        notes_value = self.normalize_text(payload.get("notes")) if include_notes else ""
        return {
            "id": int(row["id"]),
            "title": self.normalize_text(payload.get("title")),
            "username": self.normalize_text(payload.get("username")),
            "password": password_value,
            "url": self.normalize_text(payload.get("url")),
            "domain": domain_from_url(self.normalize_text(payload.get("url"))),
            "notes": notes_value,
            "category": self.normalize_text(payload.get("category")) or "General",
            "tags": tags,
            "created_at": self.normalize_text(row["created_at"]) or self.normalize_text(payload.get("created_at")),
            "updated_at": self.normalize_text(row["updated_at"]),
            "version": int(payload.get("version", 1) or 1),
            "totp_secret": self.normalize_text(payload.get("totp_secret")),
            "sharing_metadata": payload.get("sharing_metadata", {}),
        }

    def create_entry(self, data_dict: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data_dict, dict):
            raise TypeError("data_dict должен быть словарем.")

        created_at = utc_now_iso()
        updated_at = created_at
        payload = self.normalize_entry_payload(data_dict, existing_payload=None, created_at=created_at)
        tags = self.normalize_tags(data_dict.get("tags", ""))
        encrypted_data = self.encode_with_active_key(payload)

        with self.db.session() as conn:
            cur = conn.execute(
                """
                INSERT INTO vault_entries (
                    encrypted_data,
                    title,
                    username,
                    encrypted_password,
                    url,
                    notes,
                    created_at,
                    updated_at,
                    tags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    encrypted_data,
                    None,
                    None,
                    None,
                    None,
                    None,
                    created_at,
                    updated_at,
                    tags,
                ),
            )
            entry_id = int(cur.lastrowid)

        result = {
            **payload,
            "id": entry_id,
            "domain": domain_from_url(payload.get("url", "")),
            "tags": tags,
            "updated_at": updated_at,
        }
        if self.bus is not None:
            self.bus.publish(EntryCreated(entry_id=entry_id, title=result["title"]))
        return result

    def get_entry(self, entry_id: int) -> dict[str, Any]:
        with self.db.session() as conn:
            row = conn.execute(
                """
                SELECT id, encrypted_data, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                WHERE id = ?
                """,
                (int(entry_id),),
            ).fetchone()
        if row is None:
            raise ValueError("Запись недоступна.")
        try:
            payload = self.decode_row_payload(row)
        except Exception as exc:
            raise ValueError("Запись недоступна.") from exc
        return self.build_entry_dict(row, payload, include_sensitive=True, include_notes=True)

    def get_all_entries(
        self,
        include_sensitive: bool = False,
        include_notes: bool = False,
    ) -> list[dict[str, Any]]:
        with self.db.session() as conn:
            rows = conn.execute(
                """
                SELECT id, encrypted_data, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                ORDER BY updated_at DESC, id DESC
                """
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = self.decode_row_payload(row)
                output.append(
                    self.build_entry_dict(
                        row=row,
                        payload=payload,
                        include_sensitive=include_sensitive,
                        include_notes=include_notes,
                    )
                )
            except Exception:
                continue
        return output

    def update_entry(self, entry_id: int, data_dict: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data_dict, dict):
            raise TypeError("data_dict должен быть словарем.")

        with self.db.session() as conn:
            row = conn.execute(
                """
                SELECT id, encrypted_data, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                WHERE id = ?
                """,
                (int(entry_id),),
            ).fetchone()
            if row is None:
                raise ValueError("Запись недоступна.")

            try:
                existing_payload = self.decode_row_payload(row)
            except Exception as exc:
                raise ValueError("Запись недоступна.") from exc

            payload = self.normalize_entry_payload(
                data_dict,
                existing_payload=existing_payload,
                created_at=self.normalize_text(existing_payload.get("created_at")) or self.normalize_text(row["created_at"]),
            )
            tags = self.normalize_tags(data_dict.get("tags", row["tags"]))
            updated_at = utc_now_iso()
            encrypted_data = self.encode_with_active_key(payload)

            conn.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, tags = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    encrypted_data,
                    None,
                    None,
                    None,
                    None,
                    None,
                    tags,
                    updated_at,
                    int(entry_id),
                ),
            )

        result = {
            **payload,
            "id": int(entry_id),
            "domain": domain_from_url(payload.get("url", "")),
            "tags": tags,
            "updated_at": updated_at,
        }
        if self.bus is not None:
            self.bus.publish(EntryUpdated(title=result["title"], entry_id=int(entry_id)))
        return result

    def delete_entry(self, entry_id: int, soft_delete: bool = True) -> None:
        with self.db.session() as conn:
            row = conn.execute(
                """
                SELECT id, encrypted_data, title, username, encrypted_password, url, notes, created_at, updated_at, tags
                FROM vault_entries
                WHERE id = ?
                """,
                (int(entry_id),),
            ).fetchone()
            if row is None:
                raise ValueError("Запись недоступна.")

            payload = self.decode_row_payload(row)
            title = self.normalize_text(payload.get("title"))
            encrypted_data = self.normalize_text(row["encrypted_data"])
            if not encrypted_data:
                encrypted_data = self.encode_with_active_key(payload)

            if soft_delete:
                deleted_at = utc_now_iso()
                expires_at = utc_iso_after_days(self.soft_delete_retention_days)
                conn.execute(
                    """
                    INSERT INTO deleted_entries (
                        source_entry_id,
                        encrypted_data,
                        tags,
                        created_at,
                        updated_at,
                        deleted_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(entry_id),
                        encrypted_data,
                        self.normalize_tags(row["tags"]),
                        self.normalize_text(row["created_at"]) or utc_now_iso(),
                        self.normalize_text(row["updated_at"]) or utc_now_iso(),
                        deleted_at,
                        expires_at,
                    ),
                )

            conn.execute("DELETE FROM vault_entries WHERE id = ?", (int(entry_id),))

        if self.bus is not None:
            self.bus.publish(EntryDeleted(title=title, entry_id=int(entry_id)))

    def parse_query_filters(self, query: str) -> tuple[dict[str, str], str]:
        if not query:
            return {}, ""
        filters: dict[str, str] = {}
        for match in self.field_filter_pattern.finditer(query):
            field_name = match.group(1).strip().lower()
            field_value = match.group(2).strip()
            if field_name and field_value:
                filters[field_name] = field_value
        free_text = self.field_filter_pattern.sub(" ", query).strip()
        return filters, free_text

    def fuzzy_contains(self, haystack: str, needle: str) -> bool:
        if not needle:
            return True
        hay = haystack.lower()
        ned = needle.lower()
        if ned in hay:
            return True
        tokens = [token for token in re.split(r"\s+", hay) if token]
        if not tokens:
            return False
        query_len = len(ned)
        if query_len < 4:
            return False
        query_first = ned[0]

        for token in tokens:
            if not token:
                continue
            if token[0] != query_first:
                continue
            token_len = len(token)
            if abs(token_len - query_len) > 2 and ned not in token and token not in ned:
                continue
            quick = difflib.SequenceMatcher(a=token, b=ned).quick_ratio()
            if quick < 0.72:
                continue
            ratio = difflib.SequenceMatcher(a=token, b=ned).ratio()
            if ratio >= 0.84:
                return True
        return False

    def entry_matches_filters(
        self,
        entry: dict[str, Any],
        filters: dict[str, str],
        free_text: str,
        use_fuzzy: bool,
    ) -> bool:
        for field_name, expected in filters.items():
            actual = self.normalize_text(entry.get(field_name)).lower()
            if expected.lower() not in actual:
                return False
        if not free_text:
            return True
        searchable = " ".join(
            [
                self.normalize_text(entry.get("title")),
                self.normalize_text(entry.get("username")),
                self.normalize_text(entry.get("url")),
                self.normalize_text(entry.get("notes")),
            ]
        ).lower()
        if free_text.lower() in searchable:
            return True
        if not use_fuzzy:
            return False
        return self.fuzzy_contains(searchable, free_text)

    def search_entries(
        self,
        query: str,
        tags: Optional[list[str]] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        filters, free_text = self.parse_query_filters(query or "")
        entries = self.get_all_entries(include_sensitive=False, include_notes=True)

        exact_matches: list[dict[str, Any]] = []
        tags_filter = {self.normalize_text(item).lower() for item in (tags or []) if self.normalize_text(item)}

        for entry in entries:
            if tags_filter:
                entry_tags = {item.strip().lower() for item in self.normalize_tags(entry.get("tags")).split(",") if item.strip()}
                if not entry_tags.intersection(tags_filter):
                    continue

            updated_at = self.normalize_text(entry.get("updated_at"))
            if date_from and updated_at and updated_at < date_from:
                continue
            if date_to and updated_at and updated_at > date_to:
                continue

            if not self.entry_matches_filters(entry, filters, free_text, use_fuzzy=False):
                continue
            exact_matches.append(entry)

        output = exact_matches
        if free_text and not exact_matches:
            fuzzy_matches: list[dict[str, Any]] = []
            for entry in entries:
                if tags_filter:
                    entry_tags = {item.strip().lower() for item in self.normalize_tags(entry.get("tags")).split(",") if item.strip()}
                    if not entry_tags.intersection(tags_filter):
                        continue

                updated_at = self.normalize_text(entry.get("updated_at"))
                if date_from and updated_at and updated_at < date_from:
                    continue
                if date_to and updated_at and updated_at > date_to:
                    continue

                if not self.entry_matches_filters(entry, filters, free_text, use_fuzzy=True):
                    continue
                fuzzy_matches.append(entry)
            output = fuzzy_matches

        sanitized: list[dict[str, Any]] = []
        for entry in output:
            row = dict(entry)
            row["password"] = ""
            row["notes"] = ""
            sanitized.append(row)
        return sanitized

    def reencrypt_all_entries(
        self,
        old_key: bytes,
        new_key: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        legacy_crypto: Optional[EncryptionService] = None,
        conn=None,
    ) -> None:
        if conn is not None:
            self.reencrypt_all_entries_with_connection(
                conn=conn,
                old_key=old_key,
                new_key=new_key,
                progress_callback=progress_callback,
                legacy_crypto=legacy_crypto,
            )
            return

        with self.db.session() as conn_from_db:
            self.reencrypt_all_entries_with_connection(
                conn=conn_from_db,
                old_key=old_key,
                new_key=new_key,
                progress_callback=progress_callback,
                legacy_crypto=legacy_crypto,
            )

    def reencrypt_all_entries_with_connection(
        self,
        conn,
        old_key: bytes,
        new_key: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        legacy_crypto: Optional[EncryptionService] = None,
    ) -> None:
        chosen_legacy_crypto = legacy_crypto or self.legacy_crypto
        rows = conn.execute(
            """
            SELECT id, encrypted_data, title, username, encrypted_password, url, notes, created_at, updated_at, tags
            FROM vault_entries
            ORDER BY id
            """
        ).fetchall()
        total = len(rows)
        if progress_callback is not None:
            progress_callback(0, total)

        for index, row in enumerate(rows, start=1):
            payload = self.decode_row_payload_with_key(
                row=row,
                key=old_key,
                legacy_crypto=chosen_legacy_crypto,
            )
            encrypted_data = self.encryption_service.encrypt_payload(payload, new_key)
            conn.execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, title = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    encrypted_data,
                    None,
                    None,
                    None,
                    None,
                    None,
                    utc_now_iso(),
                    int(row["id"]),
                ),
            )
            if progress_callback is not None:
                progress_callback(index, total)
