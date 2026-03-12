from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from core.events import EventBus, UserLoggedIn, UserLoggedOut
from core.key_manager import KeyManager
from core.security import secure_zero_bytearray
from core.state_manager import StateManager
from database.db import Database
from core.crypto.abstract import EncryptionService


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class AuthenticationResult:
    success: bool
    message: str
    delay_sec: int = 0


@dataclass
class SessionMetrics:
    login_timestamp: str = ""
    last_activity_timestamp: str = ""
    failed_attempt_count: int = 0


class AuthenticationService:
    def __init__(
        self,
        key_manager: KeyManager,
        state: StateManager,
        bus: Optional[EventBus] = None,
    ):
        self.key_manager = key_manager
        self.state = state
        self.bus = bus
        self.metrics = SessionMetrics()

    @staticmethod
    def calculate_delay_sec(failed_count: int) -> int:
        if failed_count <= 2:
            return 1
        if failed_count <= 4:
            return 5
        return 30

    def has_master_password(self) -> bool:
        return self.key_manager.is_master_password_configured()

    def setup_master_password(self, password: str, username: str = "user") -> None:
        self.key_manager.setup_master_password(password)
        master_key = self.key_manager.derive_master_encryption_key(password)
        self.key_manager.cache_encryption_key(master_key)
        self.state.unlock(username=username)
        now_ts = now_utc_iso()
        self.state.update_login_timestamps(now_ts)
        self.state.set_failed_attempt_count(0)
        self.metrics = SessionMetrics(
            login_timestamp=now_ts,
            last_activity_timestamp=now_ts,
            failed_attempt_count=0,
        )
        if self.bus is not None:
            self.bus.publish(UserLoggedIn(username=username))

    def authenticate(self, password: str, username: str = "user") -> AuthenticationResult:
        if not self.has_master_password():
            return AuthenticationResult(success=False, message="Мастер-пароль не настроен.", delay_sec=0)

        if not self.key_manager.verify_master_password(password):
            failed_count = self.state.register_failed_attempt()
            delay = self.calculate_delay_sec(failed_count)
            self.metrics.failed_attempt_count = failed_count
            return AuthenticationResult(success=False, message="Неверный пароль.", delay_sec=delay)

        master_key = self.key_manager.derive_master_encryption_key(password)
        self.key_manager.cache_encryption_key(master_key)
        self.state.unlock(username=username)
        self.state.set_failed_attempt_count(0)

        now_ts = now_utc_iso()
        self.state.update_login_timestamps(now_ts)
        self.metrics = SessionMetrics(
            login_timestamp=now_ts,
            last_activity_timestamp=now_ts,
            failed_attempt_count=0,
        )
        if self.bus is not None:
            self.bus.publish(UserLoggedIn(username=username))
        return AuthenticationResult(success=True, message="Успешный вход.", delay_sec=0)

    @staticmethod
    def apply_backoff_delay(delay_sec: int) -> None:
        if int(delay_sec) > 0:
            time.sleep(int(delay_sec))

    def record_activity(self) -> None:
        if not self.state.is_unlocked():
            return
        now_ts = now_utc_iso()
        self.state.update_last_activity(now_ts)
        self.key_manager.touch_cached_key()
        self.metrics.last_activity_timestamp = now_ts

    def logout(self, emit_event: bool = True) -> None:
        username = self.state.username()
        self.key_manager.clear_cached_key("logout")
        self.state.lock()
        self.metrics.last_activity_timestamp = ""
        self.metrics.login_timestamp = ""
        self.metrics.failed_attempt_count = 0
        if emit_event and self.bus is not None:
            self.bus.publish(UserLoggedOut(username=username))

    def handle_application_activity(self, app_is_active: bool) -> None:
        self.key_manager.set_application_active(app_is_active)
        if self.state.is_unlocked() and not self.key_manager.has_cached_key():
            self.logout(emit_event=True)

    def enforce_session_timeout(self) -> None:
        if self.state.is_unlocked() and not self.key_manager.has_cached_key():
            self.logout(emit_event=True)

    def change_master_password(
        self,
        current_password: str,
        new_password: str,
        db: Database,
        crypto: EncryptionService,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        if not self.key_manager.verify_master_password(current_password):
            raise ValueError("Текущий пароль неверный.")

        valid, issues = self.key_manager.validate_password_strength(new_password)
        if not valid:
            raise ValueError(" ".join(issues))

        old_key = bytearray(self.key_manager.derive_master_encryption_key(current_password))
        new_salt = self.key_manager.make_salt(self.key_manager.pbkdf2_params.salt_len)
        new_key = bytearray(
            self.key_manager.derive_encryption_key_with_salt(
                password=new_password,
                salt=new_salt,
                key_type="vault_encryption",
            )
        )
        new_auth_hash = self.key_manager.create_auth_hash(new_password)
        params_payload = self.key_manager.serialize_parameter_bundle()

        completed = False
        try:
            with db.session() as conn:
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
                    enc_password = row["encrypted_password"]
                    if not isinstance(enc_password, str):
                        raise ValueError("Некорректный формат encrypted_password в базе.")
                    old_password_raw = base64.b64decode(enc_password.encode("utf-8"))
                    plain_password = crypto.decrypt_with_key(old_password_raw, bytes(old_key))
                    new_password_raw = crypto.encrypt_with_key(plain_password, bytes(new_key))
                    new_password_text = base64.b64encode(new_password_raw).decode("utf-8")

                    notes_value = row["notes"]
                    new_notes_text = None
                    if notes_value is not None:
                        if not isinstance(notes_value, str):
                            raise ValueError("Некорректный формат notes в базе.")
                        old_notes_raw = base64.b64decode(notes_value.encode("utf-8"))
                        plain_notes = crypto.decrypt_with_key(old_notes_raw, bytes(old_key))
                        new_notes_raw = crypto.encrypt_with_key(plain_notes, bytes(new_key))
                        new_notes_text = base64.b64encode(new_notes_raw).decode("utf-8")

                    conn.execute(
                        """
                        UPDATE vault_entries
                        SET encrypted_password = ?, notes = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_password_text, new_notes_text, now_utc_iso(), int(row["id"])),
                    )
                    if progress_callback is not None:
                        progress_callback(index, total)

                self.key_manager.store_key_data_with_connection(
                    conn=conn,
                    key_type=self.key_manager.auth_hash_key_type,
                    key_data=new_auth_hash.encode("utf-8"),
                    version=self.key_manager.current_key_version,
                )
                self.key_manager.store_key_data_with_connection(
                    conn=conn,
                    key_type=self.key_manager.enc_salt_key_type,
                    key_data=new_salt,
                    version=self.key_manager.current_key_version,
                )
                self.key_manager.store_key_data_with_connection(
                    conn=conn,
                    key_type=self.key_manager.params_key_type,
                    key_data=params_payload,
                    version=self.key_manager.current_key_version,
                )
                completed = True
        finally:
            secure_zero_bytearray(old_key)
            if completed:
                self.key_manager.cache_encryption_key(bytes(new_key))
            secure_zero_bytearray(new_key)
        if completed:
            self.record_activity()
