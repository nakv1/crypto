from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from core.security import secure_zero_bytearray


@dataclass
class SessionState:
    unlocked: bool = False
    username: str = ""


class StateManager:
    def __init__(self):
        self.mutex = threading.Lock()
        self.session = SessionState(unlocked=False)
        self.master_key: Optional[bytearray] = None

        # Заглушки будущих фич
        self.clipboard_value: str = ""
        self.clipboard_timeout_sec: int = 0
        self.inactivity_minutes: int = 0

    def is_unlocked(self) -> bool:
        with self.mutex:
            return bool(self.session.unlocked)

    def unlock(self, master_key: bytes, username: str = "user") -> None:
        if not master_key:
            raise ValueError("master_key не может быть пустым")
        with self.mutex:
            # Стираем старый ключ, если был.
            if self.master_key is not None:
                secure_zero_bytearray(self.master_key)
            self.master_key = bytearray(master_key)
            self.session = SessionState(unlocked=True, username=username)

    def lock(self) -> None:
        with self.mutex:
            self.session = SessionState(unlocked=False, username="")
            if self.master_key is not None:
                secure_zero_bytearray(self.master_key)
                self.master_key = None

    def get_master_key(self) -> bytes:
        with self.mutex:
            if not self.session.unlocked or self.master_key is None:
                raise RuntimeError("Хранилище заблокировано")
            return bytes(self.master_key)

    def username(self) -> str:
        with self.mutex:
            return self.session.username
