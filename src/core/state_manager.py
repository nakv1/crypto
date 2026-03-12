from __future__ import annotations

import threading
from dataclasses import dataclass


@dataclass
class SessionState:
    unlocked: bool = False
    username: str = ""
    login_timestamp: str = ""
    last_activity_timestamp: str = ""
    failed_attempt_count: int = 0


class StateManager:
    def __init__(self):
        self.mutex = threading.Lock()
        self.session = SessionState(unlocked=False)

        # Заглушки будущих фич
        self.clipboard_value: str = ""
        self.clipboard_timeout_sec: int = 0
        self.inactivity_minutes: int = 0

    def is_unlocked(self) -> bool:
        with self.mutex:
            return bool(self.session.unlocked)

    def unlock(self, username: str = "user") -> None:
        with self.mutex:
            self.session.unlocked = True
            self.session.username = username

    def lock(self) -> None:
        with self.mutex:
            self.session = SessionState(unlocked=False, username="")

    def username(self) -> str:
        with self.mutex:
            return self.session.username

    def register_failed_attempt(self) -> int:
        with self.mutex:
            self.session.failed_attempt_count += 1
            return self.session.failed_attempt_count

    def set_failed_attempt_count(self, count: int) -> None:
        with self.mutex:
            self.session.failed_attempt_count = max(0, int(count))

    def failed_attempt_count(self) -> int:
        with self.mutex:
            return int(self.session.failed_attempt_count)

    def update_login_timestamps(self, timestamp: str) -> None:
        with self.mutex:
            self.session.login_timestamp = timestamp
            self.session.last_activity_timestamp = timestamp

    def update_last_activity(self, timestamp: str) -> None:
        with self.mutex:
            self.session.last_activity_timestamp = timestamp

    def login_timestamp(self) -> str:
        with self.mutex:
            return self.session.login_timestamp

    def last_activity_timestamp(self) -> str:
        with self.mutex:
            return self.session.last_activity_timestamp
