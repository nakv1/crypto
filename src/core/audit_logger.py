
from core.events import (
    EventBus,
    EntryAdded,
    EntryUpdated,
    EntryDeleted,
    UserLoggedIn,
    UserLoggedOut,
)
from database.repositories import AuditRepository

class AuditLogger:

    def __init__(self, bus: EventBus, audit_repo: AuditRepository):
        self._bus = bus
        self._audit = audit_repo

    def start(self) -> None:
        self._bus.subscribe(EntryAdded, self.on_entry_added)
        self._bus.subscribe(EntryUpdated, self.on_entry_updated)
        self._bus.subscribe(EntryDeleted, self.on_entry_deleted)
        self._bus.subscribe(UserLoggedIn, self.on_user_logged_in)
        self._bus.subscribe(UserLoggedOut, self.on_user_logged_out)

    def on_entry_added(self, e: EntryAdded) -> None:
        self._audit.write("EntryAdded", {"title": e.title})

    def on_entry_deleted(self, e: EntryDeleted) -> None:
        self._audit.write("EntryDeleted", {"title": e.title})

    def on_entry_updated(self, e: EntryUpdated) -> None:
        self._audit.write("EntryUpdated", {"title": e.title})

    def on_user_logged_in(self, e: UserLoggedIn) -> None:
        self._audit.write("UserLoggedIn", {"username": e.username})

    def on_user_logged_out(self, e: UserLoggedOut) -> None:
        self._audit.write("UserLoggedOut", {"username": e.username})
