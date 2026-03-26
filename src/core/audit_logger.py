from core.events import (
    EventBus,
    EntryAdded,
    EntryCreated,
    EntryUpdated,
    EntryDeleted,
    UserLoggedIn,
    UserLoggedOut,
    ClipboardCopied,
    ClipboardCleared,
)
from database.repositories import AuditRepository


class AuditLogger:

    def __init__(self, bus: EventBus, audit_repo: AuditRepository) -> None:
        self.bus = bus
        self.audit = audit_repo

    def start(self) -> None:
        self.bus.subscribe(EntryAdded, self.on_entry_added)
        self.bus.subscribe(EntryCreated, self.on_entry_created)
        self.bus.subscribe(EntryUpdated, self.on_entry_updated)
        self.bus.subscribe(EntryDeleted, self.on_entry_deleted)
        self.bus.subscribe(UserLoggedIn, self.on_user_logged_in)
        self.bus.subscribe(UserLoggedOut, self.on_user_logged_out)
        self.bus.subscribe(ClipboardCopied, self.on_clipboard_copied)
        self.bus.subscribe(ClipboardCleared, self.on_clipboard_cleared)

    def on_entry_added(self, e: EntryAdded) -> None:
        self.audit.write("EntryAdded", {"title": e.title})

    def on_entry_created(self, e: EntryCreated) -> None:
        self.audit.write("EntryCreated", {"entry_id": e.entry_id, "title": e.title})

    def on_entry_deleted(self, e: EntryDeleted) -> None:
        self.audit.write("EntryDeleted", {"entry_id": e.entry_id, "title": e.title})

    def on_entry_updated(self, e: EntryUpdated) -> None:
        self.audit.write("EntryUpdated", {"entry_id": e.entry_id, "title": e.title})

    def on_user_logged_in(self, e: UserLoggedIn) -> None:
        self.audit.write("UserLoggedIn", {"username": e.username})

    def on_user_logged_out(self, e: UserLoggedOut) -> None:
        self.audit.write("UserLoggedOut", {"username": e.username})

    def on_clipboard_copied(self, e: ClipboardCopied) -> None:
        self.audit.write("ClipboardCopied", {"entry_id": e.entry_id})

    def on_clipboard_cleared(self, e: ClipboardCleared) -> None:
        self.audit.write("ClipboardCleared", {"reason": e.reason})
