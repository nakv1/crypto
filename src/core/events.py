from dataclasses import dataclass
from typing import Callable, Dict, List, Type, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import threading
import logging


logger = logging.getLogger(__name__)

# Базовый класс события
class Event:
    """Base class for events."""


# Конкретные события
@dataclass(frozen=True)
class EntryAdded(Event):
    title: str


@dataclass(frozen=True)
class EntryUpdated(Event):
    title: str


@dataclass(frozen=True)
class EntryDeleted(Event):
    title: str


@dataclass(frozen=True)
class UserLoggedIn(Event):
    username: str


@dataclass(frozen=True)
class UserLoggedOut(Event):
    username: str = ""


@dataclass(frozen=True)
class ClipboardCopied(Event):
    entry_id: Optional[int] = None


@dataclass(frozen=True)
class ClipboardCleared(Event):
    reason: str = "timeout"


# EventBus


class EventBus:

    def __init__(self) -> None:
        self.subscribers: Dict[Type[Event], List[Callable[[Event], Any]]] = {}
        self.lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=2)

    def subscribe(self, event_type: Type[Event], handler: Callable[[Event], Any]) -> None:
        with self.lock:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(handler)

    def publish(self, event: Event, async_mode: bool = False) -> None:
        with self.lock:
            handlers = list(self.subscribers.get(type(event), []))

        for handler in handlers:
            if async_mode:
                self.executor.submit(handler, event)
            else:
                try:
                    handler(event)
                except Exception:
                    logger.exception("Event handler failed: %s", handler)

    def shutdown(self) -> None:
        self.executor.shutdown(wait=False, cancel_futures=True)