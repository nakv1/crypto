
from dataclasses import dataclass
from typing import Callable, Dict, List, Type, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import threading


# Базовый класс события
class Event:
    pass

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

    def __init__(self):
        self._subscribers: Dict[Type[Event], List[Callable[[Event], Any]]] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=2)

    def subscribe(self, event_type: Type[Event], handler: Callable[[Event], Any]) -> None:
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(handler)

    def publish(self, event: Event, async_mode: bool = False) -> None:
        with self._lock:
            handlers = list(self._subscribers.get(type(event), []))

        for handler in handlers:
            if async_mode:
                self._executor.submit(handler, event)
            else:
                handler(event)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)