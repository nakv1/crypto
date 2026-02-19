from __future__ import annotations

import time

from core.events import EventBus, EntryAdded


def test_publish_sync():
    bus = EventBus()
    seen = []

    def handler(e):
        seen.append(e.title)

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded(title="A"), async_mode=False)
    assert seen == ["A"]
    bus.shutdown()


def test_publish_async():
    bus = EventBus()
    seen = []

    def handler(e):
        seen.append(e.title)

    bus.subscribe(EntryAdded, handler)
    bus.publish(EntryAdded(title="B"), async_mode=True)
    # Дадим чуть времени пулу
    for _ in range(50):
        if seen:
            break
        time.sleep(0.01)
    assert seen == ["B"]
    bus.shutdown()
