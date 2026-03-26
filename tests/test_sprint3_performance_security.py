from __future__ import annotations

import tracemalloc
from pathlib import Path
from time import perf_counter

import pytest

from core.crypto.authentication import AuthenticationService
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database
from database.repositories import VaultRepository


def make_runtime(tmp_path: Path) -> tuple[Database, AuthenticationService, VaultRepository]:
    db = Database(tmp_path / "vault.db")
    db.connect()
    state = StateManager()
    key_manager = KeyManager(db)
    auth = AuthenticationService(key_manager=key_manager, state=state)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(key_manager)
    vault = VaultRepository(db=db, crypto=crypto)
    return db, auth, vault


def fill_entries(vault: VaultRepository, count: int = 1000) -> None:
    for index in range(count):
        vault.add(
            title=f"title-{index}",
            username=f"user-{index}",
            password=f"StrongPassA1!{index}",
            url=f"https://example{index}.com/login",
            notes=f"note-{index}",
            tags="work,example",
            category="Work",
        )


def test_performance_load_and_search_for_1000_entries(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    fill_entries(vault, 1000)

    list_start = perf_counter()
    all_rows = vault.list()
    list_elapsed = perf_counter() - list_start

    search_start = perf_counter()
    search_rows = vault.search(query="title-999")
    search_elapsed = perf_counter() - search_start

    assert len(all_rows) == 1000
    assert len(search_rows) == 1
    assert list_elapsed < 2.0
    assert search_elapsed < 0.2

    db.close()


def test_memory_usage_under_50mb_for_1000_entries(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    fill_entries(vault, 1000)

    tracemalloc.start()
    vault.list()
    vault.search(query="title-500")
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    del current_bytes
    assert peak_bytes < 50 * 1024 * 1024
    db.close()


def test_list_does_not_keep_plain_passwords(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    fill_entries(vault, 20)
    rows = vault.list()
    assert rows
    assert all(row.password == "" for row in rows)

    db.close()


def test_generic_entry_error_message_does_not_leak_existence(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    with pytest.raises(ValueError, match="Запись недоступна\\."):
        vault.entry_manager.get_entry(999999)

    with pytest.raises(ValueError, match="Запись недоступна\\."):
        vault.entry_manager.update_entry(
            999999,
            {
                "title": "A",
                "username": "B",
                "password": "StrongPassA1!Updated",
            },
        )

    with pytest.raises(ValueError, match="Запись недоступна\\."):
        vault.entry_manager.delete_entry(999999)

    db.close()
