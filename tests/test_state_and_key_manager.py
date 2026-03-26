from __future__ import annotations

from pathlib import Path

import pytest

from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database


def test_state_manager_unlock_lock_cycle():
    state = StateManager()
    assert state.is_unlocked() is False

    state.unlock(username="nak")
    assert state.is_unlocked() is True
    assert state.username() == "nak"

    assert state.register_failed_attempt() == 1
    assert state.register_failed_attempt() == 2
    assert state.failed_attempt_count() == 2

    state.lock()
    assert state.is_unlocked() is False
    assert state.username() == ""
    assert state.failed_attempt_count() == 0


def test_key_manager_setup_verify_and_cache(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    km = KeyManager(db)
    password = "UltraSafeA1!Key"
    km.setup_master_password(password)

    assert km.is_master_password_configured() is True
    assert km.verify_master_password(password) is True
    assert km.verify_master_password("wrong-password") is False

    key = km.derive_master_encryption_key(password)
    km.cache_encryption_key(key)
    assert km.has_cached_key() is True
    assert km.get_active_key() == key

    km.clear_cached_key()
    assert km.has_cached_key() is False
    with pytest.raises(RuntimeError):
        km.get_active_key()

    db.close()
