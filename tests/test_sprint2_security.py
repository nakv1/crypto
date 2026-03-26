from __future__ import annotations

import os

import pytest

from core.crypto.authentication import AuthenticationService
from core.crypto.key_derivation import Argon2Params, KeyDerivationService, Pbkdf2Params
from core.crypto.key_storage import SecureKeyCache
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database
from database.repositories import VaultRepository


def test_argon2_parameter_validation():
    variants = [
        Argon2Params(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16),
        Argon2Params(time_cost=4, memory_cost=131072, parallelism=2, hash_len=32, salt_len=16),
    ]
    for params in variants:
        service = KeyDerivationService(argon2_params=params, pbkdf2_params=Pbkdf2Params())
        hash_value = service.create_auth_hash("UltraSafeA1!Key")
        assert service.verify_auth_hash("UltraSafeA1!Key", hash_value) is True
        assert service.verify_auth_hash("WrongUltraSafeA1!Key", hash_value) is False


def test_key_derivation_consistency_100_times():
    service = KeyDerivationService()
    salt = os.urandom(16)
    keys = {service.derive_encryption_key("UltraSafeA1!Key", salt) for _ in range(100)}
    assert len(keys) == 1


def test_timing_resistance_uses_compare_digest(monkeypatch):
    import core.crypto.key_derivation as derivation_module

    calls: list[tuple[bytes, bytes]] = []

    def fake_compare(left: bytes, right: bytes) -> bool:
        calls.append((bytes(left), bytes(right)))
        return left == right

    monkeypatch.setattr(derivation_module.secrets, "compare_digest", fake_compare)

    service = KeyDerivationService()
    hash_value = service.create_auth_hash("UltraSafeA1!Key")
    assert service.verify_auth_hash("UltraSafeA1!Key", hash_value) is True
    assert service.verify_auth_hash("WrongUltraSafeA1!Key", hash_value) is False
    assert len(calls) >= 2


def test_memory_safety_cache_zeroizes_key():
    cache = SecureKeyCache()
    cache.cache_key(b"A" * 32)
    raw_ref = cache.key_data
    assert raw_ref is not None
    assert any(byte != 0 for byte in raw_ref)
    cache.clear_key("manual")
    assert all(byte == 0 for byte in raw_ref)


def test_password_change_integration_with_ten_entries(tmp_path):
    db = Database(tmp_path / "vault.db")
    db.connect()
    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(km)
    vault = VaultRepository(db=db, crypto=crypto)

    entry_ids: list[int] = []
    for i in range(10):
        entry_ids.append(
            vault.add(
                title=f"entry-{i}",
                username="nak",
                password=f"secret-{i}",
                notes=f"note-{i}",
            )
        )

    auth.change_master_password(
        current_password="UltraSafeA1!Key",
        new_password="UltraSafeB2!Key",
        db=db,
        crypto=crypto,
    )

    auth.logout(emit_event=False)
    result_old = auth.authenticate("UltraSafeA1!Key", username="nak")
    assert result_old.success is False

    result_new = auth.authenticate("UltraSafeB2!Key", username="nak")
    assert result_new.success is True

    for i, entry_id in enumerate(entry_ids):
        row = vault.get_by_id(entry_id)
        assert row is not None
        assert row["password"] == f"secret-{i}"
        assert row["notes"] == f"note-{i}"

    db.close()
