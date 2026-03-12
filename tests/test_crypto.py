from __future__ import annotations

from pathlib import Path

import pytest

from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from database.db import Database


def test_xor_encrypt_decrypt_roundtrip(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    km = KeyManager(db)
    km.setup_master_password("UltraSafeA1!Key")
    key = km.derive_master_encryption_key("UltraSafeA1!Key")
    km.cache_encryption_key(key)

    crypto = AES256Placeholder(km)
    pt = b"hello world"

    ct = crypto.encrypt(pt)
    assert ct != pt

    out = crypto.decrypt(ct)
    assert out == pt
    db.close()


def test_empty_key_rejected(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    km = KeyManager(db)
    crypto = AES256Placeholder(km)
    with pytest.raises(ValueError):
        crypto.encrypt_with_key(b"x", b"")

    db.close()
