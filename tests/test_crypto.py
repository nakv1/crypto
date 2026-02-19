from __future__ import annotations

import pytest

from core.crypto.placeholder import AES256Placeholder

def test_xor_encrypt_decrypt_roundtrip():
    crypto = AES256Placeholder()
    key = b"secret-key"
    pt = b"hello world"

    ct = crypto.encrypt(pt, key)
    assert ct != pt

    out = crypto.decrypt(ct, key)
    assert out == pt


def test_empty_key_rejected():
    crypto = AES256Placeholder()
    with pytest.raises(ValueError):
        crypto.encrypt(b"x", b"")
