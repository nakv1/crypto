from __future__ import annotations

from core.key_manager import KeyManager

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def __init__(self, key_manager: KeyManager):
        super().__init__(key_manager=key_manager)

    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        return self.xor_data(data, key)

    def decrypt_with_key(self, ciphertext: bytes, key: bytes) -> bytes:
        return self.xor_data(ciphertext, key)

    @staticmethod
    def xor_data(data: bytes, key: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data должен быть bytes")
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("Ключ не может быть пустым")

        out = bytearray(len(data))
        klen = len(key)
        for i, b in enumerate(data):
            out[i] = b ^ key[i % klen]
        return bytes(out)
