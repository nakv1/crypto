from __future__ import annotations

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        return self._xor(data, key)

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        return self._xor(ciphertext, key)

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data должен быть bytes")
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("Ключ не может быть пустым")

        out = bytearray(len(data))
        klen = len(key)
        for i, b in enumerate(data):
            out[i] = b ^ key[i % klen]
        return bytes(out)
