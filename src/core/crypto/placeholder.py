from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.key_manager import KeyManager

from .abstract import EncryptionService


class AES256Placeholder(EncryptionService):
    format_marker = b"GCM1"
    nonce_size = 12
    auth_tag_size = 16

    def __init__(self, key_manager: KeyManager):
        super().__init__(key_manager=key_manager)

    @staticmethod
    def ensure_key(key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise ValueError("Ключ должен быть 32 байта для AES-256-GCM.")
        return bytes(key)

    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data должен быть bytes")
        key_bytes = self.ensure_key(key)
        nonce = os.urandom(self.nonce_size)
        ciphertext = AESGCM(key_bytes).encrypt(nonce, bytes(data), None)
        return self.format_marker + nonce + ciphertext

    def decrypt_with_key(self, ciphertext: bytes, key: bytes) -> bytes:
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext должен быть bytes")
        key_bytes = self.ensure_key(key)
        ciphertext_bytes = bytes(ciphertext)
        marker = self.format_marker

        if ciphertext_bytes.startswith(marker):
            payload = ciphertext_bytes[len(marker) :]
            min_len = self.nonce_size + self.auth_tag_size
            if len(payload) < min_len:
                raise ValueError("Некорректная длина шифротекста.")
            nonce = payload[: self.nonce_size]
            encrypted = payload[self.nonce_size :]
            try:
                return AESGCM(key_bytes).decrypt(nonce, encrypted, None)
            except InvalidTag as exc:
                raise ValueError("Обнаружена подмена данных.") from exc
            except Exception as exc:
                raise ValueError("Не удалось расшифровать данные.") from exc

        # Legacy fallback: старые записи Sprint 1/2 зашифрованы XOR.
        return self.xor_data(ciphertext_bytes, key_bytes)

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
