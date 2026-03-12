from __future__ import annotations

from abc import ABC, abstractmethod

from core.key_manager import KeyManager


class EncryptionService(ABC):
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager

    def encrypt(self, data: bytes, key_type: str = "vault_encryption") -> bytes:
        key = self.key_manager.get_active_key(key_type=key_type)
        return self.encrypt_with_key(data, key)

    def decrypt(self, ciphertext: bytes, key_type: str = "vault_encryption") -> bytes:
        key = self.key_manager.get_active_key(key_type=key_type)
        return self.decrypt_with_key(ciphertext, key)

    @abstractmethod
    def encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """Зашифровать данные указанным ключом."""

    @abstractmethod
    def decrypt_with_key(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровать данные указанным ключом."""
