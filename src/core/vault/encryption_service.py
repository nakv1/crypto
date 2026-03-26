from __future__ import annotations

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultEncryptionService:
    nonce_size = 12
    key_size = 32
    auth_tag_size = 16

    def ensure_valid_key(self, key: bytes) -> bytes:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("Ключ должен быть bytes.")
        key_bytes = bytes(key)
        if len(key_bytes) != self.key_size:
            raise ValueError("Требуется ключ AES-256 длиной 32 байта.")
        return key_bytes

    def serialize_payload(self, payload: dict[str, Any]) -> bytes:
        if not isinstance(payload, dict):
            raise TypeError("payload должен быть словарем.")
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def deserialize_payload(self, payload_bytes: bytes) -> dict[str, Any]:
        try:
            decoded = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Не удалось декодировать полезную нагрузку записи.") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Полезная нагрузка записи должна быть объектом JSON.")
        return decoded

    def pack_encrypted_payload(self, nonce: bytes, ciphertext_and_tag: bytes) -> str:
        return base64.b64encode(bytes(nonce) + bytes(ciphertext_and_tag)).decode("utf-8")

    def unpack_encrypted_payload(self, encrypted_data: str) -> tuple[bytes, bytes]:
        if not isinstance(encrypted_data, str) or not encrypted_data:
            raise ValueError("encrypted_data пустой или имеет неверный тип.")
        try:
            raw = base64.b64decode(encrypted_data.encode("utf-8"), validate=True)
        except Exception as exc:
            raise ValueError("encrypted_data не является корректным base64.") from exc
        min_len = self.nonce_size + self.auth_tag_size
        if len(raw) < min_len:
            raise ValueError("encrypted_data имеет некорректную длину.")
        nonce = raw[: self.nonce_size]
        ciphertext_and_tag = raw[self.nonce_size :]
        return nonce, ciphertext_and_tag

    def encrypt_payload(self, payload: dict[str, Any], key: bytes) -> str:
        key_bytes = self.ensure_valid_key(key)
        plaintext = self.serialize_payload(payload)
        nonce = os.urandom(self.nonce_size)
        ciphertext_and_tag = AESGCM(key_bytes).encrypt(nonce, plaintext, None)
        return self.pack_encrypted_payload(nonce, ciphertext_and_tag)

    def decrypt_payload(self, encrypted_data: str, key: bytes) -> dict[str, Any]:
        key_bytes = self.ensure_valid_key(key)
        nonce, ciphertext_and_tag = self.unpack_encrypted_payload(encrypted_data)
        try:
            plaintext = AESGCM(key_bytes).decrypt(nonce, ciphertext_and_tag, None)
        except InvalidTag as exc:
            raise ValueError("Обнаружена подмена данных записи.") from exc
        except Exception as exc:
            raise ValueError("Не удалось расшифровать запись.") from exc
        return self.deserialize_payload(plaintext)

    def reencrypt_payload(self, encrypted_data: str, old_key: bytes, new_key: bytes) -> str:
        payload = self.decrypt_payload(encrypted_data, old_key)
        return self.encrypt_payload(payload, new_key)
