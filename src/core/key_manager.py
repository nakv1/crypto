from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from core.crypto.key_derivation import (
    Argon2Params,
    KeyDerivationService,
    PasswordPolicy,
    PasswordStrengthValidator,
    Pbkdf2Params,
    pack_parameter_bundle,
    unpack_parameter_bundle,
)
from core.crypto.key_storage import KeyCacheConfig, PlatformSecretStore, SecureKeyCache
from database.db import Database


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class KdfParams:
    algorithm: str = "pbkdf2_hmac_sha256"
    iterations: int = 100000
    dklen: int = 32
    salt_len: int = 16

    def to_json(self) -> str:
        return json.dumps(
            {
                "algorithm": self.algorithm,
                "iterations": int(self.iterations),
                "dklen": int(self.dklen),
                "salt_len": int(self.salt_len),
            },
            ensure_ascii=False,
        )

    @staticmethod
    def from_json(raw: str) -> "KdfParams":
        try:
            data = json.loads(raw)
        except Exception:
            return KdfParams()
        if not isinstance(data, dict):
            return KdfParams()
        return KdfParams(
            algorithm=str(data.get("algorithm", "pbkdf2_hmac_sha256")),
            iterations=max(100000, int(data.get("iterations", 100000))),
            dklen=max(16, int(data.get("dklen", 32))),
            salt_len=max(16, int(data.get("salt_len", 16))),
        )


class KeyManager:
    auth_hash_key_type = "auth_hash"
    enc_salt_key_type = "enc_salt"
    params_key_type = "params"
    current_key_version = 1

    def __init__(
        self,
        db: Database,
        argon2_params: Optional[Argon2Params] = None,
        pbkdf2_params: Optional[Pbkdf2Params] = None,
        password_policy: Optional[PasswordPolicy] = None,
        cache_config: Optional[KeyCacheConfig] = None,
    ):
        self.db = db
        self.argon2_params = (argon2_params or Argon2Params()).validated()
        self.pbkdf2_params = (pbkdf2_params or Pbkdf2Params()).validated()
        self.password_policy = password_policy or PasswordPolicy()

        self.password_validator = PasswordStrengthValidator(self.password_policy)
        self.derivation = KeyDerivationService(self.argon2_params, self.pbkdf2_params)
        self.key_cache = SecureKeyCache(cache_config or KeyCacheConfig())
        self.secret_store = PlatformSecretStore()

    def bind_database(self, db: Database) -> None:
        self.db = db

    def configure_parameters(
        self,
        argon2_params: Optional[Argon2Params] = None,
        pbkdf2_params: Optional[Pbkdf2Params] = None,
        password_policy: Optional[PasswordPolicy] = None,
    ) -> None:
        if argon2_params is not None:
            self.argon2_params = argon2_params.validated()
            self.derivation.set_argon2_params(self.argon2_params)
        if pbkdf2_params is not None:
            self.pbkdf2_params = pbkdf2_params.validated()
            self.derivation.set_pbkdf2_params(self.pbkdf2_params)
        if password_policy is not None:
            self.password_policy = password_policy
            self.password_validator = PasswordStrengthValidator(self.password_policy)

    def configure_cache(self, cache_config: KeyCacheConfig) -> None:
        self.key_cache.set_config(cache_config)

    def set_cache_policy(self, idle_timeout_sec: int, lock_when_inactive: bool) -> None:
        self.configure_cache(
            KeyCacheConfig(
                idle_timeout_sec=max(60, int(idle_timeout_sec)),
                lock_when_inactive=bool(lock_when_inactive),
                use_memory_protection=self.key_cache.config.use_memory_protection,
            )
        )

    def validate_password_strength(self, password: str) -> tuple[bool, list[str]]:
        return self.password_validator.validate(password)

    def serialize_parameter_bundle(self) -> bytes:
        return pack_parameter_bundle(
            argon2_params=self.argon2_params,
            pbkdf2_params=self.pbkdf2_params,
            password_policy=self.password_policy,
        )

    def load_parameter_bundle(self) -> tuple[Argon2Params, Pbkdf2Params, PasswordPolicy]:
        raw = self.load_key_data(self.params_key_type)
        if raw is None:
            return self.argon2_params, self.pbkdf2_params, self.password_policy
        argon2_params, pbkdf2_params, policy = unpack_parameter_bundle(raw)
        return argon2_params, pbkdf2_params, policy

    def refresh_parameters_from_storage(self) -> None:
        argon2_params, pbkdf2_params, policy = self.load_parameter_bundle()
        self.configure_parameters(
            argon2_params=argon2_params,
            pbkdf2_params=pbkdf2_params,
            password_policy=policy,
        )

    def is_master_password_configured(self) -> bool:
        auth_hash = self.load_key_data(self.auth_hash_key_type)
        enc_salt = self.load_key_data(self.enc_salt_key_type)
        return auth_hash is not None and enc_salt is not None

    def setup_master_password(self, password: str) -> None:
        ok, reasons = self.validate_password_strength(password)
        if not ok:
            raise ValueError(" ".join(reasons))

        auth_hash = self.create_auth_hash(password)
        salt = self.make_salt(self.pbkdf2_params.salt_len)
        params_payload = self.serialize_parameter_bundle()

        self.store_key_data(self.auth_hash_key_type, auth_hash.encode("utf-8"), self.current_key_version)
        self.store_key_data(self.enc_salt_key_type, salt, self.current_key_version)
        self.store_key_data(self.params_key_type, params_payload, self.current_key_version)

    def create_auth_hash(self, password: str) -> str:
        self.refresh_parameters_from_storage_if_exists()
        return self.derivation.create_auth_hash(password)

    def verify_master_password(self, password: str) -> bool:
        raw_hash = self.load_key_data(self.auth_hash_key_type)
        if raw_hash is None:
            return False
        self.refresh_parameters_from_storage_if_exists()
        try:
            hash_text = raw_hash.decode("utf-8")
        except Exception:
            return False
        return self.derivation.verify_auth_hash(password, hash_text)

    def derive_master_encryption_key(self, password: str, key_type: str = "vault_encryption") -> bytes:
        self.refresh_parameters_from_storage_if_exists()
        salt = self.load_key_data(self.enc_salt_key_type)
        if salt is None:
            raise RuntimeError("Соль для ключа шифрования не настроена.")
        return self.derivation.derive_encryption_key(
            password=password,
            salt=salt,
            params=self.pbkdf2_params,
            key_type=key_type,
        )

    def derive_encryption_key_with_salt(
        self,
        password: str,
        salt: bytes,
        key_type: str = "vault_encryption",
    ) -> bytes:
        self.refresh_parameters_from_storage_if_exists()
        return self.derivation.derive_encryption_key(
            password=password,
            salt=salt,
            params=self.pbkdf2_params,
            key_type=key_type,
        )

    def cache_encryption_key(self, key: bytes) -> None:
        self.key_cache.cache_key(key)

    def get_active_key(self, key_type: str = "vault_encryption") -> bytes:
        base_key = self.key_cache.get_key()
        if base_key is None:
            raise RuntimeError("Ключ сессии отсутствует или истек.")
        if key_type == "vault_encryption":
            return base_key
        return self.derivation.derive_key_from_master(
            master_key=base_key,
            key_type=key_type,
            key_len=self.pbkdf2_params.key_len,
        )

    def clear_cached_key(self, reason: str = "manual") -> None:
        self.key_cache.clear_key(reason)

    def touch_cached_key(self) -> None:
        self.key_cache.touch_activity()

    def has_cached_key(self) -> bool:
        return self.key_cache.has_key()

    def set_application_active(self, app_is_active: bool) -> None:
        self.key_cache.set_application_active(app_is_active)

    def make_salt(self, length: int = 16) -> bytes:
        return self.derivation.make_salt(length)

    @staticmethod
    def verifier(key: bytes) -> bytes:
        return hashlib.sha256(key).digest()

    def store_key_data(self, key_type: str, key_data: bytes, version: int = 1) -> None:
        with self.db.session() as conn:
            self.store_key_data_with_connection(conn, key_type, key_data, version)

    def store_key_data_with_connection(self, conn, key_type: str, key_data: bytes, version: int = 1) -> None:
        if not isinstance(key_type, str) or not key_type.strip():
            raise ValueError("key_type не может быть пустым")
        if not isinstance(key_data, (bytes, bytearray)) or len(key_data) == 0:
            raise ValueError("key_data не может быть пустым")
        if int(version) < 1:
            raise ValueError("version должен быть >= 1")

        conn.execute(
            """
            INSERT INTO key_store (key_type, key_data, version, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key_type, version)
            DO UPDATE SET key_data = excluded.key_data, created_at = excluded.created_at
            """,
            (key_type, bytes(key_data), int(version), utc_now_iso()),
        )

    def load_key_data(self, key_type: str, version: Optional[int] = None) -> Optional[bytes]:
        sql = """
        SELECT key_data
        FROM key_store
        WHERE key_type = ?
        """
        params: list[object] = [key_type]
        if version is not None:
            sql += " AND version = ?"
            params.append(int(version))
        sql += " ORDER BY version DESC LIMIT 1"

        with self.db.session() as conn:
            row = conn.execute(sql, tuple(params)).fetchone()
        if row is None:
            return None

        val = row["key_data"]
        if isinstance(val, (bytes, bytearray, memoryview)):
            return bytes(val)
        if isinstance(val, str):
            return val.encode("utf-8")
        return None

    def refresh_parameters_from_storage_if_exists(self) -> None:
        raw = self.load_key_data(self.params_key_type)
        if raw is None:
            return
        argon2_params, pbkdf2_params, policy = unpack_parameter_bundle(raw)
        self.configure_parameters(argon2_params=argon2_params, pbkdf2_params=pbkdf2_params, password_policy=policy)

    # Совместимость со Sprint 1 API
    def derive_key(self, password: str, salt: bytes, params: Optional[KdfParams] = None) -> bytes:
        p = params or KdfParams(
            iterations=self.pbkdf2_params.iterations,
            dklen=self.pbkdf2_params.key_len,
            salt_len=self.pbkdf2_params.salt_len,
        )
        pbkdf2 = Pbkdf2Params(iterations=p.iterations, key_len=p.dklen, salt_len=p.salt_len).validated()
        return self.derivation.derive_encryption_key(password=password, salt=salt, params=pbkdf2, key_type="legacy")

    def store_key(self, key_type: str, salt: bytes, verifier_hash: bytes, params: KdfParams) -> None:
        payload = {
            "salt_b64": base64.b64encode(salt).decode("utf-8"),
            "hash_b64": base64.b64encode(verifier_hash).decode("utf-8"),
            "params": params.to_json(),
        }
        self.store_key_data(
            key_type=f"legacy:{key_type}",
            key_data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            version=1,
        )

    def load_key(self, key_type: str) -> Optional[tuple[bytes, bytes, KdfParams]]:
        raw = self.load_key_data(f"legacy:{key_type}")
        if raw is None:
            return None
        try:
            payload = json.loads(raw.decode("utf-8"))
            salt = base64.b64decode(payload["salt_b64"])
            hash_value = base64.b64decode(payload["hash_b64"])
            params = KdfParams.from_json(payload.get("params", "{}"))
            return salt, hash_value, params
        except Exception:
            return None
