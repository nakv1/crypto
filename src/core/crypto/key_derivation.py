from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from argon2 import PasswordHasher, Type
from argon2.exceptions import Argon2Error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.security import secure_buffer


@dataclass(frozen=True)
class Argon2Params:
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 4
    hash_len: int = 32
    salt_len: int = 16

    def validated(self) -> "Argon2Params":
        time_cost = max(3, min(int(self.time_cost), 10))
        memory_cost = max(65536, min(int(self.memory_cost), 262144))
        parallelism = max(1, min(int(self.parallelism), 16))
        hash_len = max(16, min(int(self.hash_len), 64))
        salt_len = max(16, min(int(self.salt_len), 64))
        return Argon2Params(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len,
        )

    def to_dict(self) -> Dict[str, int]:
        return {
            "time_cost": int(self.time_cost),
            "memory_cost": int(self.memory_cost),
            "parallelism": int(self.parallelism),
            "hash_len": int(self.hash_len),
            "salt_len": int(self.salt_len),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Argon2Params":
        return Argon2Params(
            time_cost=int(data.get("time_cost", 3)),
            memory_cost=int(data.get("memory_cost", 65536)),
            parallelism=int(data.get("parallelism", 4)),
            hash_len=int(data.get("hash_len", 32)),
            salt_len=int(data.get("salt_len", 16)),
        ).validated()


@dataclass(frozen=True)
class Pbkdf2Params:
    iterations: int = 100000
    salt_len: int = 16
    key_len: int = 32

    def validated(self) -> "Pbkdf2Params":
        iterations = max(100000, min(int(self.iterations), 2000000))
        salt_len = max(16, min(int(self.salt_len), 64))
        key_len = max(16, min(int(self.key_len), 64))
        return Pbkdf2Params(iterations=iterations, salt_len=salt_len, key_len=key_len)

    def to_dict(self) -> Dict[str, int]:
        return {
            "iterations": int(self.iterations),
            "salt_len": int(self.salt_len),
            "key_len": int(self.key_len),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Pbkdf2Params":
        return Pbkdf2Params(
            iterations=int(data.get("iterations", 100000)),
            salt_len=int(data.get("salt_len", 16)),
            key_len=int(data.get("key_len", 32)),
        ).validated()


@dataclass(frozen=True)
class PasswordPolicy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    blocked_patterns: Tuple[str, ...] = (
        "password123",
        "qwerty",
        "123456",
        "admin",
        "letmein",
        "welcome",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "min_length": int(self.min_length),
            "require_upper": bool(self.require_upper),
            "require_lower": bool(self.require_lower),
            "require_digit": bool(self.require_digit),
            "require_symbol": bool(self.require_symbol),
            "blocked_patterns": list(self.blocked_patterns),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "PasswordPolicy":
        patterns_raw = data.get("blocked_patterns", ())
        if not isinstance(patterns_raw, (list, tuple)):
            patterns_raw = ()
        patterns = tuple(str(x).lower() for x in patterns_raw if str(x).strip())
        if not patterns:
            patterns = PasswordPolicy().blocked_patterns
        return PasswordPolicy(
            min_length=max(8, int(data.get("min_length", 12))),
            require_upper=bool(data.get("require_upper", True)),
            require_lower=bool(data.get("require_lower", True)),
            require_digit=bool(data.get("require_digit", True)),
            require_symbol=bool(data.get("require_symbol", True)),
            blocked_patterns=patterns,
        )


class PasswordStrengthValidator:
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        self.policy = policy or PasswordPolicy()

    def validate(self, password: str) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not isinstance(password, str) or not password:
            issues.append("Пароль не может быть пустым.")
            return False, issues

        if len(password) < self.policy.min_length:
            issues.append(f"Минимальная длина пароля: {self.policy.min_length} символов.")

        if self.policy.require_upper and not any(ch.isupper() for ch in password):
            issues.append("Добавь хотя бы одну заглавную букву.")

        if self.policy.require_lower and not any(ch.islower() for ch in password):
            issues.append("Добавь хотя бы одну строчную букву.")

        if self.policy.require_digit and not any(ch.isdigit() for ch in password):
            issues.append("Добавь хотя бы одну цифру.")

        if self.policy.require_symbol and re.search(r"[^A-Za-z0-9]", password) is None:
            issues.append("Добавь хотя бы один спецсимвол.")

        lower = password.lower()
        for pattern in self.policy.blocked_patterns:
            if pattern and pattern in lower:
                issues.append("Пароль содержит слишком распространенный шаблон.")
                break

        return len(issues) == 0, issues


class KeyDerivationService:
    def __init__(
        self,
        argon2_params: Optional[Argon2Params] = None,
        pbkdf2_params: Optional[Pbkdf2Params] = None,
    ):
        self.argon2_params = (argon2_params or Argon2Params()).validated()
        self.pbkdf2_params = (pbkdf2_params or Pbkdf2Params()).validated()
        self.argon2_hasher = self.make_argon2_hasher(self.argon2_params)

    @staticmethod
    def make_argon2_hasher(params: Argon2Params) -> PasswordHasher:
        safe = params.validated()
        return PasswordHasher(
            time_cost=safe.time_cost,
            memory_cost=safe.memory_cost,
            parallelism=safe.parallelism,
            hash_len=safe.hash_len,
            salt_len=safe.salt_len,
            type=Type.ID,
        )

    def set_argon2_params(self, params: Argon2Params) -> None:
        self.argon2_params = params.validated()
        self.argon2_hasher = self.make_argon2_hasher(self.argon2_params)

    def set_pbkdf2_params(self, params: Pbkdf2Params) -> None:
        self.pbkdf2_params = params.validated()

    def create_auth_hash(self, password: str) -> str:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль не может быть пустым")
        return self.argon2_hasher.hash(password)

    def verify_auth_hash(self, password: str, stored_hash: str) -> bool:
        if not isinstance(password, str) or not password:
            secrets.compare_digest(b"0", b"1")
            return False
        if not isinstance(stored_hash, str) or not stored_hash:
            secrets.compare_digest(b"0", b"1")
            return False

        verified = False
        try:
            verified = bool(self.argon2_hasher.verify(stored_hash, password))
        except Argon2Error:
            verified = False
        except Exception:
            verified = False

        return secrets.compare_digest(b"1" if verified else b"0", b"1")

    def derive_encryption_key(
        self,
        password: str,
        salt: bytes,
        params: Optional[Pbkdf2Params] = None,
        key_type: str = "vault_encryption",
    ) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль не может быть пустым")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
            raise ValueError("salt должен быть bytes и длиной >= 16")

        safe = (params or self.pbkdf2_params).validated()
        if len(salt) < safe.salt_len:
            raise ValueError("Длина salt меньше параметра pbkdf2 salt_len")

        domain_salt = bytes(salt) + b"|cryptosafe|" + key_type.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=safe.key_len,
            salt=domain_salt,
            iterations=safe.iterations,
        )
        with secure_buffer(password.encode("utf-8")) as password_buf:
            return kdf.derive(bytes(password_buf))

    @staticmethod
    def derive_key_from_master(master_key: bytes, key_type: str, key_len: int = 32) -> bytes:
        if not isinstance(master_key, (bytes, bytearray)) or len(master_key) == 0:
            raise ValueError("master_key не может быть пустым")
        if not key_type.strip():
            raise ValueError("key_type не может быть пустым")
        if key_len < 16:
            raise ValueError("key_len должен быть >= 16")

        label = key_type.encode("utf-8")
        material = bytearray()
        counter = 1
        while len(material) < key_len:
            block = hmac.new(
                bytes(master_key),
                msg=label + b":" + counter.to_bytes(4, "big"),
                digestmod=hashlib.sha256,
            ).digest()
            material.extend(block)
            counter += 1
        return bytes(material[:key_len])

    def make_salt(self, length: Optional[int] = None) -> bytes:
        size = int(length or self.pbkdf2_params.salt_len)
        if size < 16:
            raise ValueError("Длина соли должна быть >= 16")
        return os.urandom(size)


def pack_parameter_bundle(
    argon2_params: Argon2Params,
    pbkdf2_params: Pbkdf2Params,
    password_policy: PasswordPolicy,
) -> bytes:
    payload = {
        "argon2": argon2_params.validated().to_dict(),
        "pbkdf2": pbkdf2_params.validated().to_dict(),
        "password_policy": password_policy.to_dict(),
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def unpack_parameter_bundle(raw: bytes) -> tuple[Argon2Params, Pbkdf2Params, PasswordPolicy]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return Argon2Params(), Pbkdf2Params(), PasswordPolicy()

    if not isinstance(data, dict):
        return Argon2Params(), Pbkdf2Params(), PasswordPolicy()

    argon2_raw = data.get("argon2", {})
    pbkdf2_raw = data.get("pbkdf2", {})
    policy_raw = data.get("password_policy", {})

    if not isinstance(argon2_raw, dict):
        argon2_raw = {}
    if not isinstance(pbkdf2_raw, dict):
        pbkdf2_raw = {}
    if not isinstance(policy_raw, dict):
        policy_raw = {}

    return (
        Argon2Params.from_dict(argon2_raw),
        Pbkdf2Params.from_dict(pbkdf2_raw),
        PasswordPolicy.from_dict(policy_raw),
    )
