from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from database.db import Database
from core.security import secure_buffer


@dataclass(frozen=True)
class KdfParams:
    algorithm: str = "pbkdf2_hmac_sha256"
    iterations: int = 200_000
    dklen: int = 32

    def to_json(self) -> str:
        return json.dumps(
            {"algorithm": self.algorithm, "iterations": self.iterations, "dklen": self.dklen},
            ensure_ascii=False,
        )

    @staticmethod
    def from_json(s: str) -> "KdfParams":
        try:
            obj = json.loads(s)
            return KdfParams(
                algorithm=obj.get("algorithm", "pbkdf2_hmac_sha256"),
                iterations=int(obj.get("iterations", 200_000)),
                dklen=int(obj.get("dklen", 32)),
            )
        except Exception:
            # В Sprint 1 не валим приложение из‑за кривых параметров.
            return KdfParams()


class KeyManager:
    def __init__(self, db: Database):
        self._db = db

    def derive_key(self, password: str, salt: bytes, params: Optional[KdfParams] = None) -> bytes:
        if not isinstance(password, str) or not password:
            raise ValueError("Пароль не может быть пустым")
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("salt должен быть bytes и длиной >= 8")

        p = params or KdfParams()
        # Важно: работаем через bytearray и затираем его.
        with secure_buffer(password.encode("utf-8")) as pwd_buf:
            return hashlib.pbkdf2_hmac("sha256", bytes(pwd_buf), bytes(salt), p.iterations, dklen=p.dklen)

    def store_key(self, key_type: str, salt: bytes, verifier_hash: bytes, params: KdfParams) -> None:
        if not key_type.strip():
            raise ValueError("key_type не может быть пустым")
        if not salt:
            raise ValueError("salt не может быть пустым")
        if not verifier_hash:
            raise ValueError("verifier_hash не может быть пустым")

        with self._db.session() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, salt, hash, params)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key_type) DO UPDATE SET salt=excluded.salt, hash=excluded.hash, params=excluded.params
                """,
                (key_type, salt, verifier_hash, params.to_json()),
            )

    def load_key(self, key_type: str) -> Optional[tuple[bytes, bytes, KdfParams]]:
        with self._db.session() as conn:
            row = conn.execute(
                "SELECT salt, hash, params FROM key_store WHERE key_type = ?",
                (key_type,),
            ).fetchone()
        if not row:
            return None

        salt = row["salt"]
        h = row["hash"]
        params = KdfParams.from_json(row["params"] or "")
        return salt, h, params

    @staticmethod
    def make_salt(length: int = 16) -> bytes:
        return os.urandom(length)

    @staticmethod
    def verifier(key: bytes) -> bytes:
        return hashlib.sha256(key).digest()