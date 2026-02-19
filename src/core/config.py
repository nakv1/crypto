from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def _default_env() -> str:
    return os.environ.get("CRYPTOSAFE_ENV", "dev").strip().lower() or "dev"


def _app_dir(env: str) -> Path:
    home = Path.home()
    base = home / ".cryptosafe_manager"
    return base / env


@dataclass
class AppConfig:
    env: str
    db_path: Path
    # Заглушки будущих настроек
    clipboard_timeout_sec: int = 15
    auto_lock_minutes: int = 5
    kdf_iterations: int = 200_000


class ConfigManager:
    def __init__(self, env: Optional[str] = None):
        self._env = (env or _default_env()).strip().lower()
        self._dir = _app_dir(self._env)
        self._file = self._dir / "config.json"

    def load(self) -> AppConfig:
        self._dir.mkdir(parents=True, exist_ok=True)

        if not self._file.exists():
            cfg = self._make_default()
            self.save(cfg)
            return cfg

        try:
            raw = json.loads(self._file.read_text(encoding="utf-8"))
        except Exception:
            # Если конфиг битый — используем дефолт (не раскрываем деталей пользователю).
            cfg = self._make_default()
            self.save(cfg)
            return cfg

        db_path = Path(raw.get("db_path") or str(self._default_db_path()))
        return AppConfig(
            env=self._env,
            db_path=db_path,
            clipboard_timeout_sec=int(raw.get("clipboard_timeout_sec", 15)),
            auto_lock_minutes=int(raw.get("auto_lock_minutes", 5)),
            kdf_iterations=int(raw.get("kdf_iterations", 200_000)),
        )

    def save(self, cfg: AppConfig) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "env": cfg.env,
            "db_path": str(cfg.db_path),
            "clipboard_timeout_sec": int(cfg.clipboard_timeout_sec),
            "auto_lock_minutes": int(cfg.auto_lock_minutes),
            "kdf_iterations": int(cfg.kdf_iterations),
        }
        self._file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def set_db_path(self, db_path: Path) -> AppConfig:
        cfg = self.load()
        cfg.db_path = Path(db_path)
        self.save(cfg)
        return cfg

    def _make_default(self) -> AppConfig:
        return AppConfig(env=self._env, db_path=self._default_db_path())

    def _default_db_path(self) -> Path:
        return self._dir / "vault.db"

    @property
    def config_path(self) -> Path:
        return self._file
