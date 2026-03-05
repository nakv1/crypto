from __future__ import annotations

import json
import os
import stat
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

        project_root = Path(__file__).resolve().parents[2]
        default_path = self._default_db_path()

        # Если путь относительный — берём дефолт (data/vault.db)
        if not db_path.is_absolute():
            db_path = default_path

        # Если путь указывает на корень проекта/vault.db — тоже заменяем
        elif db_path.resolve() == (project_root / "vault.db").resolve():
            db_path = default_path

        return AppConfig(
            env=self._env,
            db_path=db_path,
        )

    def save(self, cfg: AppConfig) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "env": cfg.env,
            "db_path": str(Path(cfg.db_path).resolve()),
        }
        self._file.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        try:
            if os.name != "nt" and self._file.exists():
                os.chmod(self._file, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except Exception:
            pass

    def set_db_path(self, db_path: Path) -> AppConfig:
        cfg = self.load()
        cfg.db_path = Path(db_path)
        self.save(cfg)
        return cfg

    def _make_default(self) -> AppConfig:
        return AppConfig(env=self._env, db_path=self._default_db_path())

    def _default_db_path(self) -> Path:
        project_root = Path(__file__).resolve().parents[2]
        data_dir = project_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / "vault.db"

    @property
    def config_path(self) -> Path:
        return self._file
