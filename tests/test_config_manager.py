from __future__ import annotations

import json
from pathlib import Path

from core.config import ConfigManager


def test_config_manager_creates_default(tmp_path: Path, monkeypatch):
    # изолируем home
    monkeypatch.setenv("CRYPTOSAFE_ENV", "test")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    mgr = ConfigManager()
    cfg = mgr.load()
    assert cfg.env == "test"
    assert cfg.db_path.name.endswith("vault.db")
    assert mgr.config_path.exists()


def test_config_manager_save_and_load(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("CRYPTOSAFE_ENV", "test")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    mgr = ConfigManager()
    cfg = mgr.load()
    new_db = tmp_path / "x" / "my.db"
    cfg.db_path = new_db
    mgr.save(cfg)

    raw = json.loads(mgr.config_path.read_text(encoding="utf-8"))
    assert "db_path" in raw

    cfg2 = mgr.load()
    assert cfg2.db_path == new_db.resolve()
