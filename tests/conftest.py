from __future__ import annotations

import os
import sys
from pathlib import Path
import pytest

from database.db import Database


@pytest.fixture(autouse=True)
def qt_offscreen(monkeypatch):
    # Для CI/безголового запуска
    monkeypatch.setenv("QT_QPA_PLATFORM", os.environ.get("QT_QPA_PLATFORM", "offscreen"))


@pytest.fixture(scope="session", autouse=True)
def add_src_to_path():
    root = Path(__file__).resolve().parent.parent
    src = root / "src"
    sys.path.insert(0, str(src))
    return None


@pytest.fixture
def test_db(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()
    try:
        yield db
    finally:
        db.close()
