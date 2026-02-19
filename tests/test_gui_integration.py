from __future__ import annotations

import sys
from pathlib import Path

import pytest
from PySide6.QtWidgets import QApplication

from core.config import ConfigManager
from core.key_manager import KeyManager
from core.state_manager import StateManager
from core.events import EventBus
from database.db import Database
from database.repositories import AuditRepository
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard


@pytest.fixture
def qapp():
    app = QApplication.instance() or QApplication(sys.argv)
    return app


def test_setup_wizard_creates_keystore(tmp_path: Path, qapp, monkeypatch):
    # Подменяем HOME, чтобы ConfigManager писал конфиг в tmp.
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_mgr = ConfigManager(env="test")
    cfg = cfg_mgr.load()
    cfg.db_path = tmp_path / "vault.db"
    cfg_mgr.save(cfg)

    db = Database(cfg.db_path)
    db.connect()
    km = KeyManager(db)
    state = StateManager()

    wiz = SetupWizard(cfg_mgr, db, km, state)
    # Заполняем страницы напрямую.
    wiz._page_password._pwd1.setText("StrongPassword123")
    wiz._page_password._pwd2.setText("StrongPassword123")
    wiz._page_db._path.setText(str(cfg.db_path))
    wiz._page_crypto._iterations.setText("200000")
    wiz._on_finish_clicked()

    assert state.is_unlocked()
    assert km.load_key("master") is not None

    db.close()


def test_main_window_launch(tmp_path: Path, qapp):
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)

    bus = EventBus()
    state = StateManager()

    w = MainWindow(bus=bus, state=state, audit_repo=audit)
    w.show()
    assert w.menuBar() is not None
    w.close()

    bus.shutdown()
    db.close()
