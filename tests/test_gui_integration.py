from __future__ import annotations

import sys
from pathlib import Path

import pytest
pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from core.config import ConfigManager
from core.key_manager import KeyManager
from core.state_manager import StateManager
from core.events import EventBus
from database.db import Database
from database.repositories import AuditRepository, SettingsRepository, VaultRepository
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard
from core.crypto.placeholder import AES256Placeholder


@pytest.fixture
def qapp():
    app = QApplication.instance() or QApplication(sys.argv)
    return app


def test_setup_wizard_creates_keystore(tmp_path: Path, qapp, monkeypatch):
    # Подменяем HOME, чтобы ConfigManager писал конфиг в tmp.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
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
    wiz.page_password.pwd1.setText("StrongPassword123")
    wiz.page_password.pwd2.setText("StrongPassword123")
    wiz.page_db.path.setText(str(cfg.db_path))
    wiz.page_crypto.iterations_input.setText("200000")
    wiz.on_finish_clicked()

    assert state.is_unlocked()
    assert km.load_key("master") is not None

    db.close()


def test_main_window_launch(tmp_path: Path, qapp):
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)

    bus = EventBus()
    state = StateManager()
    crypto = AES256Placeholder()
    vault_repo = VaultRepository(db=db, crypto=crypto, key_provider=state.get_master_key)
    settings_repo = SettingsRepository(db=db, crypto=crypto, key_provider=state.get_master_key)

    w = MainWindow(
        bus=bus,
        state=state,
        audit_repo=audit,
        vault_repo=vault_repo,
        settings_repo=settings_repo,
    )
    w.show()
    assert w.menuBar() is not None
    w.close()

    bus.shutdown()
    db.close()
