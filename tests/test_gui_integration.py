from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
from PySide6.QtWidgets import QApplication

from core.config import ConfigManager
from core.crypto.authentication import AuthenticationService
from core.crypto.placeholder import AES256Placeholder
from core.events import EventBus
from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database
from database.repositories import AuditRepository, SettingsRepository, VaultRepository
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard


@pytest.fixture
def qapp():
    app = QApplication.instance() or QApplication(sys.argv)
    return app


def test_setup_wizard_creates_keystore(tmp_path: Path, qapp, monkeypatch):
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
    auth = AuthenticationService(key_manager=km, state=state)

    wiz = SetupWizard(cfg_mgr, db, km, auth)
    wiz.page_password.pwd1.setText("UltraSafeA1!Key")
    wiz.page_password.pwd2.setText("UltraSafeA1!Key")
    wiz.page_db.path.setText(str(cfg.db_path))
    wiz.page_crypto.pbkdf2_input.setText("100000")
    wiz.page_crypto.auto_lock_input.setText("3600")
    wiz.page_crypto.focus_lock_input.setText("1")
    wiz.on_finish_clicked()

    assert state.is_unlocked()
    assert km.is_master_password_configured()

    db.close()


def test_main_window_launch(tmp_path: Path, qapp):
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)
    bus = EventBus()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state, bus=bus)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")

    crypto = AES256Placeholder(km)
    vault_repo = VaultRepository(db=db, crypto=crypto)
    settings_repo = SettingsRepository(db=db, crypto=crypto)

    window = MainWindow(
        bus=bus,
        state=state,
        auth_service=auth,
        audit_repo=audit,
        vault_repo=vault_repo,
        settings_repo=settings_repo,
    )
    window.show()
    assert window.menuBar() is not None
    window.close()

    bus.shutdown()
    db.close()


def test_main_window_search_history_keeps_last10(tmp_path: Path, qapp):
    del qapp
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)
    bus = EventBus()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state, bus=bus)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(km)
    vault_repo = VaultRepository(db=db, crypto=crypto)
    settings_repo = SettingsRepository(db=db, crypto=crypto)

    window = MainWindow(
        bus=bus,
        state=state,
        auth_service=auth,
        audit_repo=audit,
        vault_repo=vault_repo,
        settings_repo=settings_repo,
    )

    for index in range(12):
        window.push_search_history(f"query-{index}")

    assert len(window.search_history) == 10
    assert window.search_history[0] == "query-11"
    assert window.search_history[-1] == "query-2"

    stored = settings_repo.get("ui.search_history", "[]") or "[]"
    parsed = json.loads(stored)
    assert isinstance(parsed, list)
    assert len(parsed) == 10
    assert parsed[0] == "query-11"

    window.close()
    bus.shutdown()
    db.close()


def test_main_window_locks_ui_on_inactive_and_restores_after_auth(tmp_path: Path, qapp):
    del qapp
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)
    bus = EventBus()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state, bus=bus)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(km)
    vault_repo = VaultRepository(db=db, crypto=crypto)
    settings_repo = SettingsRepository(db=db, crypto=crypto)
    vault_repo.add(
        title="Mail",
        username="nakv1",
        password="UltraSafeA1!Key",
        url="https://gmail.com",
        notes="demo",
        tags="mail",
        category="Personal",
    )

    window = MainWindow(
        bus=bus,
        state=state,
        auth_service=auth,
        audit_repo=audit,
        vault_repo=vault_repo,
        settings_repo=settings_repo,
    )
    window.reload_table()
    assert window.secure_table.model.rowCount() >= 1
    assert window.centralWidget().isEnabled() is True

    auth.handle_application_activity(False)
    window.sync_lock_state(prompt_relogin_on_active=False)
    assert state.is_unlocked() is False
    assert window.secure_table.model.rowCount() == 0
    assert window.centralWidget().isEnabled() is False

    auth.handle_application_activity(True)
    relogin = auth.authenticate("UltraSafeA1!Key", username="nak")
    assert relogin.success is True
    window.sync_lock_state(prompt_relogin_on_active=False)
    assert state.is_unlocked() is True
    assert window.centralWidget().isEnabled() is True
    assert window.secure_table.model.rowCount() >= 1

    window.close()
    bus.shutdown()
    db.close()


def test_enter_locked_mode_clears_clipboard_only_on_first_transition(tmp_path: Path, qapp):
    del qapp
    db = Database(tmp_path / "vault.db")
    db.connect()
    audit = AuditRepository(db)
    bus = EventBus()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state, bus=bus)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(km)
    vault_repo = VaultRepository(db=db, crypto=crypto)
    settings_repo = SettingsRepository(db=db, crypto=crypto)

    window = MainWindow(
        bus=bus,
        state=state,
        auth_service=auth,
        audit_repo=audit,
        vault_repo=vault_repo,
        settings_repo=settings_repo,
    )

    clipboard = QApplication.clipboard()
    clipboard.setText("should-be-cleared")
    window.enter_locked_mode()
    assert clipboard.text() == ""

    clipboard.setText("copied-after-lock")
    window.enter_locked_mode()
    assert clipboard.text() == "copied-after-lock"

    window.close()
    bus.shutdown()
    db.close()
