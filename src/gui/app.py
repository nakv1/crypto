from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from core.audit_logger import AuditLogger
from core.config import ConfigManager
from core.crypto.authentication import AuthenticationService
from core.crypto.placeholder import AES256Placeholder
from core.events import EventBus
from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database
from database.repositories import AuditRepository, SettingsRepository, VaultRepository
from gui.login_dialog import LoginDialog
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard


class CryptoSafeApp:
    def run(self, app: QApplication) -> int:
        cfg_mgr = ConfigManager()
        cfg = cfg_mgr.load()

        env_db_path = os.getenv("CRYPTOSAFE_DB_PATH")
        db_path = env_db_path or str(cfg.db_path)

        db = Database(Path(db_path))
        db.connect()

        bus = EventBus()
        state = StateManager()
        key_manager = KeyManager(db)
        crypto = AES256Placeholder(key_manager)
        auth = AuthenticationService(key_manager=key_manager, state=state, bus=bus)

        audit_repo = AuditRepository(db)
        audit = AuditLogger(bus, audit_repo)
        audit.start()

        if not auth.has_master_password():
            wizard = SetupWizard(
                cfg_mgr=cfg_mgr,
                db=db,
                key_manager=key_manager,
                auth_service=auth,
            )
            result = wizard.exec()
            if result != QDialog.Accepted:
                QMessageBox.critical(None, "CryptoSafe", "Setup не завершен. Приложение будет закрыто.")
                return 0
        else:
            while True:
                dlg = LoginDialog()
                if dlg.exec() != QDialog.Accepted:
                    return 0
                password = dlg.password()
                if not password:
                    QMessageBox.warning(None, "CryptoSafe", "Пароль не может быть пустым.")
                    continue

                result = auth.authenticate(password=password, username="user")
                if result.success:
                    break

                QMessageBox.warning(
                    None,
                    "CryptoSafe",
                    f"{result.message} Следующая попытка через {result.delay_sec} сек.",
                )
                auth.apply_backoff_delay(result.delay_sec)

        vault_repo = VaultRepository(db=db, crypto=crypto)
        settings_repo = SettingsRepository(db=db, crypto=crypto)

        try:
            timeout_raw = settings_repo.get("security.auto_lock_timeout_sec", "3600") or "3600"
            timeout_val = max(60, int(timeout_raw))
        except Exception:
            timeout_val = 3600
        focus_raw = settings_repo.get("security.lock_on_focus_loss", "1") or "1"
        lock_on_focus = str(focus_raw).strip() != "0"
        key_manager.set_cache_policy(idle_timeout_sec=timeout_val, lock_when_inactive=lock_on_focus)

        main = MainWindow(
            bus=bus,
            state=state,
            auth_service=auth,
            audit_repo=audit_repo,
            vault_repo=vault_repo,
            settings_repo=settings_repo,
        )
        main.show()

        def on_app_state_changed(new_state) -> None:
            auth.handle_application_activity(new_state == Qt.ApplicationActive)

        app.applicationStateChanged.connect(on_app_state_changed)

        try:
            code = app.exec()
            return int(code)
        finally:
            try:
                auth.logout(emit_event=True)
                bus.shutdown()
            finally:
                db.close()
