from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox, QWidget

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
    @staticmethod
    def apply_cache_policy_from_settings(settings_repo: SettingsRepository, key_manager: KeyManager) -> None:
        try:
            timeout_raw = settings_repo.get("security.auto_lock_timeout_sec", "3600") or "3600"
            timeout_val = max(60, int(timeout_raw))
        except Exception:
            timeout_val = 3600
        focus_raw = settings_repo.get("security.lock_on_focus_loss", "1") or "1"
        lock_on_focus = str(focus_raw).strip() != "0"
        key_manager.set_cache_policy(idle_timeout_sec=timeout_val, lock_when_inactive=lock_on_focus)

    def open_database_context(
        self,
        db_path: Path,
        cfg_mgr: ConfigManager,
        bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> tuple[Optional[dict], str]:
        try:
            db = Database(db_path)
            db.connect()
        except Exception as exc:
            return None, f"Не удалось открыть базу: {exc}"

        state = StateManager()
        key_manager = KeyManager(db)
        crypto = AES256Placeholder(key_manager)
        auth = AuthenticationService(key_manager=key_manager, state=state, bus=bus)

        if not auth.has_master_password():
            wizard = SetupWizard(
                cfg_mgr=cfg_mgr,
                db=db,
                key_manager=key_manager,
                auth_service=auth,
                parent=parent,
            )
            result = wizard.exec()
            if result != QDialog.Accepted:
                db.close()
                return None, "Открытие отменено: setup не завершен."
        else:
            while True:
                dlg = LoginDialog(parent)
                if dlg.exec() != QDialog.Accepted:
                    db.close()
                    return None, "Открытие отменено пользователем."
                password = dlg.password()
                if not password:
                    QMessageBox.warning(parent, "CryptoSafe", "Пароль не может быть пустым.")
                    continue

                result = auth.authenticate(password=password, username="user")
                if result.success:
                    break

                QMessageBox.warning(
                    parent,
                    "CryptoSafe",
                    f"{result.message} Следующая попытка через {result.delay_sec} сек.",
                )
                auth.apply_backoff_delay(result.delay_sec)

        vault_repo = VaultRepository(db=db, crypto=crypto)
        settings_repo = SettingsRepository(db=db, crypto=crypto)
        audit_repo = AuditRepository(db)
        self.apply_cache_policy_from_settings(settings_repo, key_manager)

        return {
            "db": db,
            "state": state,
            "key_manager": key_manager,
            "crypto": crypto,
            "auth": auth,
            "audit_repo": audit_repo,
            "vault_repo": vault_repo,
            "settings_repo": settings_repo,
        }, ""

    def run(self, app: QApplication) -> int:
        cfg_mgr = ConfigManager()
        cfg = cfg_mgr.load()

        env_db_path = os.getenv("CRYPTOSAFE_DB_PATH")
        db_path = Path(env_db_path) if env_db_path else Path(cfg.db_path)

        bus = EventBus()
        runtime, message = self.open_database_context(
            db_path=db_path,
            cfg_mgr=cfg_mgr,
            bus=bus,
            parent=None,
        )
        if runtime is None:
            if message:
                QMessageBox.critical(None, "CryptoSafe", message)
            return 0

        db = runtime["db"]
        state = runtime["state"]
        key_manager = runtime["key_manager"]
        auth = runtime["auth"]
        audit_repo = runtime["audit_repo"]
        vault_repo = runtime["vault_repo"]
        settings_repo = runtime["settings_repo"]

        audit = AuditLogger(bus, audit_repo)
        audit.start()

        main = MainWindow(
            bus=bus,
            state=state,
            auth_service=auth,
            audit_repo=audit_repo,
            vault_repo=vault_repo,
            settings_repo=settings_repo,
        )
        main.setWindowTitle(f"CryptoSafe Manager by nak - {db.db_path.name}")

        auth_holder = {"auth": auth}

        def switch_database(new_path: Path) -> tuple[bool, str]:
            nonlocal db, state, key_manager, auth, audit_repo, vault_repo, settings_repo

            target_path = Path(new_path).resolve()
            if db.db_path.resolve() == target_path:
                return True, f"Эта база уже открыта: {target_path.name}"

            new_runtime, open_error = self.open_database_context(
                db_path=target_path,
                cfg_mgr=cfg_mgr,
                bus=bus,
                parent=main,
            )
            if new_runtime is None:
                return False, open_error

            old_db = db
            old_auth = auth

            try:
                old_auth.logout(emit_event=True)
            except Exception:
                pass

            db = new_runtime["db"]
            state = new_runtime["state"]
            key_manager = new_runtime["key_manager"]
            auth = new_runtime["auth"]
            audit_repo = new_runtime["audit_repo"]
            vault_repo = new_runtime["vault_repo"]
            settings_repo = new_runtime["settings_repo"]

            audit.audit = audit_repo
            auth_holder["auth"] = auth
            main.apply_runtime_context(
                state=state,
                auth_service=auth,
                audit_repo=audit_repo,
                vault_repo=vault_repo,
                settings_repo=settings_repo,
                db_path=db.db_path,
            )

            try:
                old_db.close()
            except Exception:
                pass

            if env_db_path is None:
                try:
                    cfg_mgr.set_db_path(db.db_path)
                except Exception:
                    pass

            return True, f"Открыта база: {target_path.name}"

        main.open_database_handler = switch_database
        main.show()

        def on_app_state_changed(new_state) -> None:
            auth_holder["auth"].handle_application_activity(new_state == Qt.ApplicationActive)

        app.applicationStateChanged.connect(on_app_state_changed)

        try:
            code = app.exec()
            return int(code)
        finally:
            try:
                auth_holder["auth"].logout(emit_event=True)
                bus.shutdown()
            finally:
                db.close()
