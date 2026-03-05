from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox, QDialog

from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from gui.login_dialog import LoginDialog
from gui.setup_wizard import SetupWizard

from core.audit_logger import AuditLogger
from core.config import ConfigManager
from core.events import EventBus, UserLoggedIn, UserLoggedOut
from core.state_manager import StateManager
from database.db import Database
from database.repositories import AuditRepository, SettingsRepository, VaultRepository
from gui.main_window import MainWindow


class CryptoSafeApp:
    def run(self, app: QApplication) -> int:
        # 1) Загружаем конфигурацию приложения
        cfg_mgr = ConfigManager()
        cfg = cfg_mgr.load()

        # 2) Приоритет пути к БД:
        env_db_path = os.getenv("CRYPTOSAFE_DB_PATH")
        db_path = env_db_path or str(cfg.db_path)

        # 3) Инициализация сервисов
        # База данных
        db = Database(Path(db_path))
        db.connect()
        # Шина событий
        bus = EventBus()

        # Менеджер состояния
        state = StateManager()

        key_manager = KeyManager(db)
        master_key_record = key_manager.load_key("master")


        if master_key_record is None:
            wizard = SetupWizard(
                cfg_mgr=cfg_mgr,
                db=db,
                key_manager=key_manager,
                state=state,
            )
            result = wizard.exec()

            if result != QDialog.Accepted:
                QMessageBox.critical(
                    None,
                    "CryptoSafe",
                    "Setup не завершён. Приложение будет закрыто."
                )
                return 0

            # Мастер мог создать БД в новом месте. Переподключаемся.
            cfg = cfg_mgr.load()
            try:
                db.close()
            except Exception:
                pass
            db = Database(Path(cfg.db_path))
            db.connect()
            key_manager = KeyManager(db)
        else:
            for _ in range(3):
                dlg = LoginDialog()
                if dlg.exec() != QDialog.Accepted:
                    return 0
                password = dlg.password()
                if not password:
                    QMessageBox.warning(None, "CryptoSafe", "Пароль не может быть пустым.")
                    continue
                salt, verifier, params = master_key_record
                try:
                    key = key_manager.derive_key(password, salt, params)
                except Exception:
                    QMessageBox.warning(None, "CryptoSafe", "Не удалось проверить пароль.")
                    continue
                if key_manager.verifier(key) != verifier:
                    QMessageBox.warning(None, "CryptoSafe", "Неверный пароль.")
                    continue
                state.unlock(key)
                break
            if not state.is_unlocked():
                QMessageBox.critical(None, "CryptoSafe", "Доступ к хранилищу не получен.")
                return 0

        crypto = AES256Placeholder()
        vault_repo = VaultRepository(db=db, crypto=crypto, key_provider=state.get_master_key)
        settings_repo = SettingsRepository(db=db, crypto=crypto, key_provider=state.get_master_key)
        # Репозиторий аудита
        audit_repo = AuditRepository(db)

        # Логгер аудита (подписывается на события)
        audit = AuditLogger(bus, audit_repo)
        audit.start()

        if state.is_unlocked():
            bus.publish(UserLoggedIn(username=state.username()))

        # Главное окно приложения
        main = MainWindow(
            bus=bus,
            state=state,
            audit_repo=audit_repo,
            vault_repo=vault_repo,
            settings_repo=settings_repo,
        )
        main.show()

        # Главный цикл Qt + гарантированное освобождение ресурсов
        try:
            code = app.exec()
            return int(code)
        finally:
            # Корректно останавливаем EventBus
            try:
                if state.is_unlocked():
                    bus.publish(UserLoggedOut(username=state.username()))
                bus.shutdown()
            finally:
                # Закрываем базу данных в любом случае
                db.close()
