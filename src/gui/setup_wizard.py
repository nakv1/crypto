from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from core.config import ConfigManager
from core.crypto.authentication import AuthenticationService
from core.crypto.key_derivation import Pbkdf2Params
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from database.db import Database
from database.repositories import SettingsRepository
from gui.widgets.password_entry import PasswordEntry


class SetupWizard(QWizard):
    def __init__(
        self,
        cfg_mgr: ConfigManager,
        db: Database,
        key_manager: KeyManager,
        auth_service: AuthenticationService,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Первоначальная настройка")
        self.setWizardStyle(QWizard.ModernStyle)

        self.cfg_mgr = cfg_mgr
        self.db = db
        self.key_manager = key_manager
        self.auth_service = auth_service

        self.page_password = PasswordPage()
        self.page_db = DbPathPage(cfg_mgr)
        self.page_crypto = CryptoParamsPage()

        self.addPage(self.page_password)
        self.addPage(self.page_db)
        self.addPage(self.page_crypto)

        self.button(QWizard.FinishButton).clicked.connect(self.on_finish_clicked)

    @Slot()
    def on_finish_clicked(self) -> None:
        try:
            password = self.page_password.password()
        except ValueError as exc:
            QMessageBox.warning(self, "Ошибка", str(exc))
            return

        valid, issues = self.key_manager.validate_password_strength(password)
        if not valid:
            QMessageBox.warning(self, "Слабый пароль", "\n".join(issues))
            return

        db_path = self.page_db.db_path()
        pbkdf2_iterations = self.page_crypto.pbkdf2_iterations()
        auto_lock_timeout_sec = self.page_crypto.auto_lock_timeout_sec()
        lock_on_focus_loss = self.page_crypto.lock_on_focus_loss()

        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Нужно выбрать путь к базе данных")
            return

        cfg = self.cfg_mgr.load()
        cfg.db_path = Path(db_path)
        self.cfg_mgr.save(cfg)

        self.db.close()
        self.db.db_path = cfg.db_path
        self.db.connect()
        self.key_manager.bind_database(self.db)

        self.key_manager.configure_parameters(
            pbkdf2_params=Pbkdf2Params(
                iterations=pbkdf2_iterations,
                salt_len=self.key_manager.pbkdf2_params.salt_len,
                key_len=self.key_manager.pbkdf2_params.key_len,
            )
        )
        self.key_manager.set_cache_policy(
            idle_timeout_sec=auto_lock_timeout_sec,
            lock_when_inactive=lock_on_focus_loss,
        )

        self.auth_service.setup_master_password(password, username="user")

        crypto = AES256Placeholder(self.key_manager)
        settings = SettingsRepository(
            db=self.db,
            crypto=crypto,
        )
        settings.set("ui.clipboard_timeout_sec", "15", encrypted=False)
        settings.set("security.auto_lock_timeout_sec", str(auto_lock_timeout_sec), encrypted=False)
        settings.set("security.lock_on_focus_loss", "1" if lock_on_focus_loss else "0", encrypted=False)
        settings.set("security.password_policy", json.dumps(self.key_manager.password_policy.to_dict(), ensure_ascii=False), encrypted=False)
        settings.set(
            "security.kdf_parameters",
            json.dumps(
                {
                    "argon2": self.key_manager.argon2_params.to_dict(),
                    "pbkdf2": self.key_manager.pbkdf2_params.to_dict(),
                },
                ensure_ascii=False,
            ),
            encrypted=False,
        )
        settings.set("crypto.algorithm", "PLACEHOLDER", encrypted=False)


class PasswordPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Мастер-пароль")
        self.setSubTitle("Создай мастер-пароль. Он будет нужен для доступа к базе.")

        self.pwd1 = PasswordEntry("Мастер-пароль")
        self.pwd2 = PasswordEntry("Подтверждение")

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Пароль:", self.pwd1)
        form.addRow("Повтори:", self.pwd2)
        layout.addLayout(form)
        layout.addWidget(QLabel("Подсказка: от 12 символов, буквы в разных регистрах, цифры и спецсимволы."))

    def password(self) -> str:
        p1 = self.pwd1.text()
        p2 = self.pwd2.text()

        if not p1:
            raise ValueError("Мастер-пароль не может быть пустым")

        if p1 != p2:
            raise ValueError("Пароли не совпадают")

        return p1


class DbPathPage(QWizardPage):
    def __init__(self, cfg_mgr: ConfigManager):
        super().__init__()
        self.setTitle("Расположение базы")
        self.setSubTitle("Выбери файл локальной базы данных (SQLite).")

        cfg = cfg_mgr.load()
        self.path = QLineEdit(str(cfg.db_path))
        self.btn = QPushButton("Выбрать...")
        self.btn.clicked.connect(self.choose)

        form = QFormLayout()
        form.addRow("Файл БД:", self.path)
        form.addRow("", self.btn)

        layout = QVBoxLayout(self)
        layout.addLayout(form)

    @Slot()
    def choose(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Файл базы данных", self.path.text(), "SQLite DB (*.db)")
        if path:
            self.path.setText(path)

    def db_path(self) -> str:
        return self.path.text().strip()


class CryptoParamsPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Параметры безопасности")
        self.setSubTitle("Параметры KDF и авто-блокировки.")

        self.pbkdf2_input = QLineEdit("100000")
        self.pbkdf2_input.setPlaceholderText("Например: 100000")

        self.auto_lock_input = QLineEdit("3600")
        self.auto_lock_input.setPlaceholderText("Таймаут в секундах")

        self.focus_lock_input = QLineEdit("1")
        self.focus_lock_input.setPlaceholderText("1 = включено, 0 = выключено")

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("PBKDF2 iterations:", self.pbkdf2_input)
        form.addRow("Auto-lock timeout (sec):", self.auto_lock_input)
        form.addRow("Lock on focus loss (1/0):", self.focus_lock_input)
        layout.addLayout(form)
        layout.addWidget(QLabel("Argon2 используется с безопасными параметрами по умолчанию Sprint2."))

    def pbkdf2_iterations(self) -> int:
        try:
            value = int(self.pbkdf2_input.text().strip())
            return max(100000, value)
        except Exception:
            return 100000

    def auto_lock_timeout_sec(self) -> int:
        try:
            value = int(self.auto_lock_input.text().strip())
            return max(60, value)
        except Exception:
            return 3600

    def lock_on_focus_loss(self) -> bool:
        return self.focus_lock_input.text().strip() != "0"
