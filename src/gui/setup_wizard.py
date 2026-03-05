from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Slot
from PySide6.QtWidgets import (
    QWizard,
    QWizardPage,
    QVBoxLayout,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFileDialog,
    QMessageBox,
)

from core.config import ConfigManager
from core.key_manager import KeyManager, KdfParams
from core.state_manager import StateManager
from database.db import Database
from gui.widgets.password_entry import PasswordEntry


class SetupWizard(QWizard):
    def __init__(
        self,
        cfg_mgr: ConfigManager,
        db: Database,
        key_manager: KeyManager,
        state: StateManager,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Первоначальная настройка")
        self.setWizardStyle(QWizard.ModernStyle)

        self.cfg_mgr = cfg_mgr
        self.db = db
        self.km = key_manager
        self.state = state

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
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
            return
        db_path = self.page_db.db_path()
        iterations = self.page_crypto.iterations()


        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Нужно выбрать путь к базе данных")
            return

        # Сохраняем bootstrap-конфиг (только путь к БД)
        cfg = self.cfg_mgr.load()
        cfg.db_path = Path(db_path)

        self.cfg_mgr.save(cfg)

        # Поднимаем БД и создаём schema.
        self.db.close()

        new_db = Database(cfg.db_path)
        new_db.connect()

        # Важно: обновляем ссылки, чтобы KeyManager работал с подключенной БД
        self.db = new_db
        self.km = KeyManager(self.db)

        # Генерируем salt и сохраняем verifier (Sprint 1).
        salt = self.km.make_salt(16)
        params = KdfParams(iterations=int(iterations))
        master_key = self.km.derive_key(password, salt, params)
        verifier = self.km.verifier(master_key)
        self.km.store_key("master", salt, verifier, params)

        # Разблокируем сессию (Sprint 1).
        self.state.unlock(master_key)

        from core.crypto.placeholder import AES256Placeholder
        from database.repositories import SettingsRepository

        crypto = AES256Placeholder()
        settings = SettingsRepository(
            db=self.db,
            crypto=crypto,
            key_provider=self.state.get_master_key,
        )

        # Sprint 1: базовые настройки (как минимум — placeholders)
        settings.set("ui.clipboard_timeout_sec", "15", encrypted=False)
        settings.set("security.auto_lock_minutes", "5", encrypted=False)

        # iterations уже хранятся в key_store
        settings.set("crypto.kdf.iterations", str(int(iterations)), encrypted=False)
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
        layout.addWidget(QLabel("Подсказка: используй длинный пароль (12+ символов)."))

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
        self.btn = QPushButton("Выбрать…")
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
        self.setTitle("Параметры шифрования")
        self.setSubTitle("Заглушка параметров формирования ключа (Sprint 1).")

        self.iterations_input = QLineEdit("200000")
        self.iterations_input.setPlaceholderText("Например: 200000")

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("PBKDF2 iterations:", self.iterations_input)
        layout.addLayout(form)
        layout.addWidget(QLabel("В Sprint 2/3 тут будут расширенные настройки."))

    def iterations(self) -> int:
        try:
            v = int(self.iterations_input.text().strip())
            return max(50000, v)
        except Exception:
            return 200000
