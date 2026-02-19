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

        self._cfg_mgr = cfg_mgr
        self._db = db
        self._km = key_manager
        self._state = state

        self._page_password = _PasswordPage()
        self._page_db = _DbPathPage(cfg_mgr)
        self._page_crypto = _CryptoParamsPage(cfg_mgr)

        self.addPage(self._page_password)
        self.addPage(self._page_db)
        self.addPage(self._page_crypto)

        self.button(QWizard.FinishButton).clicked.connect(self._on_finish_clicked)

    @Slot()
    def _on_finish_clicked(self) -> None:
        password = self._page_password.password()
        db_path = self._page_db.db_path()
        iterations = self._page_crypto.iterations()

        if not password:
            QMessageBox.warning(self, "Ошибка", "Мастер-пароль не может быть пустым")
            return
        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Нужно выбрать путь к базе данных")
            return

        # Сохраняем конфиг (путь к БД + параметры KDF).
        cfg = self._cfg_mgr.load()
        cfg.db_path = Path(db_path)
        cfg.kdf_iterations = int(iterations)
        self._cfg_mgr.save(cfg)

        # Поднимаем БД и создаём schema.
        self._db.close()
        self._db.__init__(cfg.db_path)  # простая инициализация на новый путь
        self._db.connect()

        # Генерируем salt и сохраняем verifier (Sprint 1).
        salt = self._km.make_salt(16)
        params = KdfParams(iterations=int(iterations))
        master_key = self._km.derive_key(password, salt, params)
        verifier = self._km.verifier(master_key)
        self._km.store_key("master", salt, verifier, params)

        # Разблокируем сессию (Sprint 1).
        self._state.unlock(master_key)


class _PasswordPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Мастер-пароль")
        self.setSubTitle("Создай мастер-пароль. Он будет нужен для доступа к базе.")

        self._pwd1 = PasswordEntry("Мастер-пароль")
        self._pwd2 = PasswordEntry("Подтверждение")

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("Пароль:", self._pwd1)
        form.addRow("Повтори:", self._pwd2)
        layout.addLayout(form)
        layout.addWidget(QLabel("Подсказка: используй длинный пароль (12+ символов)."))

    def password(self) -> str:
        p1 = self._pwd1.text()
        p2 = self._pwd2.text()
        if p1 != p2:
            return ""
        return p1


class _DbPathPage(QWizardPage):
    def __init__(self, cfg_mgr: ConfigManager):
        super().__init__()
        self.setTitle("Расположение базы")
        self.setSubTitle("Выбери файл локальной базы данных (SQLite).")

        cfg = cfg_mgr.load()
        self._path = QLineEdit(str(cfg.db_path))
        self._btn = QPushButton("Выбрать…")
        self._btn.clicked.connect(self._choose)

        form = QFormLayout()
        form.addRow("Файл БД:", self._path)
        form.addRow("", self._btn)

        layout = QVBoxLayout(self)
        layout.addLayout(form)

    @Slot()
    def _choose(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Файл базы данных", self._path.text(), "SQLite DB (*.db)")
        if path:
            self._path.setText(path)

    def db_path(self) -> str:
        return self._path.text().strip()


class _CryptoParamsPage(QWizardPage):
    def __init__(self, cfg_mgr: ConfigManager):
        super().__init__()
        self.setTitle("Параметры шифрования")
        self.setSubTitle("Заглушка параметров формирования ключа (Sprint 1).")

        cfg = cfg_mgr.load()
        self._iterations = QLineEdit(str(cfg.kdf_iterations))
        self._iterations.setPlaceholderText("Например: 200000")

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.addRow("PBKDF2 iterations:", self._iterations)
        layout.addLayout(form)
        layout.addWidget(QLabel("В Sprint 2/3 тут будут расширенные настройки."))

    def iterations(self) -> int:
        try:
            v = int(self._iterations.text().strip())
            return max(50_000, v)
        except Exception:
            return 200_000
