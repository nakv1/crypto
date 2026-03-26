from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse
import urllib.request

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
)

from core.vault.password_generator import PasswordGenerationConfig, PasswordGenerator


@dataclass
class EntryFormData:
    title: str
    username: str
    password: str
    url: str
    notes: str
    tags: str
    category: str = "General"
    password_generated: bool = False


class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Генерация пароля")
        self.setMinimumWidth(360)

        self.length_input = QSpinBox()
        self.length_input.setRange(8, 64)
        self.length_input.setValue(16)

        self.uppercase_check = QCheckBox("Верхний регистр (A-Z)")
        self.uppercase_check.setChecked(True)
        self.lowercase_check = QCheckBox("Нижний регистр (a-z)")
        self.lowercase_check.setChecked(True)
        self.digits_check = QCheckBox("Цифры (0-9)")
        self.digits_check.setChecked(True)
        self.symbols_check = QCheckBox("Символы")
        self.symbols_check.setChecked(True)
        self.exclude_ambiguous_check = QCheckBox("Исключить неоднозначные символы (l I 1 0 O)")
        self.exclude_ambiguous_check.setChecked(True)
        self.enforce_strength_check = QCheckBox("Требовать высокий уровень надежности")
        self.enforce_strength_check.setChecked(True)

        self.symbols_input = QLineEdit("!@#$%^&*")
        self.symbols_input.setPlaceholderText("Набор спецсимволов")

        form = QFormLayout()
        form.addRow("Длина:", self.length_input)
        form.addRow("Символы:", self.symbols_input)

        checks_layout = QVBoxLayout()
        checks_layout.addWidget(self.uppercase_check)
        checks_layout.addWidget(self.lowercase_check)
        checks_layout.addWidget(self.digits_check)
        checks_layout.addWidget(self.symbols_check)
        checks_layout.addWidget(self.exclude_ambiguous_check)
        checks_layout.addWidget(self.enforce_strength_check)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addLayout(checks_layout)
        root.addWidget(buttons)

    def to_config(self) -> PasswordGenerationConfig:
        return PasswordGenerationConfig(
            length=int(self.length_input.value()),
            use_uppercase=bool(self.uppercase_check.isChecked()),
            use_lowercase=bool(self.lowercase_check.isChecked()),
            use_digits=bool(self.digits_check.isChecked()),
            use_symbols=bool(self.symbols_check.isChecked()),
            symbols=self.symbols_input.text().strip() or "!@#$%^&*",
            exclude_ambiguous=bool(self.exclude_ambiguous_check.isChecked()),
            enforce_strength=bool(self.enforce_strength_check.isChecked()),
            min_strength_score=3,
            history_size=20,
        )


class EntryDialog(QDialog):
    def __init__(self, parent=None, title: str = "Запись", preset: EntryFormData | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        self.password_generator = PasswordGenerator()
        self.password_was_generated = False
        self.last_favicon_domain = ""

        self.txt_title = QLineEdit()
        self.txt_username = QLineEdit()
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.btn_toggle_password = QPushButton("Показать")
        self.btn_generate_password = QPushButton("Сгенерировать")
        self.btn_toggle_password.setFixedWidth(90)
        self.btn_generate_password.setFixedWidth(110)
        self.txt_url = QLineEdit()
        self.txt_url.setPlaceholderText("https://example.com")
        self.lbl_url_status = QLabel("")
        self.lbl_url_status.setWordWrap(True)
        self.lbl_favicon = QLabel("")
        self.lbl_favicon.setFixedSize(20, 20)
        self.lbl_favicon.setAlignment(Qt.AlignCenter)
        self.txt_tags = QLineEdit()
        self.cmb_category = QComboBox()
        self.cmb_category.addItems(["General", "Work", "Personal", "Finance", "Social", "Other"])
        self.txt_notes = QTextEdit()
        self.password_strength = QProgressBar()
        self.password_strength.setRange(0, 100)
        self.password_strength.setValue(0)
        self.lbl_strength_hint = QLabel("Надежность: неизвестно")

        password_layout = QHBoxLayout()
        password_layout.addWidget(self.txt_password, 1)
        password_layout.addWidget(self.btn_toggle_password)
        password_layout.addWidget(self.btn_generate_password)

        url_layout = QHBoxLayout()
        url_layout.addWidget(self.txt_url, 1)
        url_layout.addWidget(self.lbl_favicon)

        form = QFormLayout()
        form.addRow("Название:", self.txt_title)
        form.addRow("Логин:", self.txt_username)
        form.addRow("Пароль:", password_layout)
        form.addRow("Надежность:", self.password_strength)
        form.addRow("", self.lbl_strength_hint)
        form.addRow("URL:", url_layout)
        form.addRow("", self.lbl_url_status)
        form.addRow("Теги:", self.txt_tags)
        form.addRow("Категория:", self.cmb_category)
        form.addRow("Заметки:", self.txt_notes)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.on_accept_clicked)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(buttons)

        self.btn_toggle_password.clicked.connect(self.toggle_password_visibility)
        self.btn_generate_password.clicked.connect(self.open_password_generator_dialog)
        self.txt_password.textChanged.connect(self.on_password_changed)
        self.txt_url.textChanged.connect(self.on_url_changed)
        self.txt_url.editingFinished.connect(self.apply_username_suggestion_if_needed)

        if preset is not None:
            self.txt_title.setText(preset.title)
            self.txt_username.setText(preset.username)
            self.txt_password.setText(preset.password)
            self.txt_url.setText(preset.url)
            self.txt_tags.setText(preset.tags)
            self.txt_notes.setPlainText(preset.notes)
            category_index = self.cmb_category.findText(preset.category)
            if category_index >= 0:
                self.cmb_category.setCurrentIndex(category_index)
            self.password_was_generated = bool(preset.password_generated)

        self.on_password_changed(self.txt_password.text())
        self.on_url_changed(self.txt_url.text())

    def toggle_password_visibility(self) -> None:
        if self.txt_password.echoMode() == QLineEdit.Password:
            self.txt_password.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_password.setText("Скрыть")
            return
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.btn_toggle_password.setText("Показать")

    def open_password_generator_dialog(self) -> None:
        dlg = PasswordGeneratorDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return
        try:
            generated = self.password_generator.generate(dlg.to_config())
        except Exception as exc:
            QMessageBox.warning(self, "CryptoSafe", f"Не удалось сгенерировать пароль: {exc}")
            return
        self.txt_password.setText(generated)
        self.password_was_generated = True
        self.on_password_changed(generated)

    def estimate_strength_score(self, password: str) -> int:
        return self.password_generator.estimate_strength_score(password)

    def update_strength_ui(self, score: int) -> None:
        score_clamped = min(4, max(0, int(score)))
        percent = int((score_clamped / 4) * 100)
        self.password_strength.setValue(percent)
        if score_clamped <= 1:
            self.lbl_strength_hint.setText("Надежность: низкая")
            self.password_strength.setStyleSheet("QProgressBar::chunk { background-color: #d64545; }")
            return
        if score_clamped == 2:
            self.lbl_strength_hint.setText("Надежность: средняя")
            self.password_strength.setStyleSheet("QProgressBar::chunk { background-color: #d6a645; }")
            return
        if score_clamped == 3:
            self.lbl_strength_hint.setText("Надежность: хорошая")
            self.password_strength.setStyleSheet("QProgressBar::chunk { background-color: #5fa84f; }")
            return
        self.lbl_strength_hint.setText("Надежность: высокая")
        self.password_strength.setStyleSheet("QProgressBar::chunk { background-color: #3d8f3d; }")

    def on_password_changed(self, text: str) -> None:
        score = self.estimate_strength_score(text)
        self.update_strength_ui(score)

    def validate_url(self, url_text: str) -> tuple[bool, str]:
        url = url_text.strip()
        if not url:
            return True, ""
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "URL содержит недопустимые символы."
        if parsed.scheme not in ("http", "https"):
            return False, "URL должен начинаться с http:// или https://"
        if not parsed.netloc:
            return False, "URL должен содержать доменное имя."
        return True, parsed.netloc.lower().strip()

    def fetch_favicon(self, domain: str) -> Optional[QPixmap]:
        if not domain:
            return None
        urls = [
            f"https://{domain}/favicon.ico",
            f"http://{domain}/favicon.ico",
            f"https://www.google.com/s2/favicons?domain={domain}&sz=32",
        ]
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=1.5) as response:
                    payload = response.read()
            except Exception:
                continue
            pixmap = QPixmap()
            if pixmap.loadFromData(payload):
                return pixmap
        return None

    def on_url_changed(self, text: str) -> None:
        is_valid, value = self.validate_url(text)
        if is_valid:
            self.txt_url.setStyleSheet("")
            if value:
                self.lbl_url_status.setText(f"Домен: {value}")
            else:
                self.lbl_url_status.setText("")
            if value != self.last_favicon_domain:
                self.last_favicon_domain = value
                pixmap = self.fetch_favicon(value) if value else None
                if pixmap is not None:
                    self.lbl_favicon.setPixmap(pixmap.scaled(16, 16, Qt.KeepAspectRatio, Qt.SmoothTransformation))
                else:
                    self.lbl_favicon.clear()
            return
        self.lbl_url_status.setText(value)
        self.last_favicon_domain = ""
        self.lbl_favicon.clear()
        self.txt_url.setStyleSheet("border: 1px solid #d64545;")

    def suggest_username_from_domain(self, domain: str) -> str:
        if not domain:
            return ""
        normalized = domain.lower().strip()
        if "gmail.com" in normalized or "google.com" in normalized:
            return "name@gmail.com"
        if "github.com" in normalized:
            return "username"
        if "yandex." in normalized:
            return "name@yandex.ru"
        if "mail." in normalized:
            return "name@mail.com"
        if normalized.count(".") >= 1:
            base = normalized.split(".")[0]
            return f"user@{base}.com"
        return "username"

    def apply_username_suggestion_if_needed(self) -> None:
        if self.txt_username.text().strip():
            return
        is_valid, value = self.validate_url(self.txt_url.text())
        if not is_valid or not value:
            return
        suggestion = self.suggest_username_from_domain(value)
        if suggestion:
            self.txt_username.setText(suggestion)

    def validate_before_accept(self) -> tuple[bool, str]:
        title = self.txt_title.text().strip()
        password = self.txt_password.text()
        if not title:
            return False, "Название обязательно."
        if not password:
            return False, "Пароль обязателен."

        is_url_valid, url_message = self.validate_url(self.txt_url.text())
        if not is_url_valid:
            return False, url_message

        score = self.estimate_strength_score(password)
        if not self.password_was_generated and score < 2:
            return False, "Слишком слабый пароль. Усиль пароль или сгенерируй новый."
        return True, ""

    def on_accept_clicked(self) -> None:
        ok, message = self.validate_before_accept()
        if not ok:
            QMessageBox.warning(self, "CryptoSafe", message)
            return
        self.accept()

    def get_data(self) -> EntryFormData:
        return EntryFormData(
            title=self.txt_title.text().strip(),
            username=self.txt_username.text().strip(),
            password=self.txt_password.text(),
            url=self.txt_url.text().strip(),
            notes=self.txt_notes.toPlainText().strip(),
            tags=self.txt_tags.text().strip(),
            category=self.cmb_category.currentText().strip() or "General",
            password_generated=bool(self.password_was_generated),
        )
