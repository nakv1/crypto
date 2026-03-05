from __future__ import annotations

from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox

from gui.widgets.password_entry import PasswordEntry


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход в хранилище")
        self.setMinimumWidth(360)

        self.pwd = PasswordEntry("Мастер-пароль")

        title = QLabel("Введите мастер-пароль для открытия хранилища.")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.pwd)
        layout.addWidget(buttons)

    def password(self) -> str:
        return self.pwd.text()
