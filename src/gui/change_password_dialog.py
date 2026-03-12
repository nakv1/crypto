from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QVBoxLayout

from gui.widgets.password_entry import PasswordEntry


@dataclass(frozen=True)
class ChangePasswordData:
    current_password: str
    new_password: str
    confirm_password: str


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Смена мастер-пароля")
        self.setMinimumWidth(420)

        self.current_entry = PasswordEntry("Текущий мастер-пароль")
        self.new_entry = PasswordEntry("Новый мастер-пароль")
        self.confirm_entry = PasswordEntry("Подтверждение нового пароля")

        form = QFormLayout()
        form.addRow("Текущий:", self.current_entry)
        form.addRow("Новый:", self.new_entry)
        form.addRow("Подтверждение:", self.confirm_entry)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def data(self) -> ChangePasswordData:
        return ChangePasswordData(
            current_password=self.current_entry.text(),
            new_password=self.new_entry.text(),
            confirm_password=self.confirm_entry.text(),
        )
