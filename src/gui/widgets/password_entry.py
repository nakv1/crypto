from __future__ import annotations

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QToolButton


class PasswordEntry(QWidget):
    def __init__(self, placeholder: str = "Пароль", parent: QWidget | None = None):
        super().__init__(parent)

        self.edit = QLineEdit()
        self.edit.setPlaceholderText(placeholder)
        self.edit.setEchoMode(QLineEdit.Password)

        self.btn = QToolButton()
        self.btn.setText("👁")
        self.btn.setToolTip("Показать/скрыть")
        self.btn.setCheckable(True)
        self.btn.toggled.connect(self.on_toggled)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.edit, 1)
        layout.addWidget(self.btn)

    def text(self) -> str:
        return self.edit.text()

    def setText(self, value: str) -> None:
        self.edit.setText(value)

    def clear(self) -> None:
        self.edit.clear()

    def line_edit(self) -> QLineEdit:
        return self.edit

    @Slot(bool)
    def on_toggled(self, checked: bool) -> None:
        self.edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
