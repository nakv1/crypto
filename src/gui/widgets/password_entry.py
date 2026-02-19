from __future__ import annotations

from PySide6.QtCore import Slot
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QToolButton


class PasswordEntry(QWidget):
    def __init__(self, placeholder: str = "Пароль", parent: QWidget | None = None):
        super().__init__(parent)

        self._edit = QLineEdit()
        self._edit.setPlaceholderText(placeholder)
        self._edit.setEchoMode(QLineEdit.Password)

        self._btn = QToolButton()
        self._btn.setText("👁")
        self._btn.setToolTip("Показать/скрыть")
        self._btn.setCheckable(True)
        self._btn.toggled.connect(self._on_toggled)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._edit, 1)
        layout.addWidget(self._btn)

    def text(self) -> str:
        return self._edit.text()

    def setText(self, value: str) -> None:
        self._edit.setText(value)

    def clear(self) -> None:
        self._edit.clear()

    def line_edit(self) -> QLineEdit:
        return self._edit

    @Slot(bool)
    def _on_toggled(self, checked: bool) -> None:
        self._edit.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
