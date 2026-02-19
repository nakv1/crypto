from __future__ import annotations

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit


class AuditLogViewer(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self._title = QLabel("Журнал аудита (заглушка Sprint 1)")
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setPlaceholderText("В Sprint 5 здесь будет полноценный просмотр и фильтрация.")

        layout = QVBoxLayout(self)
        layout.addWidget(self._title)
        layout.addWidget(self._text, 1)

    def set_text(self, text: str) -> None:
        self._text.setPlainText(text)
