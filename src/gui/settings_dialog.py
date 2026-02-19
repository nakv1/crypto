from __future__ import annotations

from PySide6.QtWidgets import QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout, QLineEdit, QLabel


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Настройки")
        self.resize(520, 360)

        tabs = QTabWidget()
        tabs.addTab(_SecurityTab(), "Безопасность")
        tabs.addTab(_UiTab(), "Внешний вид")
        tabs.addTab(_AdvancedTab(), "Дополнительно")

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)


class _SecurityTab(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        self.clip_timeout = QLineEdit("15")
        self.auto_lock = QLineEdit("5")
        form.addRow("Таймаут буфера (сек):", self.clip_timeout)
        form.addRow("Авто-блокировка (мин):", self.auto_lock)
        form.addRow("", QLabel("Настройки будут применяться в следующих спринтах."))


class _UiTab(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        self.theme = QLineEdit("System")
        self.lang = QLineEdit("ru")
        form.addRow("Тема:", self.theme)
        form.addRow("Язык:", self.lang)
        form.addRow("", QLabel("Заглушка Sprint 1."))


class _AdvancedTab(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        self.backup = QLineEdit("")
        self.export = QLineEdit("")
        form.addRow("Резервное копирование:", self.backup)
        form.addRow("Экспорт:", self.export)
        form.addRow("", QLabel("Заглушка Sprint 1."))
