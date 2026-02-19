
from dataclasses import dataclass

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit,
    QDialogButtonBox
)


@dataclass
class EntryFormData:
    title: str
    username: str
    password: str
    url: str
    notes: str
    tags: str


class EntryDialog(QDialog):
    def __init__(self, parent=None, title: str = "Запись", preset: EntryFormData | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(420)

        self.txt_title = QLineEdit()
        self.txt_username = QLineEdit()
        self.txt_password = QLineEdit()
        self.txt_password.setEchoMode(QLineEdit.Password)
        self.txt_url = QLineEdit()
        self.txt_tags = QLineEdit()
        self.txt_notes = QTextEdit()

        form = QFormLayout()
        form.addRow("Название:", self.txt_title)
        form.addRow("Логин:", self.txt_username)
        form.addRow("Пароль:", self.txt_password)
        form.addRow("URL:", self.txt_url)
        form.addRow("Теги:", self.txt_tags)
        form.addRow("Заметки:", self.txt_notes)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(btns)

        if preset is not None:
            self.txt_title.setText(preset.title)
            self.txt_username.setText(preset.username)
            self.txt_password.setText(preset.password)
            self.txt_url.setText(preset.url)
            self.txt_tags.setText(preset.tags)
            self.txt_notes.setPlainText(preset.notes)

    def get_data(self) -> EntryFormData:
        return EntryFormData(
            title=self.txt_title.text().strip(),
            username=self.txt_username.text().strip(),
            password=self.txt_password.text(),
            url=self.txt_url.text().strip(),
            notes=self.txt_notes.toPlainText().strip(),
            tags=self.txt_tags.text().strip(),
        )