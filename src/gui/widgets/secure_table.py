from __future__ import annotations

from dataclasses import dataclass
from typing import List

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableView


@dataclass(frozen=True)
class VaultRow:
    entry_id: int
    title: str
    username: str
    url: str
    tags: str
    updated_at: str


class VaultTableModel(QAbstractTableModel):
    def __init__(self, rows: List[VaultRow]):
        super().__init__()
        self.rows = rows
        self.headers = ["Название", "Логин", "URL", "Теги", "Обновлено"]

    def set_rows(self, rows: List[VaultRow]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None

        row = self.rows[index.row()]
        col = index.column()

        if col == 0:
            return row.title
        if col == 1:
            return row.username
        if col == 2:
            return row.url
        if col == 3:
            return row.tags
        if col == 4:
            return row.updated_at
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and 0 <= section < len(self.headers):
            return self.headers[section]
        return None


class SecureTable(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.table = QTableView()
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)

        self.model = VaultTableModel([])
        self.table.setModel(self.model)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.table)

    def set_rows(self, rows: List[VaultRow]) -> None:
        self.model.set_rows(rows)

    def table_view(self) -> QTableView:
        return self.table

    def selected_entry_id(self) -> int | None:
        index = self.table.currentIndex()
        if not index.isValid():
            return None
        row = self.model.rows[index.row()]
        return int(row.entry_id)
