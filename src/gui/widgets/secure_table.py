from __future__ import annotations

from dataclasses import dataclass
from typing import List

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTableView


@dataclass(frozen=True)
class VaultRow:
    title: str
    username: str
    url: str
    tags: str
    updated_at: str


class _VaultTableModel(QAbstractTableModel):
    def __init__(self, rows: List[VaultRow]):
        super().__init__()
        self._rows = rows
        self._headers = ["Название", "Логин", "URL", "Теги", "Обновлено"]

    def set_rows(self, rows: List[VaultRow]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None

        row = self._rows[index.row()]
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
        if orientation == Qt.Horizontal and 0 <= section < len(self._headers):
            return self._headers[section]
        return None


class SecureTable(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self._table = QTableView()
        self._table.setSelectionBehavior(QTableView.SelectRows)
        self._table.setSelectionMode(QTableView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setStretchLastSection(True)

        self._model = _VaultTableModel([])
        self._table.setModel(self._model)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._table)

    def set_rows(self, rows: List[VaultRow]) -> None:
        self._model.set_rows(rows)

    def table_view(self) -> QTableView:
        return self._table
