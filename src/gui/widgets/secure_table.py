from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, Signal
from PySide6.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QMenu, QStyle, QTableView, QVBoxLayout, QWidget


@dataclass(frozen=True)
class VaultRow:
    entry_id: int
    title: str
    username: str
    password: str
    url: str
    tags: str
    updated_at: str


class VaultTableModel(QAbstractTableModel):
    def __init__(self, rows: List[VaultRow]):
        super().__init__()
        self.rows = rows
        self.headers = ["Название", "Логин", "Пароль", "Домен", "Обновлено", "Теги"]
        self.visible_password_entry_ids: set[int] = set()
        self.show_all_passwords = False

    def set_rows(self, rows: List[VaultRow]) -> None:
        self.beginResetModel()
        self.rows = rows
        visible_ids = {entry_id for entry_id in self.visible_password_entry_ids}
        row_ids = {row.entry_id for row in rows}
        self.visible_password_entry_ids = visible_ids.intersection(row_ids)
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        del parent
        return len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        del parent
        return len(self.headers)

    @staticmethod
    def domain_from_url(url: str) -> str:
        if not url:
            return ""
        try:
            parsed = urlparse(url)
        except Exception:
            return ""
        return parsed.netloc.lower().strip()

    @staticmethod
    def mask_username(value: str) -> str:
        if not value:
            return ""
        if len(value) <= 4:
            return value
        return value[:4] + "••••"

    @staticmethod
    def mask_password(value: str) -> str:
        if not value:
            return "••••••••"
        size = min(12, max(8, len(value)))
        return "•" * size

    def is_password_visible(self, row_index: int) -> bool:
        if row_index < 0 or row_index >= len(self.rows):
            return False
        row = self.rows[row_index]
        return self.show_all_passwords or row.entry_id in self.visible_password_entry_ids

    def password_icon(self, visible: bool) -> QIcon:
        if visible:
            icon = QIcon.fromTheme("view-visible")
            if not icon.isNull():
                return icon
        else:
            icon = QIcon.fromTheme("view-hidden")
            if not icon.isNull():
                return icon

        style = self.parent().style() if self.parent() is not None else None
        if style is not None:
            if visible:
                std_icon = style.standardIcon(QStyle.SP_DialogApplyButton)
            else:
                std_icon = style.standardIcon(QStyle.SP_DialogCancelButton)
            if not std_icon.isNull():
                return std_icon

        pixmap = self.draw_eye_icon(visible=visible)
        return QIcon(pixmap)

    @staticmethod
    def draw_eye_icon(visible: bool) -> QPixmap:
        pixmap = QPixmap(16, 16)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing, True)

        stroke = QColor("#7a7a7a")
        fill = QColor("#cfcfcf") if visible else QColor("#6f6f6f")
        pupil = QColor("#4d4d4d")

        painter.setPen(QPen(stroke, 1.3))
        painter.setBrush(QBrush(fill))
        painter.drawEllipse(2, 4, 12, 8)
        painter.setBrush(QBrush(pupil))
        painter.drawEllipse(6, 7, 4, 3)

        if visible:
            painter.end()
            return pixmap

        painter.setPen(QPen(QColor("#d64545"), 1.5))
        painter.drawLine(3, 13, 13, 3)
        painter.end()
        return pixmap

    @staticmethod
    def format_timestamp(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            dt = datetime.fromisoformat(text)
            return dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return text

    def toggle_password_for_row(self, row_index: int) -> None:
        if row_index < 0 or row_index >= len(self.rows):
            return
        if self.show_all_passwords:
            return
        entry_id = self.rows[row_index].entry_id
        if entry_id in self.visible_password_entry_ids:
            self.visible_password_entry_ids.remove(entry_id)
        else:
            self.visible_password_entry_ids.add(entry_id)
        left = self.index(row_index, 2)
        right = self.index(row_index, 2)
        self.dataChanged.emit(left, right, [Qt.DisplayRole, Qt.DecorationRole, Qt.ToolTipRole])

    def set_password_for_entry(self, entry_id: int, password_value: str, visible: bool) -> None:
        row_index = -1
        for index, row in enumerate(self.rows):
            if int(row.entry_id) == int(entry_id):
                row_index = index
                break
        if row_index < 0:
            return

        row = self.rows[row_index]
        self.rows[row_index] = VaultRow(
            entry_id=row.entry_id,
            title=row.title,
            username=row.username,
            password=str(password_value or ""),
            url=row.url,
            tags=row.tags,
            updated_at=row.updated_at,
        )

        if visible:
            self.visible_password_entry_ids.add(int(entry_id))
        else:
            if int(entry_id) in self.visible_password_entry_ids:
                self.visible_password_entry_ids.remove(int(entry_id))

        left = self.index(row_index, 2)
        right = self.index(row_index, 2)
        self.dataChanged.emit(left, right, [Qt.DisplayRole, Qt.DecorationRole, Qt.ToolTipRole])

    def clear_all_password_values(self) -> None:
        if not self.rows:
            self.visible_password_entry_ids.clear()
            return
        updated_rows: list[VaultRow] = []
        for row in self.rows:
            updated_rows.append(
                VaultRow(
                    entry_id=row.entry_id,
                    title=row.title,
                    username=row.username,
                    password="",
                    url=row.url,
                    tags=row.tags,
                    updated_at=row.updated_at,
                )
            )
        self.rows = updated_rows
        self.visible_password_entry_ids.clear()
        self.show_all_passwords = False
        left = self.index(0, 2)
        right = self.index(self.rowCount() - 1, 2)
        self.dataChanged.emit(left, right, [Qt.DisplayRole, Qt.DecorationRole, Qt.ToolTipRole])

    def set_show_all_passwords(self, enabled: bool) -> None:
        enabled_flag = bool(enabled)
        if self.show_all_passwords == enabled_flag:
            return
        self.show_all_passwords = enabled_flag
        if self.rowCount() == 0:
            return
        left = self.index(0, 2)
        right = self.index(self.rowCount() - 1, 2)
        self.dataChanged.emit(left, right, [Qt.DisplayRole, Qt.DecorationRole, Qt.ToolTipRole])

    def clear_visible_passwords(self) -> None:
        if not self.visible_password_entry_ids:
            return
        self.visible_password_entry_ids.clear()
        if self.rowCount() == 0:
            return
        left = self.index(0, 2)
        right = self.index(self.rowCount() - 1, 2)
        self.dataChanged.emit(left, right, [Qt.DisplayRole, Qt.DecorationRole, Qt.ToolTipRole])

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None

        row = self.rows[index.row()]
        col = index.column()
        password_visible = self.is_password_visible(index.row())

        if role == Qt.DisplayRole:
            if col == 0:
                return row.title
            if col == 1:
                return self.mask_username(row.username)
            if col == 2:
                text = row.password if password_visible else self.mask_password(row.password)
                return text
            if col == 3:
                return self.domain_from_url(row.url)
            if col == 4:
                return self.format_timestamp(row.updated_at)
            if col == 5:
                return row.tags
            return None

        if role == Qt.ToolTipRole:
            if col == 1:
                return row.username
            if col == 2:
                if password_visible:
                    return "Нажми для скрытия пароля"
                return "Нажми для показа пароля"
            if col == 3:
                return row.url
            if col == 4:
                return row.updated_at
            return None

        if role == Qt.DecorationRole and col == 2:
            return self.password_icon(password_visible)

        if role == Qt.UserRole:
            return row.entry_id

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal and 0 <= section < len(self.headers):
            return self.headers[section]
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        if column == 0:
            self.rows.sort(key=lambda item: item.title.lower(), reverse=reverse)
        elif column == 1:
            self.rows.sort(key=lambda item: item.username.lower(), reverse=reverse)
        elif column == 2:
            self.rows.sort(key=lambda item: item.password, reverse=reverse)
        elif column == 3:
            self.rows.sort(key=lambda item: self.domain_from_url(item.url), reverse=reverse)
        elif column == 4:
            self.rows.sort(key=lambda item: item.updated_at, reverse=reverse)
        elif column == 5:
            self.rows.sort(key=lambda item: item.tags.lower(), reverse=reverse)
        self.layoutChanged.emit()


class SecureTable(QWidget):
    add_requested = Signal()
    edit_requested = Signal()
    delete_requested = Signal()
    copy_password_requested = Signal()
    password_visibility_requested = Signal(int, bool)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)

        self.table = QTableView()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionsMovable(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.clicked.connect(self.on_table_clicked)

        self.model = VaultTableModel([])
        self.table.setModel(self.model)
        self.table.sortByColumn(4, Qt.DescendingOrder)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 150)
        self.table.setColumnWidth(3, 160)
        self.table.setColumnWidth(4, 170)
        self.table.setColumnWidth(5, 120)

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
        row = self.model.rows[int(index.row())]
        return int(row.entry_id)

    def selected_entry_ids(self) -> list[int]:
        indexes = self.table.selectionModel().selectedRows()
        if not indexes:
            return []
        output: list[int] = []
        seen: set[int] = set()
        for index in indexes:
            if not index.isValid():
                continue
            entry_id = int(self.model.rows[int(index.row())].entry_id)
            if entry_id in seen:
                continue
            seen.add(entry_id)
            output.append(entry_id)
        return output

    def all_entry_ids(self) -> list[int]:
        return [int(row.entry_id) for row in self.model.rows]

    def show_password_for_entry(self, entry_id: int, password_value: str) -> None:
        self.model.set_password_for_entry(entry_id=entry_id, password_value=password_value, visible=True)

    def hide_password_for_entry(self, entry_id: int) -> None:
        self.model.set_password_for_entry(entry_id=entry_id, password_value="", visible=False)

    def clear_all_password_values(self) -> None:
        self.model.clear_all_password_values()

    def set_show_all_passwords(self, enabled: bool) -> None:
        self.model.set_show_all_passwords(enabled)

    def toggle_password_visibility_for_current_row(self) -> None:
        index = self.table.currentIndex()
        if not index.isValid():
            return
        row_index = int(index.row())
        self.model.toggle_password_for_row(row_index)

    def on_table_clicked(self, index: QModelIndex) -> None:
        if not index.isValid():
            return
        if int(index.column()) != 2:
            return

        if self.model.show_all_passwords:
            return

        row_index = int(index.row())
        if row_index < 0 or row_index >= len(self.model.rows):
            return
        entry_id = int(self.model.rows[row_index].entry_id)
        is_visible = self.model.is_password_visible(row_index)
        if is_visible:
            self.hide_password_for_entry(entry_id)
            self.password_visibility_requested.emit(entry_id, False)
            return
        self.password_visibility_requested.emit(entry_id, True)

    def show_context_menu(self, point) -> None:
        menu = QMenu(self)
        action_add = menu.addAction("Добавить запись")
        action_edit = menu.addAction("Изменить запись")
        action_delete = menu.addAction("Удалить запись")
        action_copy = menu.addAction("Копировать пароль")

        selected_count = len(self.selected_entry_ids())
        has_selection = selected_count > 0
        action_edit.setEnabled(selected_count == 1)
        action_delete.setEnabled(has_selection)
        action_copy.setEnabled(selected_count == 1)

        chosen = menu.exec(self.table.viewport().mapToGlobal(point))
        if chosen == action_add:
            self.add_requested.emit()
            return
        if chosen == action_edit:
            self.edit_requested.emit()
            return
        if chosen == action_delete:
            self.delete_requested.emit()
            return
        if chosen == action_copy:
            self.copy_password_requested.emit()
