from __future__ import annotations

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QSplitter,
    QVBoxLayout,
    QHBoxLayout,
    QLineEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QToolBar,
    QStatusBar,
    QLabel,
    QMessageBox,
    QPushButton,
    QDialog,
    QVBoxLayout,
)

from core.events import EventBus, EntryAdded, EntryDeleted
from core.state_manager import StateManager
from database.repositories import AuditRepository
from gui.settings_dialog import SettingsDialog
from gui.widgets.audit_log_viewer import AuditLogViewer
from gui.widgets.secure_table import SecureTable, VaultRow


class MainWindow(QMainWindow):
    def __init__(self, bus: EventBus, state: StateManager, audit_repo: AuditRepository):
        super().__init__()
        self._bus = bus
        self._state = state
        self._audit = audit_repo

        self.setWindowTitle("CryptoSafe Manager by nak")
        self.resize(1100, 650)

        self._build_menu()
        self._build_ui()
        self._fill_demo_data()

    def _build_menu(self) -> None:
        mb = self.menuBar()

        m_file = mb.addMenu("Файл")
        act_new = m_file.addAction("Создать")
        act_open = m_file.addAction("Открыть")
        act_backup = m_file.addAction("Резервная копия")
        m_file.addSeparator()
        act_exit = m_file.addAction("Выход")

        m_edit = mb.addMenu("Правка")
        act_add = m_edit.addAction("Добавить")
        act_edit = m_edit.addAction("Изменить")
        act_del = m_edit.addAction("Удалить")

        m_view = mb.addMenu("Вид")
        act_logs = m_view.addAction("Логи")
        act_settings = m_view.addAction("Настройки")

        m_help = mb.addMenu("Справка")
        act_about = m_help.addAction("О программе")

        act_new.triggered.connect(self.on_new)
        act_open.triggered.connect(self.on_open)
        act_backup.triggered.connect(self.on_backup)
        act_exit.triggered.connect(self.close)

        act_add.triggered.connect(self.on_add)
        act_edit.triggered.connect(self.on_edit)
        act_del.triggered.connect(self.on_delete)

        act_logs.triggered.connect(self.on_view_logs)
        act_settings.triggered.connect(self.on_settings)
        act_about.triggered.connect(self.on_about)

    def _build_ui(self) -> None:
        # Верхняя панель действий (быстрый доступ)
        tb = QToolBar("Действия")
        tb.setMovable(False)
        self.addToolBar(tb)

        btn_add = QPushButton("Добавить")
        btn_edit = QPushButton("Изменить")
        btn_del = QPushButton("Удалить")
        btn_copy = QPushButton("Копировать пароль")
        btn_settings = QPushButton("Настройки")

        for b in (btn_add, btn_edit, btn_del, btn_copy):
            tb.addWidget(b)
        tb.addSeparator()
        tb.addWidget(btn_settings)

        btn_add.clicked.connect(self.on_add)
        btn_edit.clicked.connect(self.on_edit)
        btn_del.clicked.connect(self.on_delete)
        btn_copy.clicked.connect(self.on_copy_password)
        btn_settings.clicked.connect(self.on_settings)

        # Центральная часть слева дерево + поиск, справа таблица
        root = QWidget()
        self.setCentralWidget(root)

        splitter = QSplitter(Qt.Horizontal, root)
        splitter.setChildrenCollapsible(False)

        # Левая панель
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(8)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Поиск…")
        self.txt_search.textChanged.connect(self.on_search_changed)

        self.tree_groups = QTreeWidget()
        self.tree_groups.setHeaderHidden(True)
        self.tree_groups.itemSelectionChanged.connect(self.on_group_changed)

        left_layout.addWidget(self.txt_search)
        left_layout.addWidget(self.tree_groups)

        # Правая панель
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(8)

        self.secure_table = SecureTable()
        right_layout.addWidget(self.secure_table)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([320, 780])

        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        # Статусбар
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.lbl_vault = QLabel("Хранилище: закрыто")
        self.lbl_clip = QLabel("Буфер: не используется")
        sb.addWidget(self.lbl_vault, 1)
        sb.addPermanentWidget(self.lbl_clip)

        self._refresh_status()

    def _fill_demo_data(self) -> None:
        # Группы (Sprint 1: демо)
        root = QTreeWidgetItem(["Все записи"])
        work = QTreeWidgetItem(["Работа"])
        personal = QTreeWidgetItem(["Личное"])
        self.tree_groups.addTopLevelItem(root)
        self.tree_groups.addTopLevelItem(work)
        self.tree_groups.addTopLevelItem(personal)
        self.tree_groups.expandAll()
        self.tree_groups.setCurrentItem(root)

        # Таблица (Sprint 1: тестовые записи)
        rows = [
            VaultRow("GitHub", "nak", "https://github.com", "dev", "2026-02-18"),
            VaultRow("Почта", "nak@mail", "https://mail.example", "mail", "2026-02-10"),
            VaultRow("Банк", "nak", "https://bank.example", "finance", "2026-01-30"),
        ]
        self.secure_table.set_rows(rows)

        # Заглушка таймера буфера
        self.lbl_clip.setText("Буфер: очистка таймером (заглушка Sprint 1)")

    def _refresh_status(self) -> None:
        if self._state.is_unlocked():
            self.lbl_vault.setText("Хранилище: открыто")
        else:
            self.lbl_vault.setText("Хранилище: закрыто (Sprint 1)")

    # Действия меню/кнопок

    @Slot()
    def on_new(self) -> None:
        QMessageBox.information(self, "Sprint 1", "Создание новой базы будет расширено в Sprint 2.")

    @Slot()
    def on_open(self) -> None:
        QMessageBox.information(self, "Sprint 1", "Открытие/логин будет реализовано в Sprint 2.")

    @Slot()
    def on_backup(self) -> None:
        QMessageBox.information(self, "Sprint 1", "Резервное копирование — заглушка (Sprint 8).")

    @Slot()
    def on_add(self) -> None:
        self._bus.publish(EntryAdded(title="Новая запись (демо)"), async_mode=True)
        QMessageBox.information(self, "Sprint 1", "Событие EntryAdded отправлено (записано в audit_log).")

    @Slot()
    def on_edit(self) -> None:
        QMessageBox.information(self, "Sprint 1", "Редактирование будет во Sprint 2.")

    @Slot()
    def on_delete(self) -> None:
        self._bus.publish(EntryDeleted(title="GitHub (демо)"), async_mode=True)
        QMessageBox.information(self, "Sprint 1", "Событие EntryDeleted отправлено (записано в audit_log).")

    @Slot()
    def on_copy_password(self) -> None:
        QMessageBox.information(self, "Sprint 1", "Защищённый буфер обмена будет в Sprint 4.")

    @Slot()
    def on_settings(self) -> None:
        SettingsDialog(self).exec()

    @Slot()
    def on_view_logs(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Логи")
        dlg.resize(640, 420)

        viewer = AuditLogViewer(dlg)

        # Sprint 1: просто вывод последних записей как текст.
        lines = []
        for r in self._audit.last(100):
            lines.append(f"{r.timestamp} | {r.action} | {r.details}")
        viewer.set_text("\n".join(lines) if lines else "Пока пусто")

        layout = QVBoxLayout(dlg)
        layout.addWidget(viewer)
        dlg.exec()

    @Slot()
    def on_about(self) -> None:
        QMessageBox.information(
            self,
            "CryptoSafe Manager",
            "CryptoSafe Manager - менеджер паролей.\n"
            "Спринт 1: фундамент (архитектура, БД, события, оболочка GUI).\n"
            "By nak",
        )

    # Заглушки фильтрации

    @Slot(str)
    def on_search_changed(self, text: str) -> None:
        # Sprint 1: заглушка поиска
        del text

    @Slot()
    def on_group_changed(self) -> None:
        # Sprint 1: заглушка фильтра по группам
        pass
