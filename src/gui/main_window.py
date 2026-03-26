from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from PySide6.QtCore import QDate, QStringListModel, Qt, Slot
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCompleter,
    QDateEdit,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QSplitter,
    QStatusBar,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.crypto.authentication import AuthenticationService
from core.events import ClipboardCleared, ClipboardCopied, EventBus
from core.state_manager import StateManager
from database.repositories import AuditRepository, SettingsRepository, VaultRepository
from gui.change_password_dialog import ChangePasswordDialog
from gui.entry_dialog import EntryDialog, EntryFormData
from gui.login_dialog import LoginDialog
from gui.settings_dialog import SettingsDialog
from gui.widgets.audit_log_viewer import AuditLogViewer
from gui.widgets.secure_table import SecureTable, VaultRow


class MainWindow(QMainWindow):
    def __init__(
            self,
            bus: EventBus,
            state: StateManager,
            auth_service: AuthenticationService,
            audit_repo: AuditRepository,
            vault_repo: VaultRepository,
            settings_repo: SettingsRepository,
            open_database_handler: Optional[Callable[[Path], tuple[bool, str]]] = None,
    ):
        super().__init__()
        self.bus = bus
        self.state = state
        self.auth = auth_service
        self.audit = audit_repo
        self.vault = vault_repo
        self.settings = settings_repo
        self.open_database_handler = open_database_handler
        self.show_passwords_globally = False
        self.search_history: list[str] = []
        self.search_history_model = QStringListModel()
        self.locked_ui_mode = False
        self.restore_prompt_in_progress = False

        self.setWindowTitle("CryptoSafe Manager by nak")
        self.resize(1100, 650)

        self.build_menu()
        self.build_ui()
        self.load_search_history_from_settings()
        self.fill_demo_data()
        self.reload_table()

    def build_menu(self) -> None:
        mb = self.menuBar()

        m_file = mb.addMenu("Файл")
        act_new = m_file.addAction("Создать")
        act_open = m_file.addAction("Открыть")
        act_backup = m_file.addAction("Резервная копия")
        act_change_password = m_file.addAction("Сменить мастер-пароль")
        m_file.addSeparator()
        act_exit = m_file.addAction("Выход")

        m_edit = mb.addMenu("Правка")
        act_add = m_edit.addAction("Добавить")
        act_edit = m_edit.addAction("Изменить")
        act_del = m_edit.addAction("Удалить")

        m_view = mb.addMenu("Вид")
        act_logs = m_view.addAction("Логи")
        act_settings = m_view.addAction("Настройки")
        act_toggle_passwords = m_view.addAction("Показать пароли")
        act_toggle_passwords.setCheckable(True)
        self.action_toggle_passwords = act_toggle_passwords

        m_help = mb.addMenu("Справка")
        act_about = m_help.addAction("О программе")

        act_new.triggered.connect(self.on_new)
        act_open.triggered.connect(self.on_open)
        act_backup.triggered.connect(self.on_backup)
        act_change_password.triggered.connect(self.on_change_master_password)
        act_exit.triggered.connect(self.close)

        act_add.triggered.connect(self.on_add)
        act_edit.triggered.connect(self.on_edit)
        act_del.triggered.connect(self.on_delete)

        act_logs.triggered.connect(self.on_view_logs)
        act_settings.triggered.connect(self.on_settings)
        act_toggle_passwords.triggered.connect(self.on_toggle_password_visibility_action)
        act_about.triggered.connect(self.on_about)

    def build_ui(self) -> None:
        tb = QToolBar("Действия")
        tb.setMovable(False)
        self.addToolBar(tb)

        btn_add = QPushButton("Добавить")
        btn_edit = QPushButton("Изменить")
        btn_del = QPushButton("Удалить")
        btn_copy = QPushButton("Копировать пароль")
        btn_toggle_passwords = QPushButton("Показать пароли")
        btn_settings = QPushButton("Настройки")

        for btn in (btn_add, btn_edit, btn_del, btn_copy):
            tb.addWidget(btn)
        tb.addSeparator()
        tb.addWidget(btn_toggle_passwords)
        tb.addSeparator()
        tb.addWidget(btn_settings)

        btn_add.clicked.connect(self.on_add)
        btn_edit.clicked.connect(self.on_edit)
        btn_del.clicked.connect(self.on_delete)
        btn_copy.clicked.connect(self.on_copy_password)
        btn_toggle_passwords.clicked.connect(lambda: self.on_toggle_password_visibility())
        btn_settings.clicked.connect(self.on_settings)

        root = QWidget()
        self.root_widget = root
        self.setCentralWidget(root)

        splitter = QSplitter(Qt.Horizontal, root)
        splitter.setChildrenCollapsible(False)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(8)

        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText('Поиск: текст, title:"mail", username:"nak"')
        self.txt_search.textChanged.connect(self.on_search_changed)
        self.txt_search.editingFinished.connect(self.on_search_committed)
        self.search_completer = QCompleter(self.search_history_model, self)
        self.search_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.search_completer.setFilterMode(Qt.MatchContains)
        self.txt_search.setCompleter(self.search_completer)

        self.cmb_category_filter = QComboBox()
        self.cmb_category_filter.addItem("Все категории", "all")
        self.cmb_category_filter.addItem("General", "General")
        self.cmb_category_filter.addItem("Work", "Work")
        self.cmb_category_filter.addItem("Personal", "Personal")
        self.cmb_category_filter.addItem("Finance", "Finance")
        self.cmb_category_filter.addItem("Social", "Social")
        self.cmb_category_filter.addItem("Other", "Other")
        self.cmb_category_filter.currentIndexChanged.connect(lambda _: self.on_filter_changed())

        self.cmb_strength_filter = QComboBox()
        self.cmb_strength_filter.addItem("Любая надежность", 0)
        self.cmb_strength_filter.addItem("Хорошая и выше (>=3)", 3)
        self.cmb_strength_filter.addItem("Высокая (>=4)", 4)
        self.cmb_strength_filter.currentIndexChanged.connect(lambda _: self.on_filter_changed())

        self.cmb_date_filter = QComboBox()
        self.cmb_date_filter.addItem("Все даты", 0)
        self.cmb_date_filter.addItem("Последние 7 дней", 7)
        self.cmb_date_filter.addItem("Последние 30 дней", 30)
        self.cmb_date_filter.addItem("Последние 365 дней", 365)
        self.cmb_date_filter.currentIndexChanged.connect(lambda _: self.on_filter_changed())

        self.txt_tag_filter = QLineEdit()
        self.txt_tag_filter.setPlaceholderText("Теги: work,mail")
        self.txt_tag_filter.textChanged.connect(lambda _: self.on_filter_changed())

        self.date_from_filter = QDateEdit()
        self.date_from_filter.setCalendarPopup(True)
        self.date_from_filter.setDisplayFormat("yyyy-MM-dd")
        self.date_from_filter.setDate(QDate.currentDate().addYears(-1))
        self.date_from_filter.dateChanged.connect(lambda _: self.on_filter_changed())

        self.date_to_filter = QDateEdit()
        self.date_to_filter.setCalendarPopup(True)
        self.date_to_filter.setDisplayFormat("yyyy-MM-dd")
        self.date_to_filter.setDate(QDate.currentDate())
        self.date_to_filter.dateChanged.connect(lambda _: self.on_filter_changed())

        self.tree_groups = QTreeWidget()
        self.tree_groups.setHeaderHidden(True)
        self.tree_groups.itemSelectionChanged.connect(self.on_group_changed)

        left_layout.addWidget(self.txt_search)
        left_layout.addWidget(self.cmb_category_filter)
        left_layout.addWidget(self.cmb_strength_filter)
        left_layout.addWidget(self.cmb_date_filter)
        left_layout.addWidget(self.txt_tag_filter)
        left_layout.addWidget(QLabel("Дата от:"))
        left_layout.addWidget(self.date_from_filter)
        left_layout.addWidget(QLabel("Дата до:"))
        left_layout.addWidget(self.date_to_filter)
        left_layout.addWidget(self.tree_groups)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(8, 8, 8, 8)
        right_layout.setSpacing(8)

        self.secure_table = SecureTable()
        self.secure_table.add_requested.connect(self.on_add)
        self.secure_table.edit_requested.connect(self.on_edit)
        self.secure_table.delete_requested.connect(self.on_delete)
        self.secure_table.copy_password_requested.connect(self.on_copy_password)
        self.secure_table.password_visibility_requested.connect(self.on_password_visibility_requested)
        right_layout.addWidget(self.secure_table)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([320, 780])

        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(splitter)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.lbl_vault = QLabel("Хранилище: закрыто")
        self.lbl_clip = QLabel("Буфер: не используется")
        sb.addWidget(self.lbl_vault, 1)
        sb.addPermanentWidget(self.lbl_clip)

        self.refresh_status()
        shortcut = QShortcut(QKeySequence("Ctrl+Shift+P"), self)
        shortcut.activated.connect(self.on_toggle_password_visibility)
        self.password_toggle_shortcut = shortcut

    def fill_demo_data(self) -> None:
        root = QTreeWidgetItem(["Все записи"])
        work = QTreeWidgetItem(["Работа"])
        personal = QTreeWidgetItem(["Личное"])
        self.tree_groups.addTopLevelItem(root)
        self.tree_groups.addTopLevelItem(work)
        self.tree_groups.addTopLevelItem(personal)
        self.tree_groups.expandAll()
        self.tree_groups.setCurrentItem(root)

        try:
            if self.state.is_unlocked() and not self.vault.list():
                self.vault.add(
                    title="GitHub (demo)",
                    username="demo",
                    password="demo",
                    url="https://github.com",
                    notes="demo",
                    tags="dev",
                    category="Work",
                )
                self.vault.add(
                    title="Почта (demo)",
                    username="demo@mail",
                    password="demo",
                    url="https://mail.example",
                    notes="demo",
                    tags="mail",
                    category="Personal",
                )
        except Exception:
            pass

        self.lbl_clip.setText("Буфер: очистка таймером (Sprint 2)")

    def load_search_history_from_settings(self) -> None:
        raw = self.settings.get("ui.search_history", "[]") or "[]"
        parsed: list[str] = []
        try:
            payload = json.loads(raw)
            if isinstance(payload, list):
                for item in payload:
                    text = str(item).strip()
                    if not text:
                        continue
                    parsed.append(text)
        except Exception:
            parsed = []
        self.search_history = parsed[:10]
        self.search_history_model.setStringList(self.search_history)

    def save_search_history_to_settings(self) -> None:
        try:
            self.settings.set(
                "ui.search_history",
                json.dumps(self.search_history[:10], ensure_ascii=False),
                encrypted=False,
            )
        except Exception:
            pass

    def push_search_history(self, query: str) -> None:
        normalized = str(query or "").strip()
        if not normalized:
            return
        updated: list[str] = [normalized]
        for item in self.search_history:
            if item == normalized:
                continue
            updated.append(item)
        self.search_history = updated[:10]
        self.search_history_model.setStringList(self.search_history)
        self.save_search_history_to_settings()

    def active_group_filter_tags(self) -> list[str]:
        current_item = self.tree_groups.currentItem()
        if current_item is None:
            return []
        text = str(current_item.text(0)).strip().lower()
        if text in ("все записи", "all entries"):
            return []
        if text == "работа":
            return ["work", "dev"]
        if text == "личное":
            return ["personal", "mail"]
        return []

    def collect_date_range_filter(self) -> tuple[Optional[str], Optional[str]]:
        days_from_combo = int(self.cmb_date_filter.currentData() or 0)
        if days_from_combo > 0:
            date_from_dt = datetime.now(timezone.utc) - timedelta(days=days_from_combo)
            return date_from_dt.isoformat(timespec="seconds"), None

        date_from = self.date_from_filter.date().toString("yyyy-MM-dd")
        date_to = self.date_to_filter.date().toString("yyyy-MM-dd")
        if date_from and date_to and date_from > date_to:
            date_from, date_to = date_to, date_from
        iso_from = f"{date_from}T00:00:00+00:00" if date_from else None
        iso_to = f"{date_to}T23:59:59+00:00" if date_to else None
        return iso_from, iso_to

    def collect_tag_filters(self) -> list[str]:
        tags: list[str] = []
        tags.extend(self.active_group_filter_tags())
        manual = str(self.txt_tag_filter.text() or "")
        for raw_tag in manual.split(","):
            tag = raw_tag.strip()
            if not tag:
                continue
            tags.append(tag)
        seen: set[str] = set()
        unique: list[str] = []
        for tag in tags:
            low = tag.lower()
            if low in seen:
                continue
            seen.add(low)
            unique.append(tag)
        return unique

    def reload_table(self) -> None:
        if not self.state.is_unlocked():
            self.enter_locked_mode()
            return

        query = str(self.txt_search.text() or "").strip()
        category = str(self.cmb_category_filter.currentData() or "all")
        min_strength = int(self.cmb_strength_filter.currentData() or 0)
        tags = self.collect_tag_filters()
        date_from, date_to = self.collect_date_range_filter()

        results = self.vault.search(
            query=query,
            tags=tags,
            category=category,
            date_from=date_from,
            date_to=date_to,
            min_password_strength=min_strength,
        )

        rows = [
            VaultRow(
                entry_id=int(entry.id),
                title=entry.title,
                username=entry.username,
                password=entry.password,
                url=entry.url,
                tags=entry.tags,
                updated_at=entry.updated_at,
            )
            for entry in results
        ]
        self.secure_table.set_rows(rows)
        if self.show_passwords_globally:
            self.load_passwords_for_all_rows()
        self.secure_table.set_show_all_passwords(self.show_passwords_globally)
        self.exit_locked_mode()
        self.lbl_vault.setText(
            f"Хранилище: {'открыто' if self.state.is_unlocked() else 'закрыто'} | Записей: {len(rows)}")

    def enter_locked_mode(self) -> None:
        already_locked = self.locked_ui_mode
        self.locked_ui_mode = True
        if hasattr(self, "root_widget"):
            self.root_widget.setEnabled(False)
        self.secure_table.set_rows([])
        self.secure_table.clear_all_password_values()
        if not already_locked:
            clipboard = QApplication.clipboard()
            clipboard.clear()
            self.bus.publish(ClipboardCleared(reason="lock"), async_mode=True)
        self.show_passwords_globally = False
        self.secure_table.set_show_all_passwords(False)
        if hasattr(self, "action_toggle_passwords"):
            self.action_toggle_passwords.setChecked(False)
        self.lbl_vault.setText("Хранилище: закрыто | Требуется повторный вход")
        if not already_locked:
            self.lbl_clip.setText("Буфер: очищен после блокировки")

    def exit_locked_mode(self) -> None:
        self.locked_ui_mode = False
        if hasattr(self, "root_widget"):
            self.root_widget.setEnabled(True)

    def sync_lock_state(self, prompt_relogin_on_active: bool = False) -> None:
        self.auth.enforce_session_timeout()
        if self.state.is_unlocked():
            was_locked = self.locked_ui_mode
            self.exit_locked_mode()
            self.refresh_status()
            if was_locked:
                self.reload_table()
            return

        self.enter_locked_mode()
        if not prompt_relogin_on_active:
            return
        if self.restore_prompt_in_progress:
            return

        self.restore_prompt_in_progress = True
        try:
            relogin_ok = self.prompt_relogin()
            if relogin_ok and self.state.is_unlocked():
                self.exit_locked_mode()
                self.refresh_status()
                self.reload_table()
            else:
                self.enter_locked_mode()
        finally:
            self.restore_prompt_in_progress = False

    def refresh_status(self) -> None:
        if self.state.is_unlocked():
            self.lbl_vault.setText("Хранилище: открыто")
        else:
            self.lbl_vault.setText("Хранилище: закрыто")

    def apply_runtime_context(
            self,
            state: StateManager,
            auth_service: AuthenticationService,
            audit_repo: AuditRepository,
            vault_repo: VaultRepository,
            settings_repo: SettingsRepository,
            db_path: Path,
    ) -> None:
        self.state = state
        self.auth = auth_service
        self.audit = audit_repo
        self.vault = vault_repo
        self.settings = settings_repo
        self.setWindowTitle(f"CryptoSafe Manager by nak - {db_path.name}")
        self.load_search_history_from_settings()
        self.sync_lock_state(prompt_relogin_on_active=False)
        if self.state.is_unlocked():
            self.reload_table()

    def require_unlocked(self) -> bool:
        self.sync_lock_state(prompt_relogin_on_active=False)
        if self.state.is_unlocked():
            self.exit_locked_mode()
            return True

        if self.prompt_relogin():
            self.exit_locked_mode()
            self.refresh_status()
            self.reload_table()
            return True

        self.enter_locked_mode()
        self.refresh_status()
        QMessageBox.warning(self, "CryptoSafe", "Хранилище закрыто. Нужен мастер-пароль.")
        return False

    def prompt_relogin(self) -> bool:
        while True:
            dlg = LoginDialog(self)
            if dlg.exec() != QDialog.Accepted:
                return False
            password = dlg.password()
            if not password:
                QMessageBox.warning(self, "CryptoSafe", "Пароль не может быть пустым.")
                continue
            result = self.auth.authenticate(password=password, username=self.state.username() or "user")
            if result.success:
                return True
            QMessageBox.warning(
                self,
                "CryptoSafe",
                f"{result.message} Следующая попытка через {result.delay_sec} сек.",
            )
            self.auth.apply_backoff_delay(result.delay_sec)

    def selected_entry_id(self) -> int | None:
        return self.secure_table.selected_entry_id()

    def selected_entry_ids(self) -> list[int]:
        return self.secure_table.selected_entry_ids()

    @Slot()
    def on_new(self) -> None:
        QMessageBox.information(self, "Sprint 2", "Создание новой базы будет расширено в следующих спринтах.")

    @Slot()
    def on_open(self) -> None:
        if self.open_database_handler is None:
            QMessageBox.warning(self, "CryptoSafe", "Операция открытия базы сейчас недоступна.")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Открыть базу данных",
            "",
            "SQLite DB (*.db);;All files (*.*)",
        )
        if not file_path:
            return

        ok, message = self.open_database_handler(Path(file_path))
        if ok:
            if message:
                QMessageBox.information(self, "CryptoSafe", message)
            self.refresh_status()
            self.reload_table()
            return

        if message:
            QMessageBox.warning(self, "CryptoSafe", message)

    @Slot()
    def on_backup(self) -> None:
        QMessageBox.information(self, "Sprint 2", "Резервное копирование — заглушка (Sprint 8).")

    @Slot()
    def on_add(self) -> None:
        if not self.require_unlocked():
            return
        dlg = EntryDialog(self, title="Добавить запись")
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        if not data.title or not data.password:
            QMessageBox.warning(self, "CryptoSafe", "Название и пароль обязательны.")
            return
        self.vault.add(
            title=data.title,
            username=data.username,
            password=data.password,
            url=data.url,
            notes=data.notes,
            tags=data.tags,
            category=data.category,
        )
        self.auth.record_activity()
        self.reload_table()

    @Slot()
    def on_edit(self) -> None:
        if not self.require_unlocked():
            return
        entry_id = self.selected_entry_id()
        if entry_id is None:
            QMessageBox.information(self, "CryptoSafe", "Выбери запись в таблице.")
            return
        row = self.vault.get_by_id(entry_id)
        if row is None:
            QMessageBox.warning(self, "CryptoSafe", "Запись не найдена.")
            return
        preset = EntryFormData(
            title=row["title"],
            username=row["username"],
            password=row["password"],
            url=row["url"],
            notes=row["notes"],
            tags=row["tags"],
            category=row.get("category", "General"),
        )
        dlg = EntryDialog(self, title="Изменить запись", preset=preset)
        if dlg.exec() != QDialog.Accepted:
            return
        data = dlg.get_data()
        if not data.title or not data.password:
            QMessageBox.warning(self, "CryptoSafe", "Название и пароль обязательны.")
            return
        self.vault.update(
            entry_id=entry_id,
            title=data.title,
            username=data.username,
            password=data.password,
            url=data.url,
            notes=data.notes,
            tags=data.tags,
            category=data.category,
        )
        self.auth.record_activity()
        self.reload_table()

    @Slot()
    def on_delete(self) -> None:
        if not self.require_unlocked():
            return
        selected_ids = self.selected_entry_ids()
        if not selected_ids:
            QMessageBox.information(self, "CryptoSafe", "Выбери запись в таблице.")
            return

        if len(selected_ids) == 1:
            row = self.vault.get_by_id(selected_ids[0])
            if row is None:
                QMessageBox.warning(self, "CryptoSafe", "Запись недоступна.")
                return
            message = f"Удалить запись '{row['title']}'?"
        else:
            message = f"Удалить выбранные записи: {len(selected_ids)} шт.?"

        if QMessageBox.question(self, "Подтверждение", message) != QMessageBox.Yes:
            return

        deleted_count = 0
        for entry_id in selected_ids:
            try:
                self.vault.delete(entry_id)
                deleted_count += 1
            except Exception:
                continue

        if deleted_count == 0:
            QMessageBox.warning(self, "CryptoSafe", "Не удалось удалить выбранные записи.")
            return

        self.auth.record_activity()
        self.reload_table()

    @Slot()
    def on_copy_password(self) -> None:
        if not self.require_unlocked():
            return
        entry_id = self.selected_entry_id()
        if entry_id is None:
            QMessageBox.information(self, "CryptoSafe", "Выбери запись в таблице.")
            return
        row = self.vault.get_by_id(entry_id)
        if row is None:
            QMessageBox.warning(self, "CryptoSafe", "Запись не найдена.")
            return
        clipboard = QApplication.clipboard()
        clipboard.setText(row["password"])
        timeout = self.settings.get("ui.clipboard_timeout_sec", "15")
        self.lbl_clip.setText(f"Буфер: пароль скопирован (очистка через {timeout} сек.)")
        self.auth.record_activity()
        self.bus.publish(ClipboardCopied(entry_id=entry_id), async_mode=True)

    @Slot()
    def on_change_master_password(self) -> None:
        if not self.require_unlocked():
            return

        dlg = ChangePasswordDialog(self)
        if dlg.exec() != QDialog.Accepted:
            return

        data = dlg.data()
        if not data.current_password or not data.new_password:
            QMessageBox.warning(self, "CryptoSafe", "Заполни все поля пароля.")
            return
        if data.new_password != data.confirm_password:
            QMessageBox.warning(self, "CryptoSafe", "Новый пароль и подтверждение не совпадают.")
            return

        progress = QProgressDialog("Перешифрование хранилища...", "", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setCancelButton(None)
        progress.setValue(0)
        progress.show()

        def update_progress(current: int, total: int) -> None:
            if total <= 0:
                progress.setValue(100)
            else:
                percent = int((current * 100) / total)
                progress.setValue(min(100, max(0, percent)))
            QApplication.processEvents()

        try:
            self.auth.change_master_password(
                current_password=data.current_password,
                new_password=data.new_password,
                db=self.vault.db,
                crypto=self.vault.crypto,
                progress_callback=update_progress,
            )
            progress.setValue(100)
            self.auth.record_activity()
            QMessageBox.information(self, "CryptoSafe", "Мастер-пароль успешно изменен.")
            self.reload_table()
        except Exception as exc:
            QMessageBox.warning(self, "CryptoSafe", f"Смена пароля не выполнена: {exc}")
        finally:
            progress.close()

    @Slot()
    def on_settings(self) -> None:
        SettingsDialog(self).exec()

    @Slot()
    def on_toggle_password_visibility(self) -> None:
        if not self.state.is_unlocked():
            return
        self.show_passwords_globally = not self.show_passwords_globally
        if self.show_passwords_globally:
            self.load_passwords_for_all_rows()
        else:
            self.secure_table.clear_all_password_values()
        self.secure_table.set_show_all_passwords(self.show_passwords_globally)
        if hasattr(self, "action_toggle_passwords"):
            self.action_toggle_passwords.setChecked(self.show_passwords_globally)
        if self.show_passwords_globally:
            self.lbl_clip.setText("Буфер: видимость паролей включена")
        else:
            self.lbl_clip.setText("Буфер: видимость паролей отключена")

    @Slot(bool)
    def on_toggle_password_visibility_action(self, checked: bool) -> None:
        if not self.state.is_unlocked():
            if hasattr(self, "action_toggle_passwords"):
                self.action_toggle_passwords.setChecked(False)
            return
        self.show_passwords_globally = bool(checked)
        if self.show_passwords_globally:
            self.load_passwords_for_all_rows()
        else:
            self.secure_table.clear_all_password_values()
        self.secure_table.set_show_all_passwords(self.show_passwords_globally)
        if self.show_passwords_globally:
            self.lbl_clip.setText("Буфер: видимость паролей включена")
        else:
            self.lbl_clip.setText("Буфер: видимость паролей отключена")

    @Slot(int, bool)
    def on_password_visibility_requested(self, entry_id: int, make_visible: bool) -> None:
        if not self.state.is_unlocked():
            return
        if not make_visible:
            self.secure_table.hide_password_for_entry(int(entry_id))
            return
        password_value = self.vault.get_password(int(entry_id))
        if password_value is None:
            return
        self.secure_table.show_password_for_entry(int(entry_id), password_value)

    def load_passwords_for_all_rows(self) -> None:
        for entry_id in self.secure_table.all_entry_ids():
            password_value = self.vault.get_password(int(entry_id))
            if password_value is None:
                continue
            self.secure_table.show_password_for_entry(int(entry_id), password_value)

    @Slot()
    def on_view_logs(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Логи")
        dlg.resize(640, 420)

        viewer = AuditLogViewer(dlg)

        lines = []
        for row in self.audit.last(100):
            lines.append(f"{row.timestamp} | {row.action} | {row.details}")
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
            "Спринт 3: AES-GCM записи, CRUD, генерация и UI-таблица.\n"
            "By nak",
        )

    @Slot(str)
    def on_search_changed(self, text: str) -> None:
        del text
        if self.state.is_unlocked():
            self.reload_table()

    @Slot()
    def on_search_committed(self) -> None:
        if self.state.is_unlocked():
            self.push_search_history(self.txt_search.text())
            self.reload_table()

    @Slot()
    def on_group_changed(self) -> None:
        if self.state.is_unlocked():
            self.reload_table()

    def on_filter_changed(self, *args) -> None:
        del args
        if self.state.is_unlocked():
            self.reload_table()
