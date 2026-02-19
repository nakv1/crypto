from __future__ import annotations

import os
from pathlib import Path

from PySide6.QtWidgets import QApplication

from core.audit_logger import AuditLogger
from core.config import ConfigManager
from core.crypto.placeholder import AES256Placeholder
from core.events import EventBus
from core.state_manager import StateManager
from database.db import Database
from database.repositories import AuditRepository
from gui.main_window import MainWindow


def _default_db_path() -> str:
    # Определяем корень проекта (на 2 уровня выше текущего файла)
    project_root = Path(__file__).resolve().parents[2]

    # Папка data в корне проекта
    data_dir = project_root / "data"

    # Создаём папку, если её нет
    data_dir.mkdir(parents=True, exist_ok=True)

    # Возвращаем путь к базе по умолчанию
    return str(data_dir / "cryptosafe.db")


class CryptoSafeApp:
    def run(self, app: QApplication) -> int:
        # 1) Загружаем конфигурацию приложения
        cfg = ConfigManager().load()

        # 2) Приоритет пути к БД:
        db_path = os.getenv("CRYPTOSAFE_DB_PATH") or str(cfg.db_path) or _default_db_path()

        # 3) Инициализация сервисов
        # База данных
        db = Database(Path(db_path))
        db.connect()

        # Репозиторий аудита
        audit_repo = AuditRepository(db)

        # Шина событий
        bus = EventBus()

        # Менеджер состояния
        state = StateManager()

        # Логгер аудита (подписывается на события)
        audit = AuditLogger(bus, audit_repo)
        audit.start()

        # Заглушка криптографии Sprint 1 (напрямую не используется)
        _crypto = AES256Placeholder()

        # Главное окно приложения
        main = MainWindow(bus=bus, state=state, audit_repo=audit_repo)
        main.show()

        # 4) Главный цикл Qt + гарантированное освобождение ресурсов
        try:
            code = app.exec()
            return int(code)
        finally:
            # Корректно останавливаем EventBus
            try:
                bus.shutdown()
            finally:
                # Закрываем базу данных в любом случае
                db.close()
