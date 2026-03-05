import sqlite3
import os
import stat
import threading
import queue
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from database.models import SCHEMA


class Database:

    # Спринт 1 первая полноценная версия схемы
    SCHEMA_VERSION = 2

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.lock = threading.Lock()
        self.pool: "queue.Queue[sqlite3.Connection]" = queue.Queue()
        self.pool_size = 4
        self.initialized = False

    def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self.lock:
            if self.initialized:
                return

            # Создаём пул соединений. check_same_thread=False — соединения могут использоваться разными потоками, но строго по одному потоку за раз.
            for _ in range(self.pool_size):
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA busy_timeout = 5000;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                self.pool.put(conn)

            # ВАЖНО: помечаем как initialized ДО ensure_schema(),
            # иначе session() внутри ensure_schema() упадёт.
            self.initialized = True

            try:
                self.apply_permissions()
                self.ensure_schema()
            except Exception:
                # если схема несовместима/ошибка миграции — закрываем пул и сбрасываем флаг
                self.close()
                raise

    def close(self) -> None:
        with self.lock:
            while not self.pool.empty():
                try:
                    conn = self.pool.get_nowait()
                except queue.Empty:
                    break
                try:
                    conn.close()
                except Exception:
                    pass
            self.initialized = False

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:

        if not self.initialized:
            raise RuntimeError("База данных не подключена. Вызови connect().")

        conn = self.pool.get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self.pool.put(conn)

    def ensure_schema(self) -> None:
        with self.session() as conn:
            current_version = conn.execute("PRAGMA user_version;").fetchone()[0]

            if current_version == 0:
                conn.executescript(SCHEMA)
                conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")
            elif current_version != self.SCHEMA_VERSION:

                raise RuntimeError(
                    f"Несовместимая версия схемы БД: {current_version} (ожидается {self.SCHEMA_VERSION})."
                )

    def apply_permissions(self) -> None:
        # Лучшие практики: ограничиваем права на файл БД (не Windows).
        try:
            if os.name != "nt" and self.db_path.exists():
                os.chmod(self.db_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
        except Exception:
            pass

    # Заглушки Sprint 1

    def backup(self, backup_path: Path) -> None:
        raise NotImplementedError("Backup будет реализован в следующих спринтах.")

    def restore(self, backup_path: Path) -> None:
        raise NotImplementedError("Restore будет реализован в следующих спринтах.")
