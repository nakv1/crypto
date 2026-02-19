import sqlite3
import threading
import queue
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from database.models import SCHEMA


class Database:

    # Спринт 1 первая полноценная версия схемы
    SCHEMA_VERSION = 2

    def __init__(self, db_path: Path):
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._pool: "queue.Queue[sqlite3.Connection]" = queue.Queue()
        self._pool_size = 4
        self._initialized = False

        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._lock:
            if self._initialized:
                return

            # Создаём пул соединений. check_same_thread=False — соединения могут использоваться разными потоками, но строго по одному потоку за раз.
            for _ in range(self._pool_size):
                conn = sqlite3.connect(self._db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON;")
                conn.execute("PRAGMA journal_mode = WAL;")
                self._pool.put(conn)

            # ВАЖНО: помечаем как initialized ДО _ensure_schema(),
            # иначе session() внутри _ensure_schema() упадёт.
            self._initialized = True

            try:
                self._ensure_schema()
            except Exception:
                # если схема несовместима/ошибка миграции — закрываем пул и сбрасываем флаг
                self.close()
                raise

    def close(self) -> None:
        with self._lock:
            while not self._pool.empty():
                try:
                    conn = self._pool.get_nowait()
                except queue.Empty:
                    break
                try:
                    conn.close()
                except Exception:
                    pass
            self._initialized = False

    @contextmanager
    def session(self) -> Iterator[sqlite3.Connection]:

        if not self._initialized:
            raise RuntimeError("База данных не подключена. Вызови connect().")

        conn = self._pool.get()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._pool.put(conn)

    def _ensure_schema(self) -> None:
        with self.session() as conn:
            current_version = conn.execute("PRAGMA user_version;").fetchone()[0]

            if current_version == 0:
                conn.executescript(SCHEMA)
                conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION};")
            elif current_version != self.SCHEMA_VERSION:

                raise RuntimeError(
                    f"Несовместимая версия схемы БД: {current_version} (ожидается {self.SCHEMA_VERSION})."
                )

    # Заглушки Sprint 1

    def backup(self, backup_path: Path) -> None:

        raise NotImplementedError("Backup будет реализован в следующих спринтах.")

    def restore(self, backup_path: Path) -> None:

        raise NotImplementedError("Restore будет реализован в следующих спринтах.")