# 🔒CryptoSafe Manager (crypto_nak2)

## RU Описание

**CryptoSafe Manager** — учебное приложение (Sprint-based development), цель которого — построить безопасный менеджер “хранилища” (vault) с графическим интерфейсом, аудитом действий и модульной архитектурой.

На текущем этапе (Sprint 1) реализован фундамент проекта:
- архитектурный каркас (Core / Database / GUI)
- база данных со схемой, версиями и репозиториями
- криптографический слой (пока placeholder) + менеджер ключей
- событийная система и аудит-логирование
- GUI-оболочка + мастер первичной настройки (Setup Wizard)
- инфраструктура запуска в Docker (для CI/проверок)

**Sprint 2 (добавлен):** master password auth, Argon2id + PBKDF2, key cache, session management, смена master-пароля с перешифрованием.

---

## EN Description

**CryptoSafe Manager** is an educational sprint-based project aimed at building a secure vault manager with GUI, audit logging, and a modular architecture.

Sprint 1 delivers the project foundation:
- layered architecture (Core / Database / GUI)
- database schema + versioning + repositories
- cryptography layer (placeholder) + key management
- event system and audit logging
- GUI shell + Setup Wizard
- Docker setup for reproducible builds and testing

**Sprint 2 (added):** master password auth, Argon2id + PBKDF2, key cache, session management, master password change with re-encryption.

---
## Карта / Roadmap

| Sprint | Description |
|--------|-------------|
| Sprint 1 | Architecture foundation, GUI skeleton, DB schema, crypto placeholders |
| Sprint 2 | Master password authentication, Argon2, real key derivation |
| Sprint 3 | AES-GCM encryption, secure vault |
| Sprint 4 | Clipboard protection, inactivity lock |
| Sprint 5 | Backup / restore |
| Sprint 6 | Logging & tamper detection |
| Sprint 7 | UX polish |
| Sprint 8 | Final hardening + documentation |
## 🔗 Структура проекта / Project Structure
```text
## Структура проекта

crypto_nak2/
├─ src/
│  ├─ core/                                 # бизнес-логика: крипта, состояние, события, аудит
│  │  ├─ crypto/
│  │  │  ├─ abstract.py                     # интерфейс EncryptionService (через KeyManager)
│  │  │  ├─ placeholder.py                  # AES256Placeholder (XOR-заглушка, до Sprint 3)
│  │  │  ├─ key_derivation.py               # Argon2id/PBKDF2, policy пароля, валидация параметров
│  │  │  ├─ key_storage.py                  # secure key cache + keyring/fallback storage
│  │  │  └─ authentication.py               # login/logout/session/backoff/password rotation
│  │  ├─ audit_logger.py                    # AuditLogger: подписка на события и запись в audit_log
│  │  ├─ config.py                          # ConfigManager: окружения/пути/параметры
│  │  ├─ events.py                          # EventBus + типы событий
│  │  ├─ state_manager.py                   # StateManager: lock/unlock, activity, failed attempts
│  │  ├─ key_manager.py                     # KeyManager: auth_hash/enc_salt/params + cache
│  │  └─ security.py                        # secure wipe и безопасные утилиты (ctypes)
│  │
│  ├─ database/                             # SQLite: подключение, схема, репозитории
│  │  ├─ db.py                              # пул соединений + миграции (SCHEMA_VERSION=4)
│  │  ├─ models.py                          # SQL schema/DDL
│  │  └─ repositories.py                    # Vault/Settings/Audit репозитории
│  │
│  ├─ gui/                                  # UI (View): PySide6 окна и диалоги
│  │  ├─ app.py                             # wiring зависимостей, setup/login flow, запуск окна
│  │  ├─ entry_dialog.py                    # диалог добавления/редактирования записи
│  │  ├─ login_dialog.py                    # диалог ввода мастер-пароля
│  │  ├─ change_password_dialog.py          # диалог смены мастер-пароля (Sprint 2)
│  │  ├─ main_window.py                     # главное окно (меню, таблица, статусбар)
│  │  ├─ setup_wizard.py                    # мастер первичной настройки (пароль/БД/KDF)
│  │  ├─ settings_dialog.py                 # окно настроек (заглушка, вкладки)
│  │  └─ widgets/
│  │    ├─ password_entry.py                # поле пароля + "показать/скрыть"
│  │    ├─ secure_table.py                  # таблица записей хранилища
│  │    └─ audit_log_viewer.py              # просмотр аудита
│  │
│  └─ main.py                               # запуск приложения
│
├─ tests/
│  ├─ conftest.py                           # фикстуры, тестовая БД
│  ├─ test_config_manager.py                # тесты ConfigManager (save/load)
│  ├─ test_crypto.py                        # тесты EncryptionService placeholder
│  ├─ test_database.py                      # тесты схемы/миграций/колонок
│  ├─ test_events.py                        # тесты EventBus
│  ├─ test_repositories_and_audit.py        # тесты репозиториев и AuditLogger
│  ├─ test_gui_integration.py               # smoke-тесты GUI (wizard + main window)
│  ├─ test_state_and_key_manager.py         # тесты StateManager и KeyManager
│  └─ test_sprint2_security.py              # Sprint 2 security tests (argon2/pbkdf2/cache/rotation)
│
├─ README.md                                # описание, roadmap, запуск, архитектура
├─ requirements.txt                         # зависимости (PySide6, argon2-cffi, cryptography, keyring)
├─ pytest.ini                               # настройка pytest (pythonpath=src)
├─ Dockerfile                               # заглушка (для будущей упаковки)
└─ docker-compose.yml                       # заглушка
```

## ⚙️ Установка / Setup (Windows)

### 1. Создание виртуальной среды / Create virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 2. Установка зависимостей / Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Запуск приложения / Run application
```bash
python main.py
```
