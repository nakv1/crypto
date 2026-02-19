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
## Архитектура (Sprint 1)

Поток данных:

GUI (PySide6)
  → Core (EventBus / StateManager / AuditLogger / Crypto placeholders)
  → Database (SQLite + repositories)

### Структура проекта

crypto_nak2/
├─ src/
│  ├─ core/                         # бизнес-логика: крипта, состояние, события, аудит
│  │  ├─ crypto/
│  │  │  ├─ abstract.py             # интерфейс EncryptionService
│  │  │  └─ placeholder.py          # AES256Placeholder (XOR-заглушка Sprint 1)
│  │  ├─ audit_logger.py            # AuditLogger: подписка на события и запись в audit_log
│  │  ├─ config.py                  # ConfigManager: окружения/пути/параметры
│  │  ├─ events.py                  # EventBus + типы событий
│  │  ├─ state_manager.py           # StateManager: lock/clipboard/idle placeholders
│  │  ├─ key_manager.py             # KeyManager: derive/store/load (базовая реализация)
│  │  └─ security.py                # secure wipe и безопасные утилиты (ctypes)
│  │
│  ├─ database/                     # SQLite: подключение, схема, репозитории
│  │  ├─ db.py                      # пул соединений + user_version (готовность к миграциям)
│  │  ├─ models.py                  # SQL schema/DDL + структуры данных
│  │  └─ repositories.py            # Vault/Settings/Audit репозитории
│  │
│  ├─ gui/                          # UI (View): PySide6 окна и диалоги
│  │   ├─ app.py                    # wiring зависимостей, запуск сервисов, показ окна
│  │   ├─ main_window.py            # главное окно (меню, таблица, статусбар)
│  │   ├─ setup_wizard.py           # мастер первичной настройки (QWizard)
│  │   ├─ settings_dialog.py        # окно настроек (заглушка, вкладки)
│  │   └─ widgets/
│  │     ├─ password_entry.py       # поле пароля + “показать/скрыть”
│  │     ├─ secure_table.py         # таблица записей хранилища
│  │     └─ audit_log_viewer.py     # просмотр аудита (заглушка)
│  │
│  │
│  └─ main.py                       # Запуск приложения
│
│
│
├─ tests/
│  ├─ conftest.py                   # фикстуры, тестовая БД
│  ├─ test_crypto.py                # тесты заглушки шифрования
│  ├─ test_database.py              # тесты схемы/репозиториев
│  ├─ test_events.py                # тесты EventBus
│  └─ test_gui_integration.py       # smoke-тесты GUI (wizard + main window)
│
│                    
├─ README.md                        # описание, roadmap, запуск, архитектура
├─ requirements.txt                 # зависимости
├─ pytest.ini                       # настройка pytest (pythonpath=src)
├─ Dockerfile                       # заглушка (Should)
└─ docker-compose.yml               # заглушка (Should)

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
