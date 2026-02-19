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
## Roadmap

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
## 🔗 Project Structure
```text
crypto_nak2/
├── src/
│   ├── core/
│   │   └── crypto/
│   │       ├── audit_logger.py
│   │       ├── config.py
│   │       ├── events.py
│   │       ├── key_manager.py
│   │       ├── security.py
│   │       └── state_manager.py
│   ├── database/
│   │   ├── db.py
│   │   ├── models.py
│   │   └── repositories.py
│   └── gui/
│       ├── app.py
│       ├── entry_dialog.py
│       ├── main_window.py
│       ├── settings_dialog.py
│       ├── setup_wizard.py
│       └── widgets/
│           ├── audit_log_viewer.py
│           ├── password_entry.py
│           └── secure_table.py
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
└── README.md

```

## ⚙️ Setup (Windows)

### 1. Create virtual environment

```bash
python -m venv venv
venv\Scripts\activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run application
```bash
python main.py
```
