from __future__ import annotations

from pathlib import Path

from core.audit_logger import AuditLogger
from core.crypto.authentication import AuthenticationService
from core.crypto.placeholder import AES256Placeholder
from core.events import EntryAdded, EntryDeleted, EventBus, UserLoggedIn
from core.key_manager import KeyManager
from core.state_manager import StateManager
from database.db import Database
from database.repositories import AuditRepository, SettingsRepository, VaultRepository


def test_vault_repository_encrypts_and_decrypts(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")

    crypto = AES256Placeholder(km)
    repo = VaultRepository(db=db, crypto=crypto)

    entry_id = repo.add(title="GitHub", username="nak", password="secret", url="https://github.com", notes="n", tags="dev")
    data = repo.get_by_id(entry_id)
    assert data is not None
    assert data["password"] == "secret"
    assert data["notes"] == "n"

    repo.update(entry_id, title="GitHub", username="nak", password="secret2", url="", notes="", tags="")
    data2 = repo.get_by_id(entry_id)
    assert data2 is not None
    assert data2["password"] == "secret2"

    repo.delete(entry_id)
    assert repo.get_by_id(entry_id) is None

    db.close()


def test_settings_repository_encrypted_roundtrip(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    state = StateManager()
    km = KeyManager(db)
    auth = AuthenticationService(key_manager=km, state=state)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")

    crypto = AES256Placeholder(km)
    settings = SettingsRepository(db=db, crypto=crypto)

    settings.set("plain", "1", encrypted=False)
    settings.set("secret", "value", encrypted=True)

    assert settings.get("plain") == "1"
    assert settings.get("secret") == "value"

    db.close()


def test_audit_logger_writes_on_events(tmp_path: Path):
    db = Database(tmp_path / "vault.db")
    db.connect()

    bus = EventBus()
    audit_repo = AuditRepository(db)
    audit = AuditLogger(bus, audit_repo)
    audit.start()

    bus.publish(UserLoggedIn(username="nak"))
    bus.publish(EntryAdded(title="t"))
    bus.publish(EntryDeleted(title="t"))

    rows = audit_repo.last(10)
    actions = {r.action for r in rows}
    assert "UserLoggedIn" in actions
    assert "EntryAdded" in actions
    assert "EntryDeleted" in actions

    bus.shutdown()
    db.close()
