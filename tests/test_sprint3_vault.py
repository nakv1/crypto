from __future__ import annotations

from pathlib import Path

from core.crypto.authentication import AuthenticationService
from core.crypto.placeholder import AES256Placeholder
from core.key_manager import KeyManager
from core.state_manager import StateManager
from core.vault.password_generator import PasswordGenerationConfig, PasswordGenerator
from database.db import Database
from database.repositories import VaultRepository


def make_runtime(tmp_path: Path) -> tuple[Database, AuthenticationService, VaultRepository]:
    db = Database(tmp_path / "vault.db")
    db.connect()
    state = StateManager()
    key_manager = KeyManager(db)
    auth = AuthenticationService(key_manager=key_manager, state=state)
    auth.setup_master_password("UltraSafeA1!Key", username="nak")
    crypto = AES256Placeholder(key_manager)
    vault = VaultRepository(db=db, crypto=crypto)
    return db, auth, vault


def test_entry_roundtrip_uses_encrypted_data_text(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    entry_id = vault.add(
        title="GitHub",
        username="nak",
        password="VeryStrongA1!Password",
        url="https://github.com/login",
        notes="personal account",
        tags="dev,git",
    )
    payload = vault.get_by_id(entry_id)
    assert payload is not None
    assert payload["title"] == "GitHub"
    assert payload["username"] == "nak"
    assert payload["password"] == "VeryStrongA1!Password"
    assert payload["notes"] == "personal account"
    assert payload["domain"] == "github.com"

    with db.session() as conn:
        row = conn.execute(
            "SELECT encrypted_data, encrypted_password, notes, typeof(encrypted_data) as t FROM vault_entries WHERE id = ?",
            (entry_id,),
        ).fetchone()
    assert row is not None
    encrypted_data = row["encrypted_data"]
    assert isinstance(encrypted_data, str)
    assert row["t"] == "text"
    assert "GitHub" not in encrypted_data
    assert "VeryStrongA1!Password" not in encrypted_data
    assert row["encrypted_password"] is None
    assert row["notes"] is None

    db.close()


def test_crud_and_soft_delete_flow(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    entry_ids: list[int] = []
    for index in range(100):
        entry_id = vault.add(
            title=f"title-{index}",
            username=f"user-{index}",
            password=f"StrongPassA1!{index}",
            url=f"https://example{index}.com",
            notes=f"note-{index}",
            tags="work,example",
        )
        entry_ids.append(entry_id)

    all_rows = vault.list()
    assert len(all_rows) == 100

    for entry_id in entry_ids[:10]:
        vault.update(
            entry_id=entry_id,
            title=f"updated-{entry_id}",
            username="updated-user",
            password=f"UpdatedPassB2!{entry_id}",
            url="https://updated.example",
            notes="updated-note",
            tags="updated",
        )

    for entry_id in entry_ids[10:30]:
        vault.delete(entry_id)

    row_after_update = vault.get_by_id(entry_ids[0])
    assert row_after_update is not None
    assert row_after_update["title"].startswith("updated-")
    assert row_after_update["password"].startswith("UpdatedPassB2!")

    deleted_row = vault.get_by_id(entry_ids[10])
    assert deleted_row is None

    rows_after_delete = vault.list()
    assert len(rows_after_delete) == 80

    with db.session() as conn:
        deleted_count = int(conn.execute("SELECT COUNT(*) FROM deleted_entries").fetchone()[0])
    assert deleted_count == 20

    db.close()


def test_password_generator_profile_and_history():
    generator = PasswordGenerator()
    config = PasswordGenerationConfig(
        length=20,
        use_uppercase=True,
        use_lowercase=True,
        use_digits=True,
        use_symbols=True,
        exclude_ambiguous=True,
        enforce_strength=True,
        min_strength_score=3,
        history_size=20,
    )

    generated: list[str] = []
    for _ in range(1000):
        password = generator.generate(config)
        generated.append(password)
        assert len(password) == 20
        assert any(ch.isupper() for ch in password)
        assert any(ch.islower() for ch in password)
        assert any(ch.isdigit() for ch in password)
        assert any(not ch.isalnum() for ch in password)
        assert generator.estimate_strength_score(password) >= 3
    assert len(set(generated)) >= 990


def test_key_store_values_are_text_not_blob(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth
    del vault
    with db.session() as conn:
        rows = conn.execute("SELECT typeof(key_data) as key_data_type FROM key_store").fetchall()
    assert rows
    assert all(row["key_data_type"] == "text" for row in rows)
    db.close()


def test_search_fulltext_fuzzy_and_field_filters(tmp_path: Path):
    db, auth, vault = make_runtime(tmp_path)
    del auth

    vault.add(
        title="Github Work",
        username="nak.dev",
        password="StrongPassA1!Github",
        url="https://github.com",
        notes="source repositories",
        tags="dev,work",
        category="Work",
    )
    vault.add(
        title="Gmail",
        username="nakv1@gmail.com",
        password="StrongPassA1!Mail",
        url="https://gmail.com",
        notes="mail account",
        tags="mail,personal",
        category="Personal",
    )

    result_text = vault.search(query="repositories")
    assert len(result_text) == 1
    assert result_text[0].title == "Github Work"

    result_fuzzy = vault.search(query="githb")
    assert len(result_fuzzy) >= 1
    assert any(item.title == "Github Work" for item in result_fuzzy)

    result_field = vault.search(query='title:"gmail"')
    assert len(result_field) == 1
    assert result_field[0].title == "Gmail"

    result_tags = vault.search(query="", tags=["mail"])
    assert len(result_tags) == 1
    assert result_tags[0].title == "Gmail"

    result_category = vault.search(query="", category="Work")
    assert len(result_category) == 1
    assert result_category[0].title == "Github Work"

    strong_only = vault.search(query="", min_password_strength=3)
    assert len(strong_only) == 2

    db.close()
