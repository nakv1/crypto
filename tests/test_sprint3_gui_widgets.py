from __future__ import annotations

import sys

import pytest

pytest.importorskip("PySide6")
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from gui.entry_dialog import EntryDialog
from gui.widgets.password_entry import PasswordEntry
from gui.widgets.secure_table import VaultRow, VaultTableModel


@pytest.fixture
def qapp():
    app = QApplication.instance() or QApplication(sys.argv)
    return app


def test_secure_table_model_masks_username_and_toggles_password():
    model = VaultTableModel(
        [
            VaultRow(
                entry_id=1,
                title="GitHub",
                username="username_long",
                password="UltraSafeA1!Key",
                url="https://github.com/login",
                tags="dev",
                updated_at="2026-03-20T10:00:00+00:00",
            )
        ]
    )

    username_value = model.data(model.index(0, 1))
    password_value_masked = model.data(model.index(0, 2))
    updated_text = model.data(model.index(0, 4))
    icon_value = model.data(model.index(0, 2), role=Qt.DecorationRole)
    assert username_value == "user••••"
    assert isinstance(password_value_masked, str)
    assert "UltraSafeA1!Key" not in password_value_masked
    assert updated_text == "2026-03-20 10:00"
    assert icon_value is not None

    model.toggle_password_for_row(0)
    password_value_visible = model.data(model.index(0, 2))
    assert password_value_visible == "UltraSafeA1!Key"

    model.set_show_all_passwords(True)
    password_value_global = model.data(model.index(0, 2))
    assert password_value_global == "UltraSafeA1!Key"


def test_entry_dialog_url_validation_and_username_suggestion(qapp):
    del qapp
    dialog = EntryDialog()
    ok, domain = dialog.validate_url("https://github.com/settings")
    assert ok is True
    assert domain == "github.com"

    dialog.txt_url.setText("https://github.com/settings")
    dialog.apply_username_suggestion_if_needed()
    assert dialog.txt_username.text() == "username"

    bad_ok, bad_message = dialog.validate_url("ftp://example.com")
    assert bad_ok is False
    assert "http" in bad_message


def test_password_entry_routes_focus_to_line_edit_for_paste(qapp):
    del qapp
    widget = PasswordEntry("Мастер-пароль")
    line_edit = widget.line_edit()

    assert widget.focusProxy() is line_edit
    assert widget.btn.focusPolicy() == Qt.NoFocus
