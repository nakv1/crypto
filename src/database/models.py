SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT,
    encrypted_password BLOB NOT NULL,
    url TEXT,
    notes BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    tags TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_title ON vault_entries(title);
CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at);
CREATE INDEX IF NOT EXISTS idx_vault_username ON vault_entries(username);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    entry_id INTEGER,
    details TEXT,
    signature BLOB
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT NOT NULL UNIQUE,
    setting_value TEXT,
    encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key);

CREATE TABLE IF NOT EXISTS key_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    hash BLOB NOT NULL,
    params TEXT
);
"""