-- Tables for FIDO2 PIM Chat.
-- An "account" is the persistent identity (UserCredentialIdentity in the class
-- diagram): it owns its FIDO2 credentials and the TPM-verified devices linked to it.

CREATE TABLE IF NOT EXISTS accounts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash     TEXT    NOT NULL,
    email             TEXT    NOT NULL,
    email_normalized  TEXT    NOT NULL UNIQUE,
    phone_normalized  TEXT    NOT NULL,
    webauthn_user_id  BLOB    NOT NULL,
    created_at        REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_phone ON accounts(phone_normalized);

CREATE TABLE IF NOT EXISTS credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    credential_id  BLOB    NOT NULL UNIQUE,
    public_key     BLOB    NOT NULL,
    sign_count     INTEGER NOT NULL DEFAULT 0,
    device_id      INTEGER REFERENCES devices(id),
    created_at     REAL    NOT NULL
);

-- One row per physical PC, identified by the hash of its TPM Endorsement Key.
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ek_hash       TEXT    NOT NULL UNIQUE,
    ek_issuer     TEXT,
    tpm_mode      TEXT    NOT NULL,            -- REAL or SIMULATED
    cert_checked  INTEGER NOT NULL DEFAULT 0,  -- EK certificate matched the EK public key
    first_seen    REAL    NOT NULL,
    shared_since  REAL                          -- set when a 2nd account is linked to the device
);

CREATE TABLE IF NOT EXISTS account_devices (
    account_id   INTEGER NOT NULL REFERENCES accounts(id),
    device_id    INTEGER NOT NULL REFERENCES devices(id),
    linked_at    REAL    NOT NULL,
    link_source  TEXT    NOT NULL,              -- REGISTRATION or NEW_DEVICE
    PRIMARY KEY (account_id, device_id)
);

-- mode:    BLOCK    target is invisible to the blocker and cannot reach them
--          SOFT     waiting for the blocker's decision; messages are held back
--          REQUEST  messages arrive in the blocker's "message requests" folder
-- origin:  MANUAL (blocker chose it), TPM, PHONE (policy engine), CONFIRMED (blocker confirmed a soft block)
-- status:  ACTIVE, or RELEASED when the blocker unblocked / allowed it
CREATE TABLE IF NOT EXISTS blocks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id    INTEGER NOT NULL REFERENCES accounts(id),
    target_id     INTEGER NOT NULL REFERENCES accounts(id),
    mode          TEXT    NOT NULL CHECK (mode IN ('BLOCK', 'SOFT', 'REQUEST')),
    origin        TEXT    NOT NULL CHECK (origin IN ('MANUAL', 'TPM', 'PHONE', 'CONFIRMED')),
    status        TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'RELEASED')),
    root_block_id INTEGER,                       -- the manual block this one descends from
    reason        TEXT,
    created_at    REAL    NOT NULL,
    updated_at    REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks(blocker_id, status);
CREATE INDEX IF NOT EXISTS idx_blocks_target  ON blocks(target_id, status);

-- delivery: INBOX (normal), REQUESTS (message request folder), QUARANTINE (held for a soft block),
--           DISCARDED (blocker confirmed the block)
CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id     INTEGER NOT NULL REFERENCES accounts(id),
    recipient_id  INTEGER NOT NULL REFERENCES accounts(id),
    body          TEXT    NOT NULL,
    delivery      TEXT    NOT NULL DEFAULT 'INBOX',
    created_at    REAL    NOT NULL,
    read_at       REAL
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id),
    device_id   INTEGER REFERENCES devices(id),
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    event       TEXT NOT NULL,
    actor_id    INTEGER,
    subject_id  INTEGER,
    detail      TEXT
);
