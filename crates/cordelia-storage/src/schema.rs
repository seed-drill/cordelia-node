//! SQLite schema definitions and migrations.
//!
//! Spec: seed-drill/specs/data-formats.md §3, §5

use rusqlite::Connection;

use crate::StorageError;

/// Current schema version (incremented per migration).
pub const SCHEMA_VERSION: u32 = 19;

/// The schema version of the released version of the program
/// (0.2.0-alpha.8): the last before the entries of a channel from its
/// secret.
pub const RELEASED_SCHEMA_VERSION: u32 = 10;

/// Migration v1: Phase 1 initial schema.
///
/// All DDL from data-formats.md §3.1-§3.5.
/// Search tables (§2 of search-indexing.md) deferred to WP8.
const MIGRATION_V1: &str = r#"
-- Core tables (data-formats.md §3)

CREATE TABLE IF NOT EXISTS channels (
    channel_id    TEXT PRIMARY KEY,
    channel_name  TEXT,
    channel_type  TEXT NOT NULL CHECK(channel_type IN ('named', 'dm', 'group')),
    mode          TEXT NOT NULL CHECK(mode IN ('realtime', 'batch')),
    access        TEXT NOT NULL CHECK(access IN ('open', 'invite_only')),
    creator_id    BLOB NOT NULL,
    key_version   INTEGER NOT NULL DEFAULT 1,
    psk_hash      BLOB,
    descriptor    BLOB,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';

CREATE TABLE IF NOT EXISTS channel_members (
    channel_id   TEXT NOT NULL REFERENCES channels(channel_id),
    entity_key   BLOB NOT NULL,
    role         TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
    posture      TEXT NOT NULL DEFAULT 'active' CHECK(posture IN ('active', 'removed')),
    joined_at    TEXT NOT NULL,
    removed_at   TEXT,
    PRIMARY KEY (channel_id, entity_key)
);

CREATE INDEX IF NOT EXISTS idx_members_entity ON channel_members(entity_key);

CREATE TABLE IF NOT EXISTS channel_keys (
    channel_id     TEXT PRIMARY KEY REFERENCES channels(channel_id),
    encrypted_psk  BLOB NOT NULL,
    key_version    INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS items (
    item_id         TEXT PRIMARY KEY,
    channel_id      TEXT NOT NULL REFERENCES channels(channel_id),
    author_id       BLOB NOT NULL,
    item_type       TEXT NOT NULL,
    published_at    TEXT NOT NULL,
    is_tombstone    INTEGER NOT NULL DEFAULT 0,
    parent_id       TEXT,
    key_version     INTEGER NOT NULL DEFAULT 1,
    content_hash    BLOB NOT NULL,
    signature       BLOB NOT NULL,
    encrypted_blob  BLOB NOT NULL,
    content_length  INTEGER NOT NULL,
    received_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_items_channel_published ON items(channel_id, published_at);
CREATE INDEX IF NOT EXISTS idx_items_channel_type      ON items(channel_id, item_type);
CREATE INDEX IF NOT EXISTS idx_items_content_hash      ON items(content_hash);

CREATE TABLE IF NOT EXISTS dm_peers (
    channel_id   TEXT PRIMARY KEY REFERENCES channels(channel_id),
    peer_key     BLOB NOT NULL
);
"#;

/// Migration v2: FTS5 search indexing (search-indexing.md §2).
const MIGRATION_V2: &str = r#"
CREATE TABLE IF NOT EXISTS search_content (
    rowid         INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id       TEXT NOT NULL UNIQUE,
    channel_id    TEXT NOT NULL,
    item_type     TEXT NOT NULL,
    published_at  TEXT NOT NULL,
    is_tombstone  INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',
    content_text  TEXT NOT NULL DEFAULT '',
    tags_text     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_search_content_channel ON search_content(channel_id);
CREATE INDEX IF NOT EXISTS idx_search_content_item_id ON search_content(item_id);
CREATE INDEX IF NOT EXISTS idx_search_content_type    ON search_content(channel_id, item_type);

CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    name,
    summary,
    content_text,
    tags_text,
    content = 'search_content',
    content_rowid = 'rowid',
    tokenize = 'unicode61'
);

CREATE TRIGGER IF NOT EXISTS search_fts_insert AFTER INSERT ON search_content BEGIN
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;

CREATE TRIGGER IF NOT EXISTS search_fts_delete AFTER DELETE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
END;

CREATE TRIGGER IF NOT EXISTS search_fts_update AFTER UPDATE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;
"#;

/// Migration v3: Channel scope for PAN ephemeral local channels (§8.2.2).
const MIGRATION_V3: &str = r#"
ALTER TABLE channels ADD COLUMN scope TEXT NOT NULL DEFAULT 'network'
    CHECK(scope IN ('network', 'local'));
"#;

/// Migration v4: device invites (decision 2026-09-30-agent-memory-sync §4.1).
///
/// Rebuilds `channels` to admit the `inbox` channel type (SQLite cannot
/// alter a CHECK constraint in place), then adds explicit trust, invite
/// processing state, and node metadata. Runs with foreign keys disabled,
/// per SQLite's table-rebuild procedure; `init_db` verifies integrity with
/// `PRAGMA foreign_key_check` before committing.
const MIGRATION_V4: &str = r#"
CREATE TABLE channels_v4 (
    channel_id    TEXT PRIMARY KEY,
    channel_name  TEXT,
    channel_type  TEXT NOT NULL CHECK(channel_type IN ('named', 'dm', 'group', 'inbox')),
    mode          TEXT NOT NULL CHECK(mode IN ('realtime', 'batch')),
    access        TEXT NOT NULL CHECK(access IN ('open', 'invite_only')),
    creator_id    BLOB NOT NULL,
    key_version   INTEGER NOT NULL DEFAULT 1,
    psk_hash      BLOB,
    descriptor    BLOB,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    scope         TEXT NOT NULL DEFAULT 'network' CHECK(scope IN ('network', 'local')),
    -- Membership/key epoch: the highest channel-state message applied
    -- (§4.1). States with a lower epoch are stale and ignored; equal
    -- epochs are ordered by author key, so all members converge.
    epoch         INTEGER NOT NULL DEFAULT 0,
    epoch_author  BLOB
);

INSERT INTO channels_v4 (channel_id, channel_name, channel_type, mode, access, creator_id,
                         key_version, psk_hash, descriptor, created_at, updated_at, scope)
    SELECT channel_id, channel_name, channel_type, mode, access, creator_id,
           key_version, psk_hash, descriptor, created_at, updated_at, scope
    FROM channels;

DROP TABLE channels;
ALTER TABLE channels_v4 RENAME TO channels;

CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';

-- Keys this node trusts to invite it into channels without asking:
-- set by `add-device` and `accept`. A person's other devices are also
-- trusted through membership of the personal channel (not stored here).
CREATE TABLE IF NOT EXISTS trusted_keys (
    entity_key  BLOB PRIMARY KEY,
    kind        TEXT NOT NULL CHECK(kind IN ('device', 'person')),
    label       TEXT,
    added_at    TEXT NOT NULL,
    revoked_at  TEXT
);

-- Processing state for invite items received in this node's inbox.
-- The invite itself stays in `items`; nothing secret is copied here.
CREATE TABLE IF NOT EXISTS invites (
    item_id     TEXT PRIMARY KEY,
    inviter     BLOB NOT NULL,
    channel_id  TEXT NOT NULL,
    status      TEXT NOT NULL
                CHECK(status IN ('pending', 'accepted', 'rejected', 'invalid', 'superseded')),
    received_at TEXT NOT NULL,
    decided_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_invites_status ON invites(status, received_at);

CREATE TABLE IF NOT EXISTS node_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"#;

/// Migration v5: replaceable items and arrival-order sync (decision
/// 2026-09-30-agent-memory-sync §4.3, §4.4a).
///
/// - `seq`: this node's arrival sequence, from a counter that never goes
///   backwards (deleting the newest row must not let a later item reuse its
///   number, or a peer paging by `seq` would skip it). Existing rows take
///   their rowid, which is already in insertion order.
/// - `slot`, `rev`: set together on replaceable items.
const MIGRATION_V5: &str = r#"
ALTER TABLE items ADD COLUMN seq INTEGER;
ALTER TABLE items ADD COLUMN slot BLOB;
ALTER TABLE items ADD COLUMN rev INTEGER;
-- Outbox: when a relay acknowledged storing this node's own item. NULL
-- items authored by this node are re-sent until one does.
ALTER TABLE items ADD COLUMN relayed_at TEXT;
UPDATE items SET seq = rowid;

CREATE TABLE IF NOT EXISTS counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
);
INSERT OR REPLACE INTO counters (name, value)
    VALUES ('item_seq', (SELECT COALESCE(MAX(seq), 0) FROM items));

CREATE INDEX IF NOT EXISTS idx_items_channel_seq ON items(channel_id, seq);
CREATE INDEX IF NOT EXISTS idx_items_slot ON items(channel_id, slot, author_id)
    WHERE slot IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_items_unrelayed ON items(author_id, seq)
    WHERE relayed_at IS NULL;
"#;

/// Migration v6: sync adapter state (decision 2026-09-30 §4.5). For each
/// local memory folder, channel, and key: what the folder and the channel
/// last agreed on (content hash, or NULL for "deleted", and revision).
const MIGRATION_V6: &str = r#"
CREATE TABLE IF NOT EXISTS sync_files (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    hash        BLOB,
    rev         INTEGER NOT NULL,
    PRIMARY KEY (folder, channel_id, key)
);
"#;

/// Migration v7: aggregate usage counts for relay operators
/// (`crate::usage`). Peers are stored as a keyed hash, never as a key.
const MIGRATION_V7: &str = r#"
CREATE TABLE IF NOT EXISTS peer_sightings (
    peer_hash   BLOB PRIMARY KEY,
    is_relay    INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_peer_sightings_last ON peer_sightings(last_seen);
CREATE INDEX IF NOT EXISTS idx_items_received ON items(received_at);
"#;

/// Migration v8: the newest channel state this node has sent to each member
/// of each channel, kept until that member is seen to hold it
/// (`crate::offers`, decision 2026-09-30 §4.1). Times are Unix seconds.
const MIGRATION_V8: &str = r#"
CREATE TABLE IF NOT EXISTS state_offers (
    channel_id      TEXT NOT NULL,
    member          BLOB NOT NULL,
    epoch           INTEGER NOT NULL,
    item_id         TEXT NOT NULL,
    sent_at         INTEGER NOT NULL,
    last_offered_at INTEGER NOT NULL,
    offers          INTEGER NOT NULL DEFAULT 1,
    confirmed_at    INTEGER,
    PRIMARY KEY (channel_id, member)
);
"#;

/// Migration v9: who wrote the entry a folder agreed (decision 2026-09-30
/// §4.5): a device's 32-byte key, or an empty value for nobody. NULL for a
/// row from before, until the folder next records that file.
const MIGRATION_V9: &str = r#"
ALTER TABLE sync_files ADD COLUMN author BLOB;
"#;

/// Migration v10: the memories this device deleted with their index
/// lines (decision 2026-09-30 §4.5, `index_lines`): for each file of a
/// folder, the line this device removed for it and when, when it
/// published the file's delete, whether the two were within an hour of
/// each other, and how many times the line has been put back. Times are
/// seconds, in UTC.
const MIGRATION_V10: &str = r#"
CREATE TABLE index_lines (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    file        TEXT NOT NULL,
    line        TEXT,
    line_at     INTEGER,
    deleted_at  INTEGER,
    whole       INTEGER NOT NULL DEFAULT 0,
    put_back    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (folder, channel_id, file)
);
"#;

/// Migration v11: entries in the form of a channel from its secret
/// (decision 2026-10-04 §2.3, §2.4, `entries`), beside `items`, which
/// stays as it is. One row for each author in each slot of each channel:
/// the newest revision that author signed there. A channel is known by
/// its ID, and the table refers to no other: a relay stores an entry with
/// no list of members and no state of the channel.
///
/// `seq` is the order in which this node stored its entries, from a
/// counter of its own that never goes backwards, as the arrival order of
/// `items` is. `stored_at` is in seconds, in UTC.
const MIGRATION_V11: &str = r#"
CREATE TABLE entries (
    channel_id   BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot         BLOB NOT NULL CHECK(length(slot) = 32),
    author       BLOB NOT NULL CHECK(length(author) = 32),
    rev          INTEGER NOT NULL CHECK(rev >= 1),
    is_delete    INTEGER NOT NULL CHECK(is_delete IN (0, 1)),
    content      BLOB NOT NULL,
    author_sig   BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig  BLOB NOT NULL CHECK(length(channel_sig) = 64),
    seq          INTEGER NOT NULL,
    stored_at    INTEGER NOT NULL,
    PRIMARY KEY (channel_id, slot, author)
);

CREATE UNIQUE INDEX idx_entries_channel_seq ON entries(channel_id, seq);

INSERT OR IGNORE INTO counters (name, value) VALUES ('entry_seq', 0);
"#;

/// Migration v12: what a device holds of its person (decision 2026-10-04
/// §3 to §6, `person`), beside everything that is there, which stays as it
/// is. It is in the node's database so that it changes in one transaction
/// with a statement (§3).
///
/// - `person`: one row, or none where the device follows no phrase. What
///   it follows (the phrase's public key, the statement key and the ID of
///   the phrase's channel: never the words), the statement it has applied
///   as its signed bytes, and the state it is in.
/// - `person_secrets`: its secrets by statement number. The one it has
///   applied has no time. Each one it left has the time it left it, by
///   its own clock, in seconds.
/// - `person_change_entries`: the latest change entry it has seen, whole,
///   and the one made apart from it where it is in a fork.
/// - `person_additions`: the records of additions it has seen under the
///   applied statement, in the order it saw them, each counted or not.
/// - `person_names`: the names it holds in the current generation, each
///   with its channel's ID, so that either is found from the other.
const MIGRATION_V12: &str = r#"
CREATE TABLE person (
    one             INTEGER PRIMARY KEY CHECK(one = 1),
    state           TEXT NOT NULL
                    CHECK(state IN ('applied', 'fork', 'removed', 'not_listed', 'not_opened')),
    phrase_key      BLOB NOT NULL CHECK(length(phrase_key) = 32),
    statement_key   BLOB NOT NULL CHECK(length(statement_key) = 32),
    phrase_channel  BLOB NOT NULL CHECK(length(phrase_channel) = 32),
    statement       BLOB NOT NULL
);

CREATE TABLE person_secrets (
    number   INTEGER NOT NULL CHECK(number BETWEEN 1 AND 256),
    secret   BLOB NOT NULL CHECK(length(secret) = 32),
    left_at  INTEGER,
    PRIMARY KEY (number, secret)
);

CREATE UNIQUE INDEX idx_person_secrets_applied ON person_secrets((left_at IS NULL))
    WHERE left_at IS NULL;

CREATE TABLE person_change_entries (
    kept            TEXT PRIMARY KEY CHECK(kept IN ('latest', 'apart')),
    channel         BLOB NOT NULL CHECK(length(channel) = 32),
    slot            BLOB NOT NULL CHECK(length(slot) = 32),
    author          BLOB NOT NULL CHECK(length(author) = 32),
    rev             INTEGER NOT NULL CHECK(rev BETWEEN 1 AND 256),
    content         BLOB NOT NULL,
    author_sig      BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig     BLOB NOT NULL CHECK(length(channel_sig) = 64)
);

CREATE TABLE person_additions (
    seen     INTEGER PRIMARY KEY,
    record   BLOB NOT NULL UNIQUE,
    key      BLOB NOT NULL CHECK(length(key) = 32),
    adder    BLOB NOT NULL CHECK(length(adder) = 32),
    counted  INTEGER NOT NULL CHECK(counted IN (0, 1)),
    seen_at  INTEGER NOT NULL
);

CREATE TABLE person_names (
    name     TEXT PRIMARY KEY CHECK(length(name) >= 1),
    channel  BLOB NOT NULL UNIQUE CHECK(length(channel) = 32),
    held_at  INTEGER NOT NULL
);
"#;

/// Migration v13: the channels from their secrets that a relay holds
/// (decision 2026-10-04 §2.4, §2.5, `relay`), beside everything that is
/// there, which stays as it is. One row for each channel that this node
/// holds as a relay:
///
/// - `held_since`: since when it has held the channel, which is when it
///   first took it, or an earlier time that a relay its operator lists
///   says it has held it since. Over its cap a relay drops the channels it
///   has held for the shortest time first, and of two held since one time,
///   the one whose row was made later.
/// - `used_at`: when the channel's key was last proved, or an entry of it
///   last shown that the relay holds. What nobody uses goes after 90 days.
/// - `bytes`: what the channel holds, as entries are counted.
/// - `mark`: 8 random bytes that are this holding's own, and never all
///   zeros. A channel that is dropped loses its row, and is taken again
///   under another mark: a place in the channel is a count within one
///   holding, and the mark says which.
///
/// A channel that is dropped loses its row, and is new when it is taken
/// again. Times are in seconds, in UTC.
///
/// And each entry is given its place in the order of its channel's own
/// entries (`entries.channel_place`): a count for each channel, from 1,
/// that says nothing of any other channel. A channel is handed to a
/// holder of its key in pages by that count. The entries that are there
/// are counted in the order in which this node stored them.
///
/// And what a device keeps of the last hand-over it made for each key
/// (`person_hand_overs`, decision 2026-10-04 §6): the pair channel of
/// the two, the revision of that hand-over there, when it says it was
/// made, and whether the store still holds it. Never the hand-over
/// itself, which holds the secret. It is one of the tables of what a
/// device holds of its person, and is made by this step.
///
/// And what `items` holds is counted as it is written (`item_count`,
/// `item_bytes` in `counters`): how many items there are, and the bytes of
/// their content together. A relay's cap for the older kind of channel is
/// set against what those items are counted at, and not against the
/// database's pages, which hold the table of entries too (decision
/// 2026-10-04 §2.5, §16). Three triggers keep the two counts, in the
/// write that changes a row, whoever makes it; the rows that are there
/// are counted by this step. So the count costs the same to read however
/// much is held.
const MIGRATION_V13: &str = r#"
CREATE TABLE relay_channels (
    channel_id  BLOB PRIMARY KEY CHECK(length(channel_id) = 32),
    held_since  INTEGER NOT NULL,
    used_at     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL CHECK(bytes >= 0),
    mark        BLOB NOT NULL CHECK(length(mark) = 8 AND mark != zeroblob(8))
);

CREATE INDEX idx_relay_channels_held ON relay_channels(held_since);
CREATE INDEX idx_relay_channels_used ON relay_channels(used_at);

ALTER TABLE entries ADD COLUMN channel_place INTEGER NOT NULL DEFAULT 0;

UPDATE entries SET channel_place = (
    SELECT COUNT(*) FROM entries AS stored
    WHERE stored.channel_id = entries.channel_id AND stored.seq <= entries.seq
);

CREATE UNIQUE INDEX idx_entries_channel_place ON entries(channel_id, channel_place);

CREATE TABLE person_hand_overs (
    key      BLOB PRIMARY KEY CHECK(length(key) = 32),
    channel  BLOB NOT NULL CHECK(length(channel) = 32),
    rev      INTEGER NOT NULL CHECK(rev >= 1),
    made_at  INTEGER NOT NULL,
    held     INTEGER NOT NULL CHECK(held IN (0, 1))
);

INSERT OR REPLACE INTO counters (name, value)
    VALUES ('item_count', (SELECT COUNT(*) FROM items));
INSERT OR REPLACE INTO counters (name, value)
    VALUES ('item_bytes', (SELECT COALESCE(SUM(content_length), 0) FROM items));

CREATE TRIGGER items_counted_in AFTER INSERT ON items BEGIN
    UPDATE counters SET value = value + 1 WHERE name = 'item_count';
    UPDATE counters SET value = value + NEW.content_length WHERE name = 'item_bytes';
END;

CREATE TRIGGER items_counted_out AFTER DELETE ON items BEGIN
    UPDATE counters SET value = value - 1 WHERE name = 'item_count';
    UPDATE counters SET value = value - OLD.content_length WHERE name = 'item_bytes';
END;

CREATE TRIGGER items_counted_again AFTER UPDATE OF content_length ON items BEGIN
    UPDATE counters SET value = value - OLD.content_length + NEW.content_length
        WHERE name = 'item_bytes';
END;
"#;

/// Migration v14: what a device keeps of each relay it is set up with,
/// for each channel of its own (decision 2026-10-04 §4.6, §7.3,
/// `at_relays`), beside everything that is there, which stays as it is.
///
/// One row for each relay, by its node key, and channel (`at_relays`):
///
/// - `mark`, `place`: the device's place in the relay's holding of the
///   channel, with the mark of that holding: where its next pull goes on
///   from. No mark is no place, and the channel is read from the start. A
///   mark is 8 bytes, and never all zeros, as a relay's is.
/// - `sent_to`: how far the device has sent the relay what its own store
///   holds of the channel, in the order in which the store took its
///   entries (`entries.seq`).
/// - `carried_to`: the same for what the device carried into the channel
///   when it applied a statement, which is sent by a rule of its own.
///
/// And one row (`person_carried`) that says how far what the store holds
/// is what the device carried: the store's order as it stood when the
/// device last applied a statement. It is one of the tables of what a
/// device holds of its person.
///
/// A relay keeps nothing in either.
const MIGRATION_V14: &str = r#"
CREATE TABLE at_relays (
    relay       BLOB NOT NULL CHECK(length(relay) = 32),
    channel     BLOB NOT NULL CHECK(length(channel) = 32),
    mark        BLOB CHECK(mark IS NULL OR (length(mark) = 8 AND mark != zeroblob(8))),
    place       INTEGER NOT NULL DEFAULT 0 CHECK(place >= 0),
    sent_to     INTEGER NOT NULL DEFAULT 0 CHECK(sent_to >= 0),
    carried_to  INTEGER NOT NULL DEFAULT 0 CHECK(carried_to >= 0),
    PRIMARY KEY (relay, channel)
);

CREATE INDEX idx_at_relays_channel ON at_relays(channel);

CREATE TABLE person_carried (
    one    INTEGER PRIMARY KEY CHECK(one = 1),
    up_to  INTEGER NOT NULL CHECK(up_to >= 0)
);
"#;

/// Migration v15: what a person did on a device at a terminal, and what
/// the device still has to tell them (decision 2026-10-04 §5.1, §6, §8).
///
/// Three tables, each one of what a device holds of its person:
///
/// - `person_typed_keys`: a key that a person typed at `cordelia accept`,
///   with when. A pair channel is read only with such a key, and only for
///   an hour after it was typed (§2.2). `taken_at` is when a hand-over was
///   taken with it: the key is then spent, and reads nothing more. `said`
///   is what became of the last hand-over that was read with it, in words
///   for a person.
/// - `person_left_out`: a key that this device counted as a device before
///   a statement, and that is in neither of that statement's lists (§8),
///   with the label it was known by and the statement's number. It is
///   shown until a person clears it, or a later statement lists it.
/// - `person_cleared`: a notice that a person has cleared here, by what
///   the notice is named by: 32 bytes. A notice that is cleared is shown
///   no more on this device.
///
/// A relay keeps nothing in any of them.
const MIGRATION_V15: &str = r#"
CREATE TABLE person_typed_keys (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    typed_at  INTEGER NOT NULL,
    taken_at  INTEGER,
    said      TEXT
);

CREATE TABLE person_left_out (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    label     TEXT NOT NULL,
    number    INTEGER NOT NULL CHECK(number >= 1),
    noted_at  INTEGER NOT NULL
);

CREATE TABLE person_cleared (
    notice      BLOB PRIMARY KEY CHECK(length(notice) = 32),
    cleared_at  INTEGER NOT NULL
);
"#;

/// Migration v16: what a relay refused for room, kept to be sent again
/// (decision 2026-10-04 §16).
///
/// One row for each entry of a channel of the device's own that a relay
/// had no room for (`at_relays_refused`): the relay by its node key, the
/// channel, and the entry's place in the order in which the device's own
/// store took its entries (`entries.seq`). How far a relay was sent a
/// channel goes on past such an entry, so that what follows it is still
/// offered: a delete, or a replacement that is no larger, makes room.
/// The entry itself is sent again after a wait, and its row goes when
/// the relay holds it, or when the store holds it no more.
///
/// A relay keeps nothing in it.
const MIGRATION_V16: &str = r#"
CREATE TABLE at_relays_refused (
    relay BLOB NOT NULL CHECK(length(relay) = 32),
    channel BLOB NOT NULL CHECK(length(channel) = 32),
    seq INTEGER NOT NULL CHECK(seq > 0),
    PRIMARY KEY (relay, channel, seq)
);

CREATE INDEX idx_at_relays_refused_channel ON at_relays_refused(channel);
"#;

/// Migration v17: what the sync adapter keeps in a channel from its
/// secret (decision 2026-10-04 §2.3, §7.3, §16).
///
/// - `sync_files.chain`: the chain of the entry that a folder agreed, as
///   its links one after another, each the start of a hash and the start
///   of a key. NULL where that entry lacked what it should say, and in a
///   row from before. With it `sync_files.author` is the key that signed
///   that entry: a folder's record keeps the signer and the chain of the
///   one entry it agreed.
/// - `person_names_before`: one row for each name and key, where that key
///   had said, in the personal channel of a generation that the device
///   left, that it syncs the name, with when the device left it, in
///   seconds. It is written in the transaction that applies a statement,
///   from what the device's own store held, and is what a device shows of
///   the names that no device lists yet in the new generation. It is one
///   of the tables of what a device holds of its person.
///
/// A relay keeps nothing in either.
const MIGRATION_V17: &str = r#"
ALTER TABLE sync_files ADD COLUMN chain BLOB;

CREATE TABLE person_names_before (
    name     TEXT NOT NULL CHECK(length(name) >= 1),
    said_by  BLOB NOT NULL CHECK(length(said_by) = 32),
    left_at  INTEGER NOT NULL,
    PRIMARY KEY (name, said_by)
);
"#;

/// Migration v18: what a device keeps of a person's acts across a
/// statement, and of the row a typed key was typed in (decision
/// 2026-10-04 §5.1, §7.1, §8, §16).
///
/// - `person_typed_keys.stood`: where the device stood, of the rows of
///   §5.1, when a person typed the key and said yes: `no_phrase`, `alone`,
///   `several` or `not_listed`. A hand-over is taken with the key only
///   while the device stands there. Empty in a row from before, which
///   reads nothing.
/// - `person_left_out.cleared_at`: when a person cleared the notice of a
///   key that is not in the last change. The row stays, so that adding
///   that key still says what it is; it is shown no more. NULL while it
///   is shown.
/// - `person_left`: a device's word that it left, kept when a statement
///   is applied that still lists its key, where nobody had cleared it:
///   the key, what the notice is named by, the number of the statement
///   under which it said so, and when this device noted it. It is shown
///   until a person clears it here, or a statement lists the key no
///   more.
///
/// A relay keeps nothing in any of them.
const MIGRATION_V18: &str = r#"
ALTER TABLE person_typed_keys ADD COLUMN stood TEXT NOT NULL DEFAULT '';

ALTER TABLE person_left_out ADD COLUMN cleared_at INTEGER;

CREATE TABLE person_left (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    notice    BLOB NOT NULL CHECK(length(notice) = 32),
    number    INTEGER NOT NULL CHECK(number >= 1),
    noted_at  INTEGER NOT NULL
);
"#;

/// Migration v19: what a device keeps of messages between the person's
/// own agents (decision 2026-10-09 §2.3, §2.5, §6, §7, §9.2).
///
/// A signer is the key that signed a message's entry (32 bytes), a
/// generation is the messages channel an entry is in, kept as the ID of
/// its row in `message_generations` (§7.1, §9.2), a message's ID is 16
/// bytes, and a time is in seconds by the device's own clock. A number,
/// and the highest number held, is at most 2^42 - 1
/// (`AGENT_MESSAGE_NUMBER_MAX`, §2.3), and a statement's number at most
/// `MAX_STATEMENT_NUMBER`. Each column takes only its type and its bound:
/// a blob of its length, or an integer, and a flag 0 or 1. A flag and a
/// kind of `to` are checked by their `IN (...)` alone, which a column of
/// integer affinity passes only with an integer; a generation by its
/// foreign key to the integer key of `message_generations`. The fields a
/// row is overwritten in before it goes take any type, since they are
/// written over with a blob of zeros.
///
/// - `message_generations`: one row for each messages channel the device
///   has held, by its ID (an integer, which is the generation in every
///   other table), with the channel's ID, the number of the statement
///   that began it, and when the device first held it. A statement's
///   number is not a generation: a device alone under a phrase that makes
///   a new phrase is at statement 1 again, with a new messages channel.
/// - `message_index`: one row for each message the device holds opened,
///   by its ID, with every field it was opened to: the label the device
///   knew its signer by, `to_kind` (1: one name, in `to_name`; 2: every
///   name, and no `to_name`), `from_name`, `sent`, the subject, `thread`
///   and `answers` (zeros where none), whether it asks for an answer,
///   the link (NULL where none), the body, when the device first held
///   it, and its place: when it was first shown, NULL until then (§6,
///   §7.1); and `not_every_relay`, 1 where it is the device's own and its
///   kept value was dropped before every relay had taken it, so that
///   `log` says it may not have reached every relay (§2.3, §4.1). The
///   body, the link, the subject, `from_name` and `to_name` are
///   overwritten with zeros before a row is deleted
///   ([`crate::messages::drop_row`]).
/// - `message_numbers`: the numbers each message is held at, one row for
///   each signer, generation and number. A message held at two numbers
///   is one row of the index and two here. They go with the index row.
/// - `message_first_held`: one row for each live number held, with its
///   ID, `sent`, and when it was first held; or with no ID and no `sent`
///   where the number was first held as a clearing, which counts the
///   number as gone and not as overwritten (§2.5). It outlives the index
///   row, so that an entry taken again at a live number after its 30
///   days is not shown again (§7.1).
/// - `message_signers`: for each signer and generation, H, the highest
///   number held of a message or a clearing, with the counts of numbers
///   that were overwritten before they were shown and of entries that
///   were not messages, and `counted_from`, the first number of that
///   signer the device held in that generation, or a lower one held
///   after it while it was live, from which what was overwritten is
///   counted, NULL until it holds one, and never above H (§2.5).
/// - `message_places`: the time of each place given to a signer in a
///   generation, kept for the hour of the reader's rate (§6).
/// - `message_lists`: the marks of the latest list of each other device,
///   by its key (§7.2).
/// - `message_read_here`: this device's own table of what its agents
///   read: each mark, with the message's ID and the name that read it,
///   and when it was made; or the mark alone, where it was merged from
///   the device's own list on a relay and no message has been found for
///   it, with when it was merged. `seq` is the order of the table, unique
///   on the device: the newest is the highest, and a mark merged as older
///   than any held takes one below the lowest, so it may be 0 or below.
///   A row with an ID goes with its message (§7.2).
/// - `message_announced`, `message_read_by_a_person`: the device's own
///   marks, that `summary` announced a message to the agent of a name
///   here, and that a person read it here. They go with the message.
/// - `message_sends`: one row for each send by the device's clock, with
///   the name of the folder's agent that sent and whether it was to every
///   name; a send again has no name (§6).
/// - `message_kept`, `message_kept_numbers`, `message_kept_taken`: each
///   message of the device's own that not every relay has taken, its
///   value as it was sent, the numbers it was sent under, and the relays
///   that have taken it (§2.3); and `again`, 1 where it waits to be sent
///   again under the next number: a relay answered that it holds another
///   entry of the device's at its newest number, or a relay handed back
///   the device's own entry over it.
///
/// `secure_delete` is not a step: it is set on a personal node's
/// connection where the node opens its store, before the steps run
/// (§7.1). A relay keeps nothing in any of these tables.
const MIGRATION_V19: &str = r#"
CREATE TABLE message_generations (
    id          INTEGER PRIMARY KEY,
    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'
                                       AND statement >= 1 AND statement <= 256),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer')
);

CREATE TABLE message_index (
    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),
    signer           BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    label            TEXT NOT NULL,
    generation       INTEGER NOT NULL REFERENCES message_generations(id),
    to_kind          INTEGER NOT NULL CHECK(to_kind IN (1, 2)),
    to_name          TEXT CHECK((to_kind = 1) = (to_name IS NOT NULL)),
    from_name        TEXT NOT NULL,
    sent             INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    subject          TEXT NOT NULL,
    thread           BLOB NOT NULL CHECK(typeof(thread) = 'blob' AND length(thread) = 16),
    answers          BLOB NOT NULL CHECK(typeof(answers) = 'blob' AND length(answers) = 16),
    asks             INTEGER NOT NULL CHECK(asks IN (0, 1)),
    link             TEXT,
    body             TEXT NOT NULL,
    first_held       INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    placed_at        INTEGER CHECK(placed_at IS NULL OR typeof(placed_at) = 'integer'),
    not_every_relay  INTEGER NOT NULL DEFAULT 0
                         CHECK(not_every_relay IN (0, 1))
);

CREATE INDEX idx_message_index_signer ON message_index(signer, generation);

CREATE TABLE message_numbers (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                       AND number >= 1 AND number <= 4398046511103),
    id          BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
    PRIMARY KEY (signer, generation, number)
);

CREATE INDEX idx_message_numbers_id ON message_numbers(id);

CREATE TABLE message_first_held (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                       AND number >= 1 AND number <= 4398046511103),
    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),
    sent        INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    CHECK((id IS NULL) = (sent IS NULL)),
    PRIMARY KEY (signer, generation, number)
);

CREATE TABLE message_signers (
    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation    INTEGER NOT NULL REFERENCES message_generations(id),
    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'
                                         AND highest >= 0 AND highest <= 4398046511103),
    overwritten   INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(overwritten) = 'integer' AND overwritten >= 0),
    not_messages  INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(not_messages) = 'integer' AND not_messages >= 0),
    counted_from  INTEGER CHECK(counted_from IS NULL
                                OR (typeof(counted_from) = 'integer'
                                    AND counted_from >= 1 AND counted_from <= highest)),
    PRIMARY KEY (signer, generation)
);

CREATE TABLE message_places (
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer')
);

CREATE INDEX idx_message_places ON message_places(signer, generation, placed_at);

-- A list is stored without repeats: whoever writes the taking of a list
-- must keep each of its marks once, since a row is keyed by the device's
-- key and the mark.
CREATE TABLE message_lists (
    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    PRIMARY KEY (key, mark)
);

CREATE INDEX idx_message_lists_mark ON message_lists(mark);

CREATE TABLE message_read_here (
    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),
    id         BLOB REFERENCES message_index(id) ON DELETE CASCADE,
    name       TEXT CHECK(name IS NULL OR length(name) >= 1),
    made_at    INTEGER NOT NULL CHECK(typeof(made_at) = 'integer'),
    merged_at  INTEGER CHECK(merged_at IS NULL OR typeof(merged_at) = 'integer'),
    CHECK((id IS NULL) = (name IS NULL)),
    CHECK(id IS NOT NULL OR merged_at IS NOT NULL)
);

CREATE INDEX idx_message_read_here_id ON message_read_here(id);

CREATE TABLE message_announced (
    id    BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,
    name  TEXT NOT NULL CHECK(length(name) >= 1),
    PRIMARY KEY (id, name)
);

CREATE TABLE message_read_by_a_person (
    id  BLOB PRIMARY KEY REFERENCES message_index(id) ON DELETE CASCADE
);

CREATE TABLE message_sends (
    sent_at  INTEGER NOT NULL CHECK(typeof(sent_at) = 'integer'),
    name     TEXT CHECK(name IS NULL OR length(name) >= 1),
    to_all   INTEGER NOT NULL CHECK(to_all IN (0, 1)),
    CHECK(name IS NOT NULL OR to_all = 0)
);

CREATE INDEX idx_message_sends_at ON message_sends(sent_at);

CREATE TABLE message_kept (
    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),
    generation  INTEGER NOT NULL REFERENCES message_generations(id),
    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),
    sent        INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    kept_at     INTEGER NOT NULL CHECK(typeof(kept_at) = 'integer'),
    again       INTEGER NOT NULL DEFAULT 0 CHECK(typeof(again) = 'integer' AND again IN (0, 1))
);

CREATE TABLE message_kept_numbers (
    id      BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,
    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                   AND number >= 1 AND number <= 4398046511103),
    PRIMARY KEY (id, number)
);

CREATE TABLE message_kept_taken (
    id     BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,
    relay  BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),
    PRIMARY KEY (id, relay)
);
"#;

/// Run `sql` and set the schema version to `version` as one transaction:
/// both happen, or neither. For a step that cannot be run twice (a column
/// added), so that a start cut short between the two leaves it to be run
/// again from the beginning.
///
/// The version is read again inside the transaction, and the step is not
/// run if the database is already at `version`. The node and a command
/// each open the database for themselves, and two that open it at one
/// moment both read the version from before: the second would otherwise
/// run the step a second time, and fail.
fn migrate_in_one(conn: &Connection, sql: &str, version: u32) -> Result<(), StorageError> {
    conn.execute_batch("BEGIN IMMEDIATE;")?;
    let step = || -> rusqlite::Result<()> {
        let now: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if now >= version {
            return Ok(());
        }
        conn.execute_batch(sql)?;
        conn.pragma_update(None, "user_version", version)
    };
    match step() {
        Ok(()) => Ok(conn.execute_batch("COMMIT;")?),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK;");
            Err(e.into())
        }
    }
}

/// Initialise the database: set pragmas and run pending migrations.
///
/// **A database from a later version is refused** (decision 2026-10-04
/// §10.1): one whose version is above this schema's was written by a
/// later version of the program, which may keep in it what this one
/// would not know to keep. The version is read before anything else is
/// done, and nothing is changed: no pragma is set, and no step is run.
/// Whoever opens the database is told both versions
/// ([`StorageError::LaterVersion`]).
pub fn init_db(conn: &Connection) -> Result<(), StorageError> {
    refuse_a_later_version(conn, SCHEMA_VERSION)?;
    run_steps(conn, SCHEMA_VERSION)
}

/// Refuse a database whose version is above `own`, as a schema at version
/// `own` refuses it: this one's, or, in a test, the version before's
/// (decision 2026-10-09 §9.2).
fn refuse_a_later_version(conn: &Connection, own: u32) -> Result<(), StorageError> {
    let found: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if found > own {
        return Err(StorageError::LaterVersion { found, own });
    }
    Ok(())
}

/// Initialise a database as the released version of the program does:
/// its pragmas, and the schema's steps up to that version's
/// ([`RELEASED_SCHEMA_VERSION`]) and none after. For a test of what this
/// version does with a database of that one (decision 2026-10-04 §10.1).
pub fn init_db_as_released(conn: &Connection) -> Result<(), StorageError> {
    run_steps(conn, RELEASED_SCHEMA_VERSION)
}

/// Make `conn`, a database with nothing in it, one at schema version 3,
/// as a version of the program that stopped there left it: for a test of
/// what the steps after it leave of what it held. The step to version 4
/// rewrites the table `channels`, so what that table held is freed as the
/// step runs (decision 2026-10-09 §7.1).
pub fn at_version_3(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(&format!("{MIGRATION_V1}{MIGRATION_V2}{MIGRATION_V3}"))?;
    conn.pragma_update(None, "user_version", 3)?;
    Ok(())
}

/// Set the pragmas, and run the steps that the database has not had, up
/// to version `up_to`: this schema's, or the released version's.
fn run_steps(conn: &Connection, up_to: u32) -> Result<(), StorageError> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;",
    )?;

    let current: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current < 1 {
        tracing::info!("applying migration v1 (initial schema)");
        conn.execute_batch(MIGRATION_V1)?;
        conn.pragma_update(None, "user_version", 1)?;
    }

    if current < 2 {
        tracing::info!("applying migration v2 (FTS5 search)");
        conn.execute_batch(MIGRATION_V2)?;
        conn.pragma_update(None, "user_version", 2)?;
    }

    if current < 3 {
        tracing::info!("applying migration v3 (channel scope)");
        conn.execute_batch(MIGRATION_V3)?;
        conn.pragma_update(None, "user_version", 3)?;
    }

    if current < 4 {
        tracing::info!("applying migration v4 (device invites)");
        migrate_v4(conn)?;
    }

    if current < 5 {
        tracing::info!("applying migration v5 (replaceable items, arrival order)");
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        match conn
            .execute_batch(MIGRATION_V5)
            .and_then(|_| conn.pragma_update(None, "user_version", 5))
        {
            Ok(()) => conn.execute_batch("COMMIT;")?,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e.into());
            }
        }
    }

    if current < 6 {
        tracing::info!("applying migration v6 (sync adapter state)");
        conn.execute_batch(MIGRATION_V6)?;
        conn.pragma_update(None, "user_version", 6)?;
    }

    if current < 7 {
        tracing::info!("applying migration v7 (usage counts)");
        conn.execute_batch(MIGRATION_V7)?;
        conn.pragma_update(None, "user_version", 7)?;
    }

    if current < 8 {
        tracing::info!("applying migration v8 (channel states sent, until confirmed)");
        conn.execute_batch(MIGRATION_V8)?;
        conn.pragma_update(None, "user_version", 8)?;
    }

    if current < 9 {
        tracing::info!("applying migration v9 (who wrote what a folder agreed)");
        migrate_in_one(conn, MIGRATION_V9, 9)?;
    }

    if current < 10 {
        tracing::info!("applying migration v10 (the lines of memories deleted here)");
        migrate_in_one(conn, MIGRATION_V10, 10)?;
    }

    if up_to <= RELEASED_SCHEMA_VERSION {
        return Ok(());
    }

    if current < 11 {
        tracing::info!("applying migration v11 (entries of a channel from its secret)");
        migrate_in_one(conn, MIGRATION_V11, 11)?;
    }

    if current < 12 {
        tracing::info!("applying migration v12 (what a device holds of its person)");
        migrate_in_one(conn, MIGRATION_V12, 12)?;
    }

    if current < 13 {
        tracing::info!("applying migration v13 (the channels a relay holds, from their secrets)");
        migrate_in_one(conn, MIGRATION_V13, 13)?;
    }

    let actual = migrate_from_v13(conn, current)?;
    tracing::debug!(schema_version = actual, "database initialised");

    Ok(())
}

/// Run the steps after version 13 that a database at version `current`
/// has not had, each as the steps before it are run. Returns the version
/// the database is at then.
fn migrate_from_v13(conn: &Connection, current: u32) -> Result<u32, StorageError> {
    if current < 14 {
        tracing::info!("applying migration v14 (what a device keeps of each relay)");
        migrate_in_one(conn, MIGRATION_V14, 14)?;
    }

    if current < 15 {
        tracing::info!("applying migration v15 (what a person typed, cleared and is to be told)");
        migrate_in_one(conn, MIGRATION_V15, 15)?;
    }

    if current < 16 {
        tracing::info!("applying migration v16 (what a relay refused for room, to send again)");
        migrate_in_one(conn, MIGRATION_V16, 16)?;
    }

    if current < 17 {
        tracing::info!(
            "applying migration v17 (the chain of what a folder agreed, and names before)"
        );
        migrate_in_one(conn, MIGRATION_V17, 17)?;
    }

    if current < 18 {
        tracing::info!(
            "applying migration v18 (the row a key was typed in, and a word that outlives a change)"
        );
        migrate_in_one(conn, MIGRATION_V18, 18)?;
    }

    if current < 19 {
        tracing::info!("applying migration v19 (messages between the person's own agents)");
        migrate_in_one(conn, MIGRATION_V19, 19)?;
    }

    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

/// Apply migration v4 inside one transaction, with foreign keys disabled
/// for the `channels` rebuild and integrity checked before commit.
fn migrate_v4(conn: &Connection) -> Result<(), StorageError> {
    // PRAGMA foreign_keys is a no-op inside a transaction, so toggle it outside.
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;

    let result = (|| -> Result<(), StorageError> {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        conn.execute_batch(MIGRATION_V4)?;

        // Every child row must still reference an existing channel.
        let violations: i64 =
            conn.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })?;
        if violations > 0 {
            return Err(StorageError::Migration(format!(
                "v4: {violations} foreign key violations after channels rebuild"
            )));
        }

        conn.pragma_update(None, "user_version", 4)?;
        conn.execute_batch("COMMIT;")?;
        Ok(())
    })();

    if result.is_err() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_fresh_db() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_init_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        init_db(&conn).unwrap(); // second call should be a no-op

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    /// A database as the released version leaves it is at that version's
    /// schema, with its tables and none of a later step's; opened as this
    /// version opens any, it is stepped the rest of the way (decision
    /// 2026-10-04 §10.1).
    #[test]
    fn test_a_database_as_released_is_stepped_no_further_than_the_released_version() {
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has = |conn: &Connection, table: &str| -> bool {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = ?1)",
                [table],
                |row| row.get(0),
            )
            .unwrap()
        };
        let conn = Connection::open_in_memory().unwrap();
        init_db_as_released(&conn).unwrap();
        assert_eq!(version(&conn), RELEASED_SCHEMA_VERSION);
        assert_eq!(RELEASED_SCHEMA_VERSION, 10);
        assert!(has(&conn, "index_lines") && has(&conn, "channels"));
        assert!(!has(&conn, "entries") && !has(&conn, "person"));
        assert!(!has(&conn, "message_index") && !has(&conn, "message_kept"));
        // Again: nothing more.
        init_db_as_released(&conn).unwrap();
        assert_eq!(version(&conn), RELEASED_SCHEMA_VERSION);

        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has(&conn, "entries") && has(&conn, "person"));
        assert!(has(&conn, "message_index") && has(&conn, "message_kept"));
        // A database that is further on is left where it is.
        init_db_as_released(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    /// A database from a later version is refused, by whoever opens it,
    /// with both versions named, and nothing of it is changed (decision
    /// 2026-10-04 §10.1): not its version, not a row, not the way it is
    /// journalled, not a byte of its file. One at this schema's version,
    /// or at an earlier one, is opened as before.
    #[test]
    fn test_a_database_from_a_later_version_is_refused_and_not_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        let later = SCHEMA_VERSION + 1;
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE of_a_later_version (what TEXT);
                 INSERT INTO of_a_later_version VALUES ('kept');",
            )
            .unwrap();
            conn.pragma_update(None, "user_version", later).unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        let refused = match crate::db::open(&path) {
            Err(e) => e,
            Ok(_) => panic!("a database from a later version was opened"),
        };
        assert!(
            matches!(refused, StorageError::LaterVersion { found, own }
                if found == later && own == SCHEMA_VERSION),
            "{refused:?}"
        );
        let says = refused.to_string();
        assert!(
            says.contains(&format!("schema version {later}"))
                && says.contains(&format!("schema version {SCHEMA_VERSION} "))
                && says.contains("nothing was changed"),
            "{says}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let conn = Connection::open(&path).unwrap();
        assert!(matches!(
            init_db(&conn),
            Err(StorageError::LaterVersion { .. })
        ));
        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let tables: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version, journal.as_str(), tables), (later, "delete", 1));
        drop(conn);
        assert_eq!(std::fs::read(&path).unwrap(), before);

        // At this schema's version: opened, and nothing refused.
        let own = dir.path().join("own.db");
        drop(crate::db::open(&own).unwrap());
        assert!(crate::db::open(&own).is_ok());
    }

    #[test]
    fn test_tables_exist() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"channels".to_string()));
        assert!(tables.contains(&"channel_members".to_string()));
        assert!(tables.contains(&"channel_keys".to_string()));
        assert!(tables.contains(&"items".to_string()));
        assert!(tables.contains(&"dm_peers".to_string()));
    }

    #[test]
    fn test_channel_type_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'invalid', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err());
    }

    // T3-1 (HIGH): mode CHECK constraint
    #[test]
    fn test_mode_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'named', 'invalid_mode', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "mode CHECK should reject 'invalid_mode'");
    }

    // T3-1: access CHECK constraint
    #[test]
    fn test_access_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test', 'named', 'realtime', 'invalid_access', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(
            result.is_err(),
            "access CHECK should reject 'invalid_access'"
        );
    }

    // T3-1: role CHECK constraint
    #[test]
    fn test_role_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('ch1', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        ).unwrap();
        let result = conn.execute(
            "INSERT INTO channel_members (channel_id, entity_id, role, joined_at)
             VALUES ('ch1', X'01', 'superadmin', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "role CHECK should reject 'superadmin'");
    }

    #[test]
    fn test_scope_check_constraint() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let result = conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, scope, creator_id, created_at, updated_at)
             VALUES ('test_scope', 'named', 'realtime', 'open', 'invalid_scope', X'00', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(result.is_err(), "scope CHECK should reject 'invalid_scope'");
    }

    #[test]
    fn test_scope_default_is_network() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('test_default_scope', 'named', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')",
            [],
        ).unwrap();
        let scope: String = conn
            .query_row(
                "SELECT scope FROM channels WHERE channel_id = 'test_default_scope'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scope, "network");
    }

    #[test]
    fn test_inbox_channel_type_accepted() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        conn.execute(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('inbox_ab', 'inbox', 'realtime', 'invite_only', X'00', '2026-01-01', '2026-01-01')",
            [],
        )
        .expect("v4 admits the inbox channel type");
    }

    #[test]
    fn test_v4_tables_and_checks() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();

        let bad_kind = conn.execute(
            "INSERT INTO trusted_keys (entity_key, kind, added_at) VALUES (X'01', 'robot', '2026-01-01')",
            [],
        );
        assert!(
            bad_kind.is_err(),
            "trusted_keys.kind CHECK should reject 'robot'"
        );

        let bad_status = conn.execute(
            "INSERT INTO invites (item_id, inviter, channel_id, status, received_at)
             VALUES ('ci_1', X'01', 'grp_x', 'maybe', '2026-01-01')",
            [],
        );
        assert!(
            bad_status.is_err(),
            "invites.status CHECK should reject 'maybe'"
        );

        conn.execute(
            "INSERT INTO node_meta (key, value) VALUES ('personal_channel_id', 'grp_x')",
            [],
        )
        .unwrap();
    }

    /// Upgrading a populated v3 database must keep every row and every
    /// foreign key intact across the `channels` rebuild.
    #[test]
    fn test_upgrade_from_v3_preserves_data() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute_batch(MIGRATION_V2).unwrap();
        conn.execute_batch(MIGRATION_V3).unwrap();
        conn.pragma_update(None, "user_version", 3).unwrap();

        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id,
                                   key_version, psk_hash, created_at, updated_at, scope)
             VALUES ('named1', 'research', 'named', 'realtime', 'open', X'AA', 2, X'BB',
                     '2026-01-01', '2026-01-02', 'network'),
                    ('grp_1', NULL, 'group', 'batch', 'invite_only', X'AA', 1, NULL,
                     '2026-01-01', '2026-01-01', 'local');
             INSERT INTO channel_members (channel_id, entity_key, role, joined_at)
             VALUES ('named1', X'AA', 'owner', '2026-01-01'),
                    ('grp_1', X'CC', 'member', '2026-01-01');
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
             VALUES ('ci_1', 'named1', X'AA', 'message', '2026-01-01', X'01', X'02', X'03', 1);",
        )
        .unwrap();

        init_db(&conn).unwrap();

        let version: u32 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        // v5: existing items got an arrival sequence, and the counter
        // continues after it.
        let (seq, counter): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT seq FROM items WHERE item_id = 'ci_1'),
                        (SELECT value FROM counters WHERE name = 'item_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(seq > 0);
        assert_eq!(counter, seq);

        let fk_on: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(fk_on, 1, "foreign keys must be re-enabled after v4");

        let (name, kv, scope): (String, i64, String) = conn
            .query_row(
                "SELECT channel_name, key_version, scope FROM channels WHERE channel_id = 'named1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (name.as_str(), kv, scope.as_str()),
            ("research", 2, "network")
        );

        let counts: (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM channels),
                        (SELECT COUNT(*) FROM channel_members),
                        (SELECT COUNT(*) FROM items)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 2, 1));

        let violations: i64 = conn
            .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(violations, 0);

        // Foreign keys still enforced against the rebuilt table.
        let orphan = conn.execute(
            "INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length)
             VALUES ('ci_2', 'missing', X'AA', 'message', '2026-01-01', X'04', X'02', X'03', 1)",
            [],
        );
        assert!(
            orphan.is_err(),
            "items.channel_id FK must survive the rebuild"
        );

        // Named-channel uniqueness index was recreated.
        let dup = conn.execute(
            "INSERT INTO channels (channel_id, channel_name, channel_type, mode, access, creator_id, created_at, updated_at)
             VALUES ('named2', 'research', 'named', 'realtime', 'open', X'AA', '2026-01-01', '2026-01-01')",
            [],
        );
        assert!(dup.is_err(), "idx_channels_name must survive the rebuild");
    }

    // T3-1: verify all valid enum values are accepted
    #[test]
    fn test_valid_enum_values_accepted() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        for (i, ct) in ["named", "dm", "group"].iter().enumerate() {
            let id = format!("ch_{i}");
            conn.execute(
                &format!(
                    "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id, created_at, updated_at)
                     VALUES ('{id}', '{ct}', 'realtime', 'open', X'00', '2026-01-01', '2026-01-01')"
                ),
                [],
            ).unwrap_or_else(|e| panic!("channel_type '{ct}' should be valid: {e}"));
        }
    }

    /// A database at version 8, as the version before this step leaves
    /// it, with what a folder had agreed for two files.
    fn at_v8() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        for sql in [MIGRATION_V1, MIGRATION_V2, MIGRATION_V3] {
            conn.execute_batch(sql).unwrap();
        }
        migrate_v4(&conn).unwrap();
        for sql in [MIGRATION_V5, MIGRATION_V6, MIGRATION_V7, MIGRATION_V8] {
            conn.execute_batch(sql).unwrap();
        }
        conn.pragma_update(None, "user_version", 8).unwrap();
        conn.execute_batch(
            "INSERT INTO sync_files (folder, channel_id, key, hash, rev)
             VALUES ('/m', 'grp_a', 'notes.md', X'07', 2), ('/m', 'grp_a', 'gone.md', NULL, 5);",
        )
        .unwrap();
        conn
    }

    /// The step to version 9 adds a column, which cannot be done twice. The
    /// column and the version change together or not at all, so a start
    /// that fails between the two leaves a database that the next start
    /// takes from the beginning. The rows are kept, and say nothing of
    /// the writer.
    #[test]
    fn test_v9_adds_the_writer_and_its_version_as_one() {
        let conn = at_v8();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_writer = |conn: &Connection| conn.prepare("SELECT author FROM sync_files").is_ok();

        // The column is added, and then something fails before the version
        // is set.
        let failing = format!("{MIGRATION_V9} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 9).is_err());
        assert_eq!(version(&conn), 8);
        assert!(!has_writer(&conn), "the column goes with the version");

        // The next start runs the step from the beginning (and the steps
        // after it).
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        let rows: Vec<(String, i64, Option<Vec<u8>>)> = conn
            .prepare("SELECT key, rev, author FROM sync_files ORDER BY key")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            rows,
            [
                ("gone.md".to_string(), 5, None),
                ("notes.md".to_string(), 2, None)
            ]
        );

        // And a start after that changes nothing.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_writer(&conn));

        // Nor does the step itself, asked for again by a process that
        // read the version before another had run it.
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
    }

    /// The table of the memories a device deleted is made in one step
    /// with its version, as the step before it is: a failure between the
    /// two leaves neither, and the step asked for twice is run once.
    #[test]
    fn test_v10_adds_the_table_of_lines_and_its_version_as_one() {
        let conn = at_v8();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_table = |conn: &Connection| conn.prepare("SELECT file FROM index_lines").is_ok();
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();

        let failing = format!("{MIGRATION_V10} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 10).is_err());
        assert_eq!(version(&conn), 9);
        assert!(!has_table(&conn), "the table goes with the version");

        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_table(&conn));
        conn.execute(
            "INSERT INTO index_lines (folder, channel_id, file) VALUES ('/m', 'grp_a', 'a.md')",
            [],
        )
        .unwrap();
        // A start after that, and the step asked for again, change nothing.
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V10, 10).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM index_lines", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), rows), (SCHEMA_VERSION, 1));
    }

    /// A database at version 10, as the version before the entries of a
    /// channel from its secret leaves it: with a channel, entries of the
    /// old form in `items`, the counter of their arrival order, what a
    /// folder agreed, and a line.
    fn at_v10() -> Connection {
        let conn = at_v8();
        migrate_in_one(&conn, MIGRATION_V9, 9).unwrap();
        migrate_in_one(&conn, MIGRATION_V10, 10).unwrap();
        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES ('grp_a', 'group', 'realtime', 'invite_only', X'AA',
                     '2026-01-01', '2026-01-01');
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length,
                                seq, slot, rev)
             VALUES ('ci_1', 'grp_a', X'AA', 'memory', '2026-01-01', X'01', X'02', X'03', 1,
                     41, X'0505', 3),
                    ('ci_2', 'grp_a', X'BB', 'memory', '2026-01-02', X'04', X'05', X'0607', 2,
                     42, X'0505', 4);
             UPDATE counters SET value = 42 WHERE name = 'item_seq';
             INSERT INTO index_lines (folder, channel_id, file, line, line_at)
             VALUES ('/m', 'grp_a', 'gone.md', '- [Gone](gone.md)', 1800000000);",
        )
        .unwrap();
        conn
    }

    /// Everything a database holds but the new table and its index: each
    /// table's definition, and each row of the tables an older binary
    /// wrote. What a later step adds is left out too: the tables of what
    /// a device holds of its person, the table of the channels a relay
    /// holds, the index of each channel's own order of entries, the
    /// counts of what `items` holds with the triggers that keep them,
    /// what a device keeps of each relay, and the tables of messages. The
    /// definition of the table of what a folder agreed is left out, and
    /// read by itself ([`definition_of`]): a later step adds a column to
    /// it.
    fn held_before_v11(conn: &Connection) -> Vec<String> {
        let mut held: Vec<String> = conn
            .prepare(
                "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name NOT IN ('entries', 'idx_entries_channel_seq',
                                    'idx_entries_channel_place', 'sync_files')
                   AND name NOT LIKE 'sqlite_autoindex_entries%'
                   AND name NOT LIKE '%person%'
                   AND name NOT LIKE '%relay_channels%'
                   AND name NOT LIKE 'items_counted%'
                   AND name NOT LIKE '%at_relays%'
                   AND name NOT LIKE '%message%'
                 ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for rows in [
            "SELECT item_id || channel_id || hex(author_id) || item_type || published_at
                 || is_tombstone || hex(content_hash) || hex(signature) || hex(encrypted_blob)
                 || content_length || seq || hex(slot) || rev FROM items ORDER BY item_id",
            "SELECT channel_id || channel_type || scope || epoch FROM channels",
            "SELECT name || value FROM counters
                 WHERE name NOT IN ('entry_seq', 'item_count', 'item_bytes')",
            "SELECT folder || channel_id || key || COALESCE(hex(hash), '') || rev FROM sync_files
                 ORDER BY key",
            "SELECT folder || channel_id || file || line || line_at FROM index_lines",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// The table of entries is made in one step with its version and the
    /// counter of its order, as the steps before it are: a failure between
    /// them leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v11_adds_the_table_of_entries_and_its_version_as_one() {
        let conn = at_v10();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let has_table = |conn: &Connection| conn.prepare("SELECT rev FROM entries").is_ok();
        let counter = |conn: &Connection| -> Option<i64> {
            conn.query_row(
                "SELECT value FROM counters WHERE name = 'entry_seq'",
                [],
                |row| row.get(0),
            )
            .ok()
        };
        assert_eq!(version(&conn), 10);
        assert!(!has_table(&conn));

        let failing = format!("{MIGRATION_V11} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 11).is_err());
        assert_eq!(version(&conn), 10);
        assert!(!has_table(&conn), "the table goes with the version");
        assert_eq!(counter(&conn), None, "and so does its counter");

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert!(has_table(&conn));
        assert_eq!(counter(&conn), Some(0));

        // A start after that, and the step asked for again, change
        // nothing: the counter stays where storing has brought it.
        conn.execute("UPDATE counters SET value = 7 WHERE name = 'entry_seq'", [])
            .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        assert_eq!((version(&conn), counter(&conn)), (SCHEMA_VERSION, Some(7)));
    }

    /// A database at version 10 that an older binary wrote is taken to
    /// version 11 with everything it held as it was: the step adds a
    /// table, an index and a counter, and touches nothing else. Entries of
    /// the old form stay in `items`, and none is moved to the new table.
    #[test]
    fn test_a_database_at_v10_that_an_older_binary_wrote_is_taken_to_v11() {
        let conn = at_v10();
        let before = held_before_v11(&conn);
        assert!(before.iter().any(|row| row.starts_with("items: ")));
        assert!(before.iter().any(|row| row.starts_with("ci_2grp_a")));

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 10);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        assert_eq!(version(&conn), 11);
        assert_eq!(held_before_v11(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v11(&conn), before);

        // What is new: the table, with nothing in it, its index, and its
        // counter beside the old one.
        let new: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE name IN ('entries', 'idx_entries_channel_seq') ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(new, ["entries", "idx_entries_channel_seq"]);
        let (entries, entry_seq, item_seq): (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM entries),
                        (SELECT value FROM counters WHERE name = 'entry_seq'),
                        (SELECT value FROM counters WHERE name = 'item_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((entries, entry_seq, item_seq), (0, 0, 42));

        // The old table is written as before, by its own counter.
        conn.execute_batch(
            "UPDATE counters SET value = value + 1 WHERE name = 'item_seq';
             INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                content_hash, signature, encrypted_blob, content_length, seq)
             VALUES ('ci_3', 'grp_a', X'AA', 'memory', '2026-01-03', X'08', X'02', X'03', 1, 43);",
        )
        .unwrap();
        let (items, entry_seq): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM items),
                        (SELECT value FROM counters WHERE name = 'entry_seq')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((items, entry_seq), (3, 0));
    }

    /// A database at version 11, as the version before what a device
    /// holds of its person leaves it: what [`at_v10`] holds, and an entry
    /// in the new form with the counter of its order.
    fn at_v11() -> Connection {
        let conn = at_v10();
        migrate_in_one(&conn, MIGRATION_V11, 11).unwrap();
        conn.execute_batch(
            "UPDATE counters SET value = 9 WHERE name = 'entry_seq';
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (zeroblob(32), zeroblob(32), zeroblob(32), 7, 0, X'0A0B',
                     zeroblob(64), zeroblob(64), 9, 1800000000);",
        )
        .unwrap();
        conn
    }

    /// The tables and the index that the step to version 12 adds.
    const NEW_IN_V12: [&str; 6] = [
        "idx_person_secrets_applied",
        "person",
        "person_additions",
        "person_change_entries",
        "person_names",
        "person_secrets",
    ];

    /// Everything a database at version 11 holds: each table's definition
    /// but those of the step to version 12, and each row of every table an
    /// older binary wrote, the entries of the new form among them. The
    /// definition of the table of entries is left out, and read by itself
    /// ([`definition_of`]): a later step adds a column to it.
    fn held_before_v12(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v11(conn);
        for rows in [
            "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name = 'idx_entries_channel_seq'
                    OR name LIKE 'sqlite_autoindex_entries%' ORDER BY name",
            "SELECT hex(channel_id) || hex(slot) || hex(author) || rev || is_delete
                 || hex(content) || hex(author_sig) || hex(channel_sig) || seq || stored_at
                 FROM entries",
            "SELECT name || value FROM counters
                 WHERE name NOT IN ('item_count', 'item_bytes') ORDER BY name",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// How a table or an index is defined.
    fn definition_of(conn: &Connection, name: &str) -> String {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .unwrap()
    }

    /// What a database holds of the step to version 12, by name. Other
    /// tables of what a device holds of its person are of later steps.
    fn new_in_v12(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE name LIKE '%person%' AND name NOT LIKE '%person_hand_overs%'
               AND name NOT LIKE '%person_carried%'
               AND name NOT LIKE '%person_typed_keys%'
               AND name NOT LIKE '%person_left_out%'
               AND name NOT LIKE '%person_cleared%'
               AND name NOT LIKE '%person_names_before%'
               AND name NOT LIKE '%person_left%'
               AND name NOT LIKE '%message%'
               AND name NOT LIKE 'sqlite_autoindex%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// The tables of what a device holds of its person are made in one
    /// step with their version, as the steps before it are: a failure
    /// between them leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v12_adds_what_a_device_holds_of_its_person_and_its_version_as_one() {
        let conn = at_v11();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 11);
        assert!(new_in_v12(&conn).is_empty());

        let failing = format!("{MIGRATION_V12} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 12).is_err());
        assert_eq!(version(&conn), 11);
        assert!(
            new_in_v12(&conn).is_empty(),
            "the tables go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v12(&conn), NEW_IN_V12);

        // A start after that, and the step asked for again, change
        // nothing: what the device holds stays.
        conn.execute(
            "INSERT INTO person_names (name, channel, held_at) VALUES ('team', zeroblob(32), 7)",
            [],
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V12, 12).unwrap();
        let names: i64 = conn
            .query_row("SELECT COUNT(*) FROM person_names", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), names), (SCHEMA_VERSION, 1));
    }

    /// A database at version 11 that an older binary wrote is taken to
    /// version 12 with everything it held as it was: the step adds five
    /// tables and an index, with nothing in them, and touches nothing
    /// else. A device that takes this version follows no phrase.
    #[test]
    fn test_a_database_at_v11_that_an_older_binary_wrote_is_taken_to_v12() {
        let conn = at_v11();
        let before = held_before_v12(&conn);
        let entries_before = definition_of(&conn, "entries");
        assert!(
            before
                .iter()
                .any(|row| row.starts_with("idx_entries_channel_seq: "))
        );
        assert!(before.iter().any(|row| row.starts_with("entry_seq9")));
        assert!(before.iter().any(|row| row.starts_with("ci_2grp_a")));

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 11);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V12, 12).unwrap();
        assert_eq!(version(&conn), 12);
        assert_eq!(held_before_v12(&conn), before);
        assert_eq!(definition_of(&conn, "entries"), entries_before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v12(&conn), before);

        // What is new: the tables, with nothing in them, and the index.
        assert_eq!(new_in_v12(&conn), NEW_IN_V12);
        for table in NEW_IN_V12.iter().filter(|name| !name.starts_with("idx_")) {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }

        // The store of entries is written as before, by its own counter.
        conn.execute_batch(
            "UPDATE counters SET value = value + 1 WHERE name = 'entry_seq';
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (zeroblob(32), zeroblob(32),
                     X'0101010101010101010101010101010101010101010101010101010101010101',
                     8, 0, X'0C', zeroblob(64), zeroblob(64), 10, 1800000001);",
        )
        .unwrap();
        let entries: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries, 2);
    }

    /// A database at version 12, as the version before the channels a
    /// relay holds leaves it: what [`at_v11`] holds, and what a device
    /// holds of its person.
    fn at_v12() -> Connection {
        let conn = at_v11();
        migrate_in_one(&conn, MIGRATION_V12, 12).unwrap();
        conn.execute_batch(
            "INSERT INTO person (one, state, phrase_key, statement_key, phrase_channel, statement)
             VALUES (1, 'applied', zeroblob(32), zeroblob(32), zeroblob(32), X'0D0E');
             INSERT INTO person_secrets (number, secret, left_at) VALUES (3, zeroblob(32), NULL);
             INSERT INTO person_names (name, channel, held_at)
             VALUES ('team', zeroblob(32), 1800000000);
             INSERT INTO entries (channel_id, slot, author, rev, is_delete, content,
                                  author_sig, channel_sig, seq, stored_at)
             VALUES (zeroblob(32), zeroblob(32),
                     X'0202020202020202020202020202020202020202020202020202020202020202',
                     3, 0, X'0E', zeroblob(64), zeroblob(64), 4, 1800000000),
                    (X'0707070707070707070707070707070707070707070707070707070707070707',
                     zeroblob(32), zeroblob(32),
                     5, 1, X'0F', zeroblob(64), zeroblob(64), 2, 1800000000),
                    (X'0707070707070707070707070707070707070707070707070707070707070707',
                     zeroblob(32),
                     X'0202020202020202020202020202020202020202020202020202020202020202',
                     6, 0, X'10', zeroblob(64), zeroblob(64), 7, 1800000000);",
        )
        .unwrap();
        conn
    }

    /// The tables, the indexes and the triggers that the step to version
    /// 13 adds.
    const NEW_IN_V13: [&str; 8] = [
        "idx_entries_channel_place",
        "idx_relay_channels_held",
        "idx_relay_channels_used",
        "items_counted_again",
        "items_counted_in",
        "items_counted_out",
        "person_hand_overs",
        "relay_channels",
    ];

    /// The two counts of what `items` holds, or `None` where there are
    /// none: how many items, and the bytes of their content.
    fn item_counts(conn: &Connection) -> Option<(i64, i64)> {
        conn.query_row(
            "SELECT (SELECT value FROM counters WHERE name = 'item_count'),
                    (SELECT value FROM counters WHERE name = 'item_bytes')",
            [],
            |row| {
                Ok(row
                    .get::<_, Option<i64>>(0)?
                    .zip(row.get::<_, Option<i64>>(1)?))
            },
        )
        .unwrap()
    }

    /// What `items` holds, counted from its rows.
    fn items_as_they_are(conn: &Connection) -> (i64, i64) {
        conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(content_length), 0) FROM items",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
    }

    /// Each entry's channel by its first byte, its place in this node's
    /// order, and its place in its channel's own, or `None` where entries
    /// have no place of their channel's own.
    fn channel_places(conn: &Connection) -> Option<Vec<String>> {
        let mut stmt = conn
            .prepare(
                "SELECT hex(substr(channel_id, 1, 1)) || ' ' || seq || ' ' || channel_place
                 FROM entries ORDER BY channel_id, seq",
            )
            .ok()?;
        let rows = stmt.query_map([], |row| row.get(0)).unwrap();
        Some(rows.collect::<Result<_, _>>().unwrap())
    }

    /// Everything a database at version 12 holds: what one at version 11
    /// holds, each definition of the step to version 12, and each row of
    /// what a device holds of its person. Of the table of entries, every
    /// row as an older binary wrote it, and not its definition.
    fn held_before_v13(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v12(conn);
        for rows in [
            "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name LIKE '%person%' AND name NOT LIKE '%person_hand_overs%'
                   AND name NOT LIKE '%person_carried%'
                   AND name NOT LIKE '%person_typed_keys%'
                   AND name NOT LIKE '%person_left_out%'
                   AND name NOT LIKE '%person_cleared%'
                   AND name NOT LIKE '%person_names_before%'
                   AND name NOT LIKE '%person_left%'
                   AND name NOT LIKE '%message%'
                 ORDER BY name",
            "SELECT state || hex(phrase_key) || hex(statement_key) || hex(phrase_channel)
                 || hex(statement) FROM person",
            "SELECT number || hex(secret) || COALESCE(left_at, '') FROM person_secrets",
            "SELECT name || hex(channel) || held_at FROM person_names",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// What a database holds of the step to version 13, by name.
    fn new_in_v13(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE (name LIKE '%relay_channels%' OR name = 'idx_entries_channel_place'
                    OR name = 'person_hand_overs' OR name LIKE 'items_counted%')
               AND name NOT LIKE 'sqlite_autoindex%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// The table of the channels a relay holds, each entry's place in its
    /// channel's own order, the table of the hand-overs a device made,
    /// and the counts of what `items` holds, are made in one step with
    /// their version, as the steps before it are: a failure between them
    /// leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v13_adds_the_channels_a_relay_holds_and_its_version_as_one() {
        let conn = at_v12();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 12);
        assert!(new_in_v13(&conn).is_empty());
        assert_eq!(channel_places(&conn), None);
        assert_eq!(item_counts(&conn), None);
        let entries_before = definition_of(&conn, "entries");

        let failing = format!("{MIGRATION_V13} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 13).is_err());
        assert_eq!(version(&conn), 12);
        assert!(
            new_in_v13(&conn).is_empty(),
            "the table goes with the version"
        );
        assert_eq!(channel_places(&conn), None, "and so does the column");
        assert_eq!(item_counts(&conn), None, "and so do the counts");
        assert_eq!(definition_of(&conn, "entries"), entries_before);

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v13(&conn), NEW_IN_V13);
        assert_eq!(channel_places(&conn).map(|places| places.len()), Some(4));
        assert_eq!(item_counts(&conn), Some((2, 3)));

        // A start after that, and the step asked for again, change
        // nothing: what the relay holds stays, and the counts stay where
        // writing has brought them.
        conn.execute(
            "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes, mark)
             VALUES (zeroblob(32), 7, 8, 1280, X'0102030405060708')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM items WHERE item_id = 'ci_1'", [])
            .unwrap();
        assert_eq!(item_counts(&conn), Some((1, 2)));
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V13, 13).unwrap();
        let channels: i64 = conn
            .query_row("SELECT COUNT(*) FROM relay_channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), channels), (SCHEMA_VERSION, 1));
        assert_eq!(item_counts(&conn), Some((1, 2)));
    }

    /// A database at version 12 that an older binary wrote is taken to
    /// version 13 with everything it held as it was: the step adds two
    /// tables and two indexes, with nothing in them, and to each entry
    /// its place in its channel's own order, with an index. It counts the
    /// items that are there, and adds the triggers that keep the counts.
    /// It touches nothing else. The entries it held are in no channel
    /// that a relay holds, and the device has made no hand-over that it
    /// keeps anything of.
    #[test]
    fn test_a_database_at_v12_that_an_older_binary_wrote_is_taken_to_v13() {
        let conn = at_v12();
        let before = held_before_v13(&conn);
        let entries_before = definition_of(&conn, "entries");
        assert!(before.iter().any(|row| row.starts_with("person: ")));
        assert!(
            before
                .iter()
                .any(|row| row.starts_with("idx_entries_channel_seq: "))
        );
        assert!(before.iter().any(|row| row.starts_with("ci_2grp_a")));
        // Four entries, in two channels, as an older binary stored them.
        let entries: i64 = conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(entries, 4);

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 12);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V13, 13).unwrap();
        assert_eq!(version(&conn), 13);
        assert_eq!(held_before_v13(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v13(&conn), before);

        // What is new: the tables, with nothing in them, and the indexes.
        assert_eq!(new_in_v13(&conn), NEW_IN_V13);
        for table in ["relay_channels", "person_hand_overs"] {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }

        // And each entry's place in its channel's own order: the entries
        // of each channel are counted from 1, in the order in which this
        // node stored them, whatever it stored in other channels between.
        assert_eq!(
            channel_places(&conn).unwrap(),
            ["00 4 1", "00 9 2", "07 2 1", "07 7 2"]
        );
        // The table of entries has that one column more, and is as it
        // was otherwise.
        let entries_after = definition_of(&conn, "entries");
        assert!(!entries_before.contains("channel_place"));
        assert_eq!(
            entries_after.replace(", channel_place INTEGER NOT NULL DEFAULT 0", ""),
            entries_before
        );
        // No two entries of a channel have one place in it.
        assert!(
            conn.execute("UPDATE entries SET channel_place = 1", [])
                .is_err()
        );

        // And the items that an older binary wrote are counted: two of
        // them, of one byte and of two.
        assert_eq!(items_as_they_are(&conn), (2, 3));
        assert_eq!(item_counts(&conn), Some((2, 3)));
    }

    // ── v14: what a device keeps of each relay ───────────────────────

    /// A database at version 13, as the version before what a device
    /// keeps of each relay leaves it: what [`at_v12`] holds, a channel
    /// that a relay holds, and what a device keeps of a hand-over.
    fn at_v13() -> Connection {
        let conn = at_v12();
        migrate_in_one(&conn, MIGRATION_V13, 13).unwrap();
        conn.execute_batch(
            "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes, mark)
             VALUES (X'0707070707070707070707070707070707070707070707070707070707070707',
                     7, 8, 2560, X'0102030405060708');
             INSERT INTO person_hand_overs (key, channel, rev, made_at, held)
             VALUES (zeroblob(32), zeroblob(32), 1800000000, 1800000000, 0);",
        )
        .unwrap();
        conn
    }

    /// The tables and the index that the step to version 14 adds.
    const NEW_IN_V14: [&str; 3] = ["at_relays", "idx_at_relays_channel", "person_carried"];

    /// What a database holds of the step to version 14, by name.
    fn new_in_v14(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE (name LIKE '%at_relays%' OR name = 'person_carried')
               AND name NOT LIKE '%at_relays_refused%'
               AND name NOT LIKE 'sqlite_autoindex%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Everything a database at version 13 holds: what one at version 12
    /// holds, each definition of the step to version 13, the table of
    /// entries as that step left it, each entry's place in its channel,
    /// and each row of the two tables of that step.
    fn held_before_v14(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v13(conn);
        for rows in [
            "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE name LIKE '%relay_channels%' OR name = 'idx_entries_channel_place'
                    OR name = 'person_hand_overs' OR name LIKE 'items_counted%'
                    OR name = 'entries'
                 ORDER BY name",
            "SELECT hex(channel_id) || seq || ' ' || channel_place FROM entries ORDER BY seq",
            "SELECT hex(channel_id) || held_since || used_at || bytes || hex(mark)
                 FROM relay_channels",
            "SELECT hex(key) || hex(channel) || rev || made_at || held FROM person_hand_overs",
            "SELECT name || value FROM counters WHERE name IN ('item_count', 'item_bytes')
                 ORDER BY name",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// The two tables of what a device keeps of each relay are made in
    /// one step with their version, as the steps before it are: a failure
    /// between them leaves none, and the step asked for twice is run
    /// once.
    #[test]
    fn test_v14_adds_what_a_device_keeps_of_each_relay_and_its_version_as_one() {
        let conn = at_v13();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 13);
        assert!(new_in_v14(&conn).is_empty());

        let failing = format!("{MIGRATION_V14} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 14).is_err());
        assert_eq!(version(&conn), 13);
        assert!(
            new_in_v14(&conn).is_empty(),
            "the tables go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v14(&conn), NEW_IN_V14);

        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        conn.execute_batch(
            "INSERT INTO at_relays (relay, channel, mark, place, sent_to, carried_to)
             VALUES (zeroblob(32), zeroblob(32), X'0102030405060708', 7, 9, 3);
             INSERT INTO person_carried (one, up_to) VALUES (1, 9);",
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V14, 14).unwrap();
        let kept: (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM at_relays), (SELECT up_to FROM person_carried)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((version(&conn), kept), (SCHEMA_VERSION, (1, 9)));
    }

    /// A database at version 13 that an older binary wrote is taken to
    /// version 14 with everything it held as it was: the step adds two
    /// tables and an index, with nothing in them, and touches nothing
    /// else. A device has no place at any relay, has sent none anything,
    /// and has carried nothing.
    #[test]
    fn test_a_database_at_v13_that_an_older_binary_wrote_is_taken_to_v14() {
        let conn = at_v13();
        let before = held_before_v14(&conn);
        assert!(before.iter().any(|row| row.starts_with("relay_channels: ")));
        assert!(before.iter().any(|row| row.starts_with("entries: ")));
        assert!(before.iter().any(|row| row.starts_with("item_count2")));

        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 13);

        // The step by itself, and then a start, which has no more to do
        // for it.
        migrate_in_one(&conn, MIGRATION_V14, 14).unwrap();
        assert_eq!(version(&conn), 14);
        assert_eq!(held_before_v14(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v14(&conn), before);

        // What is new: the tables, with nothing in them, and the index.
        assert_eq!(new_in_v14(&conn), NEW_IN_V14);
        for table in ["at_relays", "person_carried"] {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
        // The index is by channel, for what is forgotten of a channel at
        // every relay.
        assert!(definition_of(&conn, "idx_at_relays_channel").contains("at_relays(channel)"));
    }

    // ── v15: what a person typed, cleared and is to be told ──────────

    /// A database at version 14, as the version before the commands a
    /// person types leaves it: what [`at_v13`] holds, and what a device
    /// keeps of a relay.
    fn at_v14() -> Connection {
        let conn = at_v13();
        migrate_in_one(&conn, MIGRATION_V14, 14).unwrap();
        conn.execute_batch(
            "INSERT INTO at_relays (relay, channel, mark, place, sent_to, carried_to)
             VALUES (zeroblob(32), zeroblob(32), X'0102030405060708', 7, 9, 3);
             INSERT INTO person_carried (one, up_to) VALUES (1, 9);",
        )
        .unwrap();
        conn
    }

    /// The tables that the step to version 15 adds.
    const NEW_IN_V15: [&str; 3] = ["person_cleared", "person_left_out", "person_typed_keys"];

    /// What a database holds of the step to version 15, by name.
    fn new_in_v15(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE name IN ('person_cleared', 'person_left_out', 'person_typed_keys')
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Everything a database at version 14 holds: what one at version 13
    /// holds, each definition of the step to version 14, and each row of
    /// its two tables.
    fn held_before_v15(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v14(conn);
        for rows in [
            "SELECT name || ': ' || COALESCE(sql, '') FROM sqlite_master
                 WHERE (name LIKE '%at_relays%' AND name NOT LIKE '%at_relays_refused%')
                    OR name = 'person_carried'
                 ORDER BY name",
            "SELECT hex(relay) || hex(channel) || hex(mark) || place || sent_to || carried_to
                 FROM at_relays",
            "SELECT one || ' ' || up_to FROM person_carried",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// The three tables of what a person typed, cleared and is to be told
    /// are made in one step with their version: a failure between them
    /// leaves none, and the step asked for twice is run once.
    #[test]
    fn test_v15_adds_what_a_person_typed_and_is_told_and_its_version_as_one() {
        let conn = at_v14();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 14);
        assert!(new_in_v15(&conn).is_empty());

        let failing = format!("{MIGRATION_V15} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 15).is_err());
        assert_eq!(version(&conn), 14);
        assert!(
            new_in_v15(&conn).is_empty(),
            "the tables go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v15(&conn), NEW_IN_V15);

        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        conn.execute_batch(
            "INSERT INTO person_typed_keys (key, typed_at) VALUES (zeroblob(32), 7);
             INSERT INTO person_left_out (key, label, number, noted_at)
             VALUES (zeroblob(32), 'laptop', 2, 8);
             INSERT INTO person_cleared (notice, cleared_at) VALUES (zeroblob(32), 9);",
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V15, 15).unwrap();
        let kept: (i64, i64, i64) = conn
            .query_row(
                "SELECT (SELECT typed_at FROM person_typed_keys),
                        (SELECT number FROM person_left_out),
                        (SELECT cleared_at FROM person_cleared)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((version(&conn), kept), (SCHEMA_VERSION, (7, 2, 9)));
    }

    /// A database at version 14 that an older binary wrote is taken to
    /// version 15 with everything it held as it was: the step adds three
    /// tables, with nothing in them, and touches nothing else.
    #[test]
    fn test_a_database_at_v14_that_an_older_binary_wrote_is_taken_to_v15() {
        let conn = at_v14();
        let before = held_before_v15(&conn);
        assert!(before.iter().any(|row| row.starts_with("at_relays: ")));
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 14);

        migrate_in_one(&conn, MIGRATION_V15, 15).unwrap();
        assert_eq!(version(&conn), 15);
        assert_eq!(held_before_v15(&conn), before);
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(held_before_v15(&conn), before);

        assert_eq!(new_in_v15(&conn), NEW_IN_V15);
        for table in NEW_IN_V15 {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
        // A row that is not what a device keeps is refused: a key or a
        // notice of another length, and a statement numbered 0.
        for refused in [
            "INSERT INTO person_typed_keys (key, typed_at) VALUES (zeroblob(31), 1)",
            "INSERT INTO person_left_out (key, label, number, noted_at)
                 VALUES (zeroblob(33), 'laptop', 1, 1)",
            "INSERT INTO person_left_out (key, label, number, noted_at)
                 VALUES (zeroblob(32), 'laptop', 0, 1)",
            "INSERT INTO person_cleared (notice, cleared_at) VALUES (zeroblob(16), 1)",
        ] {
            assert!(conn.execute(refused, []).is_err(), "{refused}");
        }
    }

    // ── v16: what a relay refused for room ───────────────────────────

    /// A database at version 15, as the version before what a relay
    /// refused is kept leaves it: what [`at_v14`] holds, and a key that a
    /// person typed.
    fn at_v15() -> Connection {
        let conn = at_v14();
        migrate_in_one(&conn, MIGRATION_V15, 15).unwrap();
        conn.execute_batch(
            "INSERT INTO person_typed_keys (key, typed_at) VALUES (zeroblob(32), 7);",
        )
        .unwrap();
        conn
    }

    /// The table and the index that the step to version 16 adds.
    const NEW_IN_V16: [&str; 2] = ["at_relays_refused", "idx_at_relays_refused_channel"];

    /// What a database holds of the step to version 16, by name.
    fn new_in_v16(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE name LIKE '%at_relays_refused%' AND name NOT LIKE 'sqlite_autoindex%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Everything a database at version 15 holds: what one at version 14
    /// holds, each definition of the step to version 15, and each row of
    /// its tables.
    fn held_before_v16(conn: &Connection) -> Vec<String> {
        let mut held = held_before_v15(conn);
        // Two of the tables have a column more from the step to version
        // 18: each definition is read without it.
        for rows in [
            "SELECT name || ': ' || replace(replace(COALESCE(sql, ''),
                        ', stood TEXT NOT NULL DEFAULT ''''', ''), ', cleared_at INTEGER', '')
                 FROM sqlite_master
                 WHERE name IN ('person_cleared', 'person_left_out', 'person_typed_keys')
                 ORDER BY name",
            "SELECT hex(key) || typed_at FROM person_typed_keys",
        ] {
            let rows: Vec<String> = conn
                .prepare(rows)
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(!rows.is_empty());
            held.extend(rows);
        }
        held
    }

    /// The table of what a relay refused for room is made in one step
    /// with its version: a failure between them leaves neither, and the
    /// step asked for twice is run once. A database that an older binary
    /// wrote is taken to version 16 with everything it held as it was.
    #[test]
    fn test_v16_adds_what_a_relay_refused_for_room_and_its_version_as_one() {
        let conn = at_v15();
        let before = held_before_v16(&conn);
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        assert_eq!(version(&conn), 15);
        assert!(new_in_v16(&conn).is_empty());

        let failing = format!("{MIGRATION_V16} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 16).is_err());
        assert_eq!(version(&conn), 15);
        assert!(
            new_in_v16(&conn).is_empty(),
            "the table goes with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v16(&conn), NEW_IN_V16);
        assert_eq!(held_before_v16(&conn), before);
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM at_relays_refused", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);

        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        conn.execute_batch(
            "INSERT INTO at_relays_refused (relay, channel, seq)
             VALUES (zeroblob(32), zeroblob(32), 7);",
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V16, 16).unwrap();
        let kept: i64 = conn
            .query_row("SELECT seq FROM at_relays_refused", [], |row| row.get(0))
            .unwrap();
        assert_eq!((version(&conn), kept), (SCHEMA_VERSION, 7));
        // A row that is not what a device keeps is refused: a relay or a
        // channel of another length, a place that is none, and the same
        // entry twice.
        for refused in [
            "INSERT INTO at_relays_refused (relay, channel, seq)
                 VALUES (zeroblob(31), zeroblob(32), 1)",
            "INSERT INTO at_relays_refused (relay, channel, seq)
                 VALUES (zeroblob(32), zeroblob(33), 1)",
            "INSERT INTO at_relays_refused (relay, channel, seq)
                 VALUES (zeroblob(32), zeroblob(32), 0)",
            "INSERT INTO at_relays_refused (relay, channel, seq)
                 VALUES (zeroblob(32), zeroblob(32), 7)",
        ] {
            assert!(conn.execute(refused, []).is_err(), "{refused}");
        }
        assert!(
            definition_of(&conn, "idx_at_relays_refused_channel")
                .contains("at_relays_refused(channel)")
        );
    }

    /// A database as a binary from before the chain of what a folder
    /// agreed was kept leaves it: what [`at_v15`] holds, an entry that a
    /// relay refused, and a row of what a folder agreed.
    fn at_v16() -> Connection {
        let conn = at_v15();
        migrate_in_one(&conn, MIGRATION_V16, 16).unwrap();
        conn.execute_batch(
            "INSERT INTO at_relays_refused (relay, channel, seq)
             VALUES (zeroblob(32), zeroblob(32), 7);
             INSERT INTO sync_files (folder, channel_id, key, hash, rev, author)
             VALUES ('/memory', 'grp_before', 'notes.md', X'0A', 3, zeroblob(32));",
        )
        .unwrap();
        conn
    }

    /// What the step to version 17 adds: a column, and a table.
    const NEW_IN_V17: [&str; 2] = ["person_names_before", "sync_files.chain"];

    /// What a database holds of the step to version 17, by name.
    fn new_in_v17(conn: &Connection) -> Vec<String> {
        let mut held: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE name = 'person_names_before'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        if conn.prepare("SELECT chain FROM sync_files").is_ok() {
            held.push("sync_files.chain".into());
        }
        held
    }

    /// The chain of what a folder agreed, and the table of the names
    /// that were listed before a statement, are made in one step with
    /// their version: a failure between them leaves neither, and the step
    /// asked for twice is run once. A row that a folder agreed before
    /// stays as it was, with no chain.
    #[test]
    fn test_v17_adds_the_chain_a_folder_agreed_and_the_names_before_as_one() {
        let conn = at_v16();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let before = held_before_v16(&conn);
        let agreed_before = definition_of(&conn, "sync_files");
        assert_eq!(version(&conn), 16);
        assert!(new_in_v17(&conn).is_empty());

        let failing = format!("{MIGRATION_V17} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 17).is_err());
        assert_eq!(version(&conn), 16);
        assert!(
            new_in_v17(&conn).is_empty(),
            "the column and the table go with the version"
        );
        assert_eq!(definition_of(&conn, "sync_files"), agreed_before);

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v17(&conn), NEW_IN_V17);
        assert_eq!(held_before_v16(&conn), before);
        // The table of what a folder agreed has one column more, and is
        // otherwise as it was.
        let agreed_after = definition_of(&conn, "sync_files");
        assert_eq!(
            agreed_after.replace(", chain BLOB", ""),
            agreed_before,
            "{agreed_after}"
        );
        assert_ne!(agreed_after, agreed_before);
        let row: (i64, Option<Vec<u8>>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT rev, author, chain FROM sync_files WHERE folder = '/memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (3, Some(vec![0u8; 32]), None));

        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        conn.execute_batch(
            "UPDATE sync_files SET chain = zeroblob(64);
             INSERT INTO person_names_before (name, said_by, left_at)
             VALUES ('notes', zeroblob(32), 9);",
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V17, 17).unwrap();
        let kept: (i64, i64) = conn
            .query_row(
                "SELECT (SELECT length(chain) FROM sync_files),
                        (SELECT COUNT(*) FROM person_names_before)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((version(&conn), kept), (SCHEMA_VERSION, (64, 1)));
        // A row that names no name, or a key of another length, is
        // refused, and so is one name said twice by one key.
        for refused in [
            "INSERT INTO person_names_before (name, said_by, left_at) VALUES ('', zeroblob(32), 9)",
            "INSERT INTO person_names_before (name, said_by, left_at)
                 VALUES ('notes', zeroblob(31), 9)",
            "INSERT INTO person_names_before (name, said_by, left_at)
                 VALUES ('notes', zeroblob(32), 9)",
            "INSERT INTO person_names_before (name, said_by) VALUES ('other', zeroblob(32))",
        ] {
            assert!(conn.execute(refused, []).is_err(), "{refused}");
        }
    }

    /// A database as a binary from before the row of a typed key was kept
    /// leaves it: what [`at_v16`] holds, a name that was listed before,
    /// and a key that a statement left out.
    fn at_v17() -> Connection {
        let conn = at_v16();
        migrate_in_one(&conn, MIGRATION_V17, 17).unwrap();
        conn.execute_batch(
            "INSERT INTO person_names_before (name, said_by, left_at)
             VALUES ('notes', zeroblob(32), 9);
             INSERT INTO person_left_out (key, label, number, noted_at)
             VALUES (zeroblob(32), 'laptop', 2, 9);",
        )
        .unwrap();
        conn
    }

    /// What the step to version 18 adds: two columns, and a table.
    const NEW_IN_V18: [&str; 3] = [
        "person_left",
        "person_left_out.cleared_at",
        "person_typed_keys.stood",
    ];

    /// What a database holds of the step to version 18, by name.
    fn new_in_v18(conn: &Connection) -> Vec<String> {
        let mut held: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE name = 'person_left'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        if conn
            .prepare("SELECT cleared_at FROM person_left_out")
            .is_ok()
        {
            held.push("person_left_out.cleared_at".into());
        }
        if conn.prepare("SELECT stood FROM person_typed_keys").is_ok() {
            held.push("person_typed_keys.stood".into());
        }
        held
    }

    /// The row that a key was typed in, the time a key that was left out
    /// was cleared, and the table of the words that outlive a change are
    /// made in one step with their version: a failure between them leaves
    /// none, and the step asked for twice is run once. A key that was
    /// typed before stands in no row, and a key that was left out before
    /// is still shown.
    #[test]
    fn test_v18_adds_the_row_of_a_typed_key_and_the_words_that_outlive_a_change_as_one() {
        let conn = at_v17();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let before = held_before_v16(&conn);
        assert_eq!(version(&conn), 17);
        assert!(new_in_v18(&conn).is_empty());

        let failing = format!("{MIGRATION_V18} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 18).is_err());
        assert_eq!(version(&conn), 17);
        assert!(
            new_in_v18(&conn).is_empty(),
            "the columns and the table go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v18(&conn), NEW_IN_V18);
        // Everything it held is as it was, but for the two columns.
        assert_eq!(held_before_v16(&conn), before);
        assert_eq!(new_in_v17(&conn), NEW_IN_V17);
        let typed: (i64, String) = conn
            .query_row("SELECT typed_at, stood FROM person_typed_keys", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(typed, (7, String::new()));
        let left_out: (String, Option<i64>) = conn
            .query_row("SELECT label, cleared_at FROM person_left_out", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(left_out, ("laptop".to_string(), None));

        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        conn.execute_batch(
            "UPDATE person_typed_keys SET stood = 'alone';
             UPDATE person_left_out SET cleared_at = 11;
             INSERT INTO person_left (key, notice, number, noted_at)
             VALUES (zeroblob(32), zeroblob(32), 2, 9);",
        )
        .unwrap();
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V18, 18).unwrap();
        let kept: (String, i64, i64) = conn
            .query_row(
                "SELECT (SELECT stood FROM person_typed_keys),
                        (SELECT cleared_at FROM person_left_out),
                        (SELECT COUNT(*) FROM person_left)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (version(&conn), kept),
            (SCHEMA_VERSION, ("alone".to_string(), 11, 1))
        );
        // A word of a key of another length, a notice that is named by
        // other than 32 bytes, a statement numbered below 1, a second
        // word of one key, and a word with no time are refused.
        for refused in [
            "INSERT INTO person_left (key, notice, number, noted_at)
                 VALUES (zeroblob(31), zeroblob(32), 2, 9)",
            "INSERT INTO person_left (key, notice, number, noted_at)
                 VALUES (X'01' || zeroblob(31), zeroblob(31), 2, 9)",
            "INSERT INTO person_left (key, notice, number, noted_at)
                 VALUES (X'01' || zeroblob(31), zeroblob(32), 0, 9)",
            "INSERT INTO person_left (key, notice, number, noted_at)
                 VALUES (zeroblob(32), zeroblob(32), 3, 9)",
            "INSERT INTO person_left (key, notice, number)
                 VALUES (X'01' || zeroblob(31), zeroblob(32), 2)",
        ] {
            assert!(conn.execute(refused, []).is_err(), "{refused}");
        }
    }

    /// A database as a binary from before messages leaves it: what
    /// [`at_v17`] holds, where a key was typed, and a word that outlived
    /// a change.
    fn at_v18() -> Connection {
        let conn = at_v17();
        migrate_in_one(&conn, MIGRATION_V18, 18).unwrap();
        conn.execute_batch(
            "UPDATE person_typed_keys SET stood = 'alone';
             INSERT INTO person_left (key, notice, number, noted_at)
             VALUES (zeroblob(32), zeroblob(32), 2, 9);",
        )
        .unwrap();
        conn
    }

    /// What the step to version 19 adds: fourteen tables, and six
    /// indexes.
    const NEW_IN_V19: [&str; 20] = [
        "idx_message_index_signer",
        "idx_message_lists_mark",
        "idx_message_numbers_id",
        "idx_message_places",
        "idx_message_read_here_id",
        "idx_message_sends_at",
        "message_announced",
        "message_first_held",
        "message_generations",
        "message_index",
        "message_kept",
        "message_kept_numbers",
        "message_kept_taken",
        "message_lists",
        "message_numbers",
        "message_places",
        "message_read_by_a_person",
        "message_read_here",
        "message_sends",
        "message_signers",
    ];

    /// What a database holds of the step to version 19, by name.
    fn new_in_v19(conn: &Connection) -> Vec<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE name LIKE '%message%' AND name NOT LIKE 'sqlite_autoindex%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }

    /// Everything a database holds: each definition, and each row of
    /// each table, in the order of their names, but what the step to
    /// version 19 adds.
    fn everything_but_v19(conn: &Connection) -> Vec<String> {
        let names: Vec<(String, String, Option<String>)> = conn
            .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY name")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let mut held = Vec::new();
        for (kind, name, sql) in names {
            if NEW_IN_V19.contains(&name.as_str()) || name.contains("message") {
                continue;
            }
            held.push(format!("{name}: {}", sql.unwrap_or_default()));
            if kind != "table" {
                continue;
            }
            let mut rows = conn.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
            let columns = rows.column_count();
            let mut found = rows.query([]).unwrap();
            while let Some(row) = found.next().unwrap() {
                let values: Vec<String> = (0..columns)
                    .map(|i| format!("{:?}", row.get::<_, rusqlite::types::Value>(i).unwrap()))
                    .collect();
                held.push(format!("{name}: {}", values.join(", ")));
            }
        }
        held
    }

    /// The step to version 19 adds the tables of messages, empty, and
    /// changes no older row or definition (decision 2026-10-09 §9.2): it
    /// is made in one step with its version, so a failure between them
    /// leaves none of it, and the step asked for twice is run once. What
    /// the tables keep stays across a start, and each takes no row that
    /// cannot be what a device keeps.
    #[test]
    fn step_19_adds_its_tables_and_changes_no_older_row() {
        let conn = at_v18();
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let before = everything_but_v19(&conn);
        assert!(before.len() > 40, "{before:?}");
        assert_eq!(version(&conn), 18);
        assert!(new_in_v19(&conn).is_empty());

        let failing = format!("{MIGRATION_V19} SELECT no_such_function();");
        assert!(migrate_in_one(&conn, &failing, 19).is_err());
        assert_eq!(version(&conn), 18);
        assert!(
            new_in_v19(&conn).is_empty(),
            "the tables go with the version"
        );

        // The next start runs the step from the beginning.
        init_db(&conn).unwrap();
        assert_eq!(version(&conn), 19);
        assert_eq!(version(&conn), SCHEMA_VERSION);
        assert_eq!(new_in_v19(&conn), NEW_IN_V19);
        assert_eq!(everything_but_v19(&conn), before);
        for table in NEW_IN_V19.iter().filter(|name| !name.starts_with("idx_")) {
            let rows: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
        for (index, on) in [
            (
                "idx_message_index_signer",
                "message_index(signer, generation)",
            ),
            ("idx_message_lists_mark", "message_lists(mark)"),
            ("idx_message_numbers_id", "message_numbers(id)"),
            (
                "idx_message_places",
                "message_places(signer, generation, placed_at)",
            ),
            ("idx_message_read_here_id", "message_read_here(id)"),
            ("idx_message_sends_at", "message_sends(sent_at)"),
        ] {
            assert!(definition_of(&conn, index).contains(on), "{index}");
        }

        // What the device keeps, one row of each table.
        let id = "X'01010101010101010101010101010101'";
        let kept_rows = format!(
            "INSERT INTO message_generations (id, channel, statement, first_held)
                 VALUES (1, zeroblob(32), 1, 8), (2, X'{second}', 1, 9);
             INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
                 VALUES ({id}, zeroblob(32), 'laptop', 1, 1, 'notes', '~', 9, 'a', zeroblob(16),
                         zeroblob(16), 0, NULL, 'a', 9, NULL),
                        (X'02020202020202020202020202020202', zeroblob(32), 'laptop', 1, 2, NULL,
                         '~', 9, 'b', zeroblob(16), zeroblob(16), 1, 'owner/repo#1', 'b', 9, 10);
             INSERT INTO message_numbers (signer, generation, number, id)
                 VALUES (zeroblob(32), 1, 1, {id});
             INSERT INTO message_first_held (signer, generation, number, id, sent, first_held)
                 VALUES (zeroblob(32), 1, 1, {id}, 9, 9);
             INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 1, 1);
             INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10), (zeroblob(32), 1, 10);
             INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), zeroblob(16));
             INSERT INTO message_read_here (mark, seq, id, name, made_at)
                 VALUES (zeroblob(16), 2, {id}, 'notes', 11);
             INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (X'09090909090909090909090909090909', 1, 8, 12);
             INSERT INTO message_announced (id, name) VALUES ({id}, 'notes');
             INSERT INTO message_read_by_a_person (id) VALUES ({id});
             INSERT INTO message_sends (sent_at, name, to_all)
                 VALUES (9, 'notes', 0), (9, 'notes', 1), (10, NULL, 0);
             INSERT INTO message_kept (id, generation, value, sent, kept_at)
                 VALUES ({id}, 1, zeroblob(1936), 9, 9);
             INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 1), ({id}, 65);
             INSERT INTO message_kept_taken (id, relay) VALUES ({id}, zeroblob(32));
             UPDATE message_index SET not_every_relay = 1
                 WHERE id = X'02020202020202020202020202020202';",
            second = "02".repeat(32),
        );
        conn.execute_batch(&kept_rows).unwrap();
        let counted = |conn: &Connection| -> Vec<i64> {
            NEW_IN_V19
                .iter()
                .filter(|name| !name.starts_with("idx_"))
                .map(|table| {
                    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                    .unwrap()
                })
                .collect()
        };
        let kept = counted(&conn);
        assert_eq!(kept, [1, 1, 2, 2, 1, 2, 1, 1, 1, 2, 1, 2, 3, 1]);
        // A message's kept value was not dropped before every relay took
        // it, but where that is said; and H is counted from no number
        // until one is held.
        let flags: Vec<i64> = conn
            .prepare("SELECT not_every_relay FROM message_index ORDER BY id")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(flags, [0, 1]);
        conn.execute(
            "INSERT INTO message_signers (signer, generation, highest) VALUES (zeroblob(32), 2, 0)",
            [],
        )
        .unwrap();
        let counted_from: Option<i64> = conn
            .query_row(
                "SELECT counted_from FROM message_signers WHERE generation = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(counted_from, None);
        conn.execute("DELETE FROM message_signers WHERE generation = 2", [])
            .unwrap();
        // A start after that, and the step asked for again, change
        // nothing: what the device keeps stays.
        init_db(&conn).unwrap();
        migrate_in_one(&conn, MIGRATION_V19, 19).unwrap();
        assert_eq!(
            (version(&conn), counted(&conn)),
            (SCHEMA_VERSION, kept.clone())
        );
        assert_eq!(everything_but_v19(&conn), before);

        // A row that cannot be what a device keeps is refused.
        let one = |table: &str, columns: &str, values: &str| {
            format!("INSERT INTO {table} ({columns}) VALUES ({values})")
        };
        let index = |values: &str| {
            one(
                "message_index",
                "id, signer, label, generation, to_kind, to_name, from_name, sent, subject,
                 thread, answers, asks, link, body, first_held, placed_at",
                values,
            )
        };
        let other = "X'03030303030303030303030303030303'";
        let index_row = |change: (usize, &str)| {
            let mut values = [
                other,
                "zeroblob(32)",
                "'laptop'",
                "1",
                "1",
                "'notes'",
                "'~'",
                "9",
                "'a'",
                "zeroblob(16)",
                "zeroblob(16)",
                "0",
                "NULL",
                "'a'",
                "9",
                "NULL",
            ];
            values[change.0] = change.1;
            index(&values.join(", "))
        };
        assert_eq!(conn.execute(&index_row((0, other)), []), Ok(1));
        conn.execute("DELETE FROM message_index WHERE id = ?1", [&[3u8; 16][..]])
            .unwrap();
        let mut refused: Vec<String> = [
            // An ID, a signer, a thread or an answer of another length.
            (0, "zeroblob(15)"),
            (0, id),
            (1, "zeroblob(31)"),
            (9, "zeroblob(17)"),
            (10, "zeroblob(15)"),
            // No generation, a kind of `to` that is neither, a name for
            // every name, no name for one, and a flag that is neither.
            (3, "0"),
            (4, "3"),
            (4, "2"),
            (5, "NULL"),
            (11, "2"),
            // A field that a message always has, missing.
            (2, "NULL"),
            (6, "NULL"),
            (7, "NULL"),
            (8, "NULL"),
            (13, "NULL"),
            (14, "NULL"),
        ]
        .into_iter()
        .map(index_row)
        .collect();
        // A kind of `to` that is neither, with no name, as for every name.
        refused.push(index_row((4, "3")).replace("3, 'notes'", "3, NULL"));
        refused.extend([
            one(
                "message_numbers",
                "signer, generation, number, id",
                &format!("zeroblob(31), 1, 2, {id}"),
            ),
            one(
                "message_numbers",
                "signer, generation, number, id",
                &format!("zeroblob(32), 0, 2, {id}"),
            ),
            one(
                "message_numbers",
                "signer, generation, number, id",
                &format!("zeroblob(32), 1, 0, {id}"),
            ),
            one(
                "message_numbers",
                "signer, generation, number, id",
                &format!("zeroblob(32), 1, 1, {id}"),
            ),
            one(
                "message_numbers",
                "signer, generation, number, id",
                &format!("zeroblob(32), 1, 2, {other}"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                &format!("zeroblob(33), 1, 2, {id}, 9, 9"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                &format!("zeroblob(32), 0, 2, {id}, 9, 9"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                &format!("zeroblob(32), 1, 0, {id}, 9, 9"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                "zeroblob(32), 1, 2, zeroblob(17), 9, 9",
            ),
            // A row of first holding has an ID and a `sent`, or neither,
            // where its number was first held as a clearing.
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                "zeroblob(32), 1, 2, NULL, 9, 9",
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                &format!("zeroblob(32), 1, 2, {id}, NULL, 9"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent, first_held",
                &format!("zeroblob(32), 1, 1, {id}, 9, 9"),
            ),
            one(
                "message_first_held",
                "signer, generation, number, id, sent",
                &format!("zeroblob(32), 1, 2, {id}, 9"),
            ),
            one(
                "message_signers",
                "signer, generation, highest",
                "zeroblob(31), 1, 1",
            ),
            one(
                "message_signers",
                "signer, generation, highest",
                "zeroblob(32), 0, 1",
            ),
            one(
                "message_signers",
                "signer, generation, highest",
                "zeroblob(32), 2, -1",
            ),
            one(
                "message_signers",
                "signer, generation, highest, overwritten",
                "zeroblob(32), 2, 1, -1",
            ),
            one(
                "message_signers",
                "signer, generation, highest, not_messages",
                "zeroblob(32), 2, 1, -1",
            ),
            one(
                "message_signers",
                "signer, generation, highest",
                "zeroblob(32), 1, 2",
            ),
            one(
                "message_places",
                "signer, generation, placed_at",
                "zeroblob(31), 1, 10",
            ),
            one(
                "message_places",
                "signer, generation, placed_at",
                "zeroblob(32), 0, 10",
            ),
            one("message_places", "signer, generation", "zeroblob(32), 1"),
            one("message_lists", "key, mark", "zeroblob(31), zeroblob(16)"),
            one("message_lists", "key, mark", "zeroblob(32), zeroblob(17)"),
            one("message_lists", "key, mark", "zeroblob(32), zeroblob(16)"),
            // A mark of another length, a mark held twice, an ID with no
            // name or a name with no ID, an empty name, a mark with
            // neither and never merged, no time, an ID of no message, and
            // no place in the table's order or a place another mark has.
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("zeroblob(15), 3, {id}, 'notes', 11"),
            ),
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("zeroblob(16), 3, {id}, 'other', 11"),
            ),
            one(
                "message_read_here",
                "mark, seq, id, made_at, merged_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, {id}, 11, 12"),
            ),
            one(
                "message_read_here",
                "mark, seq, name, made_at, merged_at",
                "X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, 'notes', 11, 12",
            ),
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, {id}, '', 11"),
            ),
            one(
                "message_read_here",
                "mark, seq, made_at",
                "X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, 11",
            ),
            one(
                "message_read_here",
                "mark, seq, id, name",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, {id}, 'notes'"),
            ),
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 3, {other}, 'notes', 11"),
            ),
            one(
                "message_read_here",
                "mark, id, name, made_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', {id}, 'notes', 11"),
            ),
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', NULL, {id}, 'notes', 11"),
            ),
            one(
                "message_read_here",
                "mark, seq, id, name, made_at",
                &format!("X'0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A', 2, {id}, 'notes', 11"),
            ),
            one("message_announced", "id, name", &format!("{id}, 'notes'")),
            one("message_announced", "id, name", &format!("{id}, ''")),
            one("message_announced", "id, name", &format!("{id}, NULL")),
            one(
                "message_announced",
                "id, name",
                &format!("{other}, 'notes'"),
            ),
            one("message_read_by_a_person", "id", id),
            one("message_read_by_a_person", "id", other),
            one("message_sends", "sent_at, name, to_all", "9, 'notes', 2"),
            one("message_sends", "sent_at, name, to_all", "9, NULL, 1"),
            one("message_sends", "sent_at, name, to_all", "9, '', 0"),
            one("message_sends", "name, to_all", "'notes', 0"),
            one(
                "message_kept",
                "id, generation, value, sent, kept_at",
                &format!("{id}, 1, zeroblob(1936), 9, 9"),
            ),
            one(
                "message_kept",
                "id, generation, value, sent, kept_at",
                "zeroblob(15), 1, zeroblob(1936), 9, 9",
            ),
            one(
                "message_kept",
                "id, generation, value, sent, kept_at",
                &format!("{other}, 0, zeroblob(1936), 9, 9"),
            ),
            one(
                "message_kept",
                "id, generation, value, sent, kept_at",
                &format!("{other}, 1, zeroblob(1935), 9, 9"),
            ),
            one(
                "message_kept",
                "id, generation, value, kept_at",
                &format!("{other}, 1, zeroblob(1936), 9"),
            ),
            one(
                "message_kept",
                "id, generation, value, sent",
                &format!("{other}, 1, zeroblob(1936), 9"),
            ),
            one("message_kept_numbers", "id, number", &format!("{id}, 0")),
            one("message_kept_numbers", "id, number", &format!("{id}, 65")),
            one("message_kept_numbers", "id, number", &format!("{other}, 2")),
            one(
                "message_kept_taken",
                "id, relay",
                &format!("{id}, zeroblob(31)"),
            ),
            one(
                "message_kept_taken",
                "id, relay",
                &format!("{id}, zeroblob(32)"),
            ),
            one(
                "message_kept_taken",
                "id, relay",
                &format!("{other}, zeroblob(32)"),
            ),
            // A channel of another length, a channel that is a generation
            // already, no statement or one below the first, no time; a
            // number counted from below the first; and a flag that is
            // neither, or none.
            one(
                "message_generations",
                "channel, statement, first_held",
                "zeroblob(31), 1, 9",
            ),
            one(
                "message_generations",
                "channel, statement, first_held",
                "zeroblob(32), 2, 9",
            ),
            one(
                "message_generations",
                "channel, statement, first_held",
                "zeroblob(33), 1, 9",
            ),
            one(
                "message_generations",
                "channel, first_held",
                &format!("X'{}', 9", "03".repeat(32)),
            ),
            one(
                "message_generations",
                "channel, statement, first_held",
                &format!("X'{}', 0, 9", "03".repeat(32)),
            ),
            one(
                "message_generations",
                "channel, statement",
                &format!("X'{}', 1", "03".repeat(32)),
            ),
            one(
                "message_signers",
                "signer, generation, highest, counted_from",
                "zeroblob(32), 2, 1, 0",
            ),
            "UPDATE message_index SET not_every_relay = 2".to_string(),
            "UPDATE message_index SET not_every_relay = NULL".to_string(),
        ]);
        for refused in refused {
            assert!(conn.execute(&refused, []).is_err(), "{refused}");
        }
        assert_eq!(counted(&conn), kept);
    }

    /// Each column of step 19 takes only its type and its bound (decision
    /// 2026-10-09 §9.2): a channel's ID, a signer, a key, a mark, an ID, a
    /// thread, an answer, a relay and a value are blobs of their length,
    /// and a text of that length is refused; every count, number and time
    /// is an integer, and a real or a text is refused; a statement's
    /// number is at most the highest statement; `counted_from` is at most
    /// `highest`; and a flag is 0 or 1 as an integer. Each refused value
    /// is taken in its place where it is of its type.
    #[test]
    fn step_19s_columns_take_only_their_type_and_their_bound() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let id = "X'01010101010101010101010101010101'";
        conn.execute_batch(&format!(
            "INSERT INTO message_generations (id, channel, statement, first_held)
                 VALUES (1, zeroblob(32), 1, 8);
             INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                        from_name, sent, subject, thread, answers, asks,
                                        link, body, first_held, placed_at)
                 VALUES ({id}, zeroblob(32), 'laptop', 1, 1, 'notes', '~', 9, 'a',
                         zeroblob(16), zeroblob(16), 0, NULL, 'a', 9, NULL);
             INSERT INTO message_kept (id, generation, value, sent, kept_at)
                 VALUES ({id}, 1, zeroblob(1936), 9, 9);"
        ))
        .unwrap();
        let text = |bytes: usize| format!("'{}'", "a".repeat(bytes));
        let other = "X'03030303030303030303030303030303'";
        let index = |at: usize, value: &str| -> String {
            let mut values = [
                other.to_string(),
                "zeroblob(32)".into(),
                "'laptop'".into(),
                "1".into(),
                "1".into(),
                "'notes'".into(),
                "'~'".into(),
                "9".into(),
                "'a'".into(),
                "zeroblob(16)".into(),
                "zeroblob(16)".into(),
                "0".into(),
                "NULL".into(),
                "'a'".into(),
                "9".into(),
                "NULL".into(),
            ];
            values[at] = value.to_string();
            format!(
                "INSERT INTO message_index (id, signer, label, generation, to_kind, to_name,
                                            from_name, sent, subject, thread, answers, asks,
                                            link, body, first_held, placed_at)
                 VALUES ({})",
                values.join(", ")
            )
        };
        // Each: what is refused, and the same row with a value of its type
        // and bound, which is taken and then taken out again.
        let cases: Vec<(String, String, &str)> = vec![
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES ({}, 1, 9)",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 257, 9)",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 256, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1.5, 9)",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 2, 9)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 'soon')",
                    "05".repeat(32)
                ),
                format!(
                    "INSERT INTO message_generations (channel, statement, first_held)
                     VALUES (X'{}', 1, 10)",
                    "05".repeat(32)
                ),
                "DELETE FROM message_generations WHERE id <> 1",
            ),
            (
                index(0, &text(16)),
                index(0, other),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(1, &text(32)),
                index(1, "zeroblob(32)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(9, &text(16)),
                index(9, "zeroblob(16)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(10, &text(16)),
                index(10, "zeroblob(16)"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(7, "9.5"),
                index(7, "10"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(11, "'1'||'x'"),
                index(11, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(11, "0.5"),
                index(11, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(14, "'then'"),
                index(14, "9"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(15, "10.5"),
                index(15, "10"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                index(3, "'1'||'x'"),
                index(3, "1"),
                "DELETE FROM message_index WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2.5, {id})"
                ),
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2, {id})"
                ),
                "DELETE FROM message_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES ({}, 1, 2, {id})",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_numbers (signer, generation, number, id)
                     VALUES (zeroblob(32), 1, 2, {id})"
                ),
                "DELETE FROM message_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {}, 9, 9)",
                    text(16)
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9.5, 9)"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES ({}, 1, 2, {id}, 9, 9)",
                    text(32)
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2.5, {id}, 9, 9)"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 'then')"
                ),
                format!(
                    "INSERT INTO message_first_held (signer, generation, number, id, sent,
                                                     first_held)
                     VALUES (zeroblob(32), 1, 2, {id}, 9, 9)"
                ),
                "DELETE FROM message_first_held",
            ),
            (
                format!(
                    "INSERT INTO message_signers (signer, generation, highest)
                     VALUES ({}, 1, 5)",
                    text(32)
                ),
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 4.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 4)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 6)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, counted_from)
                 VALUES (zeroblob(32), 1, 5, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest)
                 VALUES (zeroblob(32), 1, 5)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, overwritten)
                 VALUES (zeroblob(32), 1, 5, 'many')"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, overwritten)
                 VALUES (zeroblob(32), 1, 5, 7)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                "INSERT INTO message_signers (signer, generation, highest, not_messages)
                 VALUES (zeroblob(32), 1, 5, 0.5)"
                    .into(),
                "INSERT INTO message_signers (signer, generation, highest, not_messages)
                 VALUES (zeroblob(32), 1, 5, 1)"
                    .into(),
                "DELETE FROM message_signers",
            ),
            (
                format!(
                    "INSERT INTO message_places (signer, generation, placed_at)
                     VALUES ({}, 1, 10)",
                    text(32)
                ),
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10)"
                    .into(),
                "DELETE FROM message_places",
            ),
            (
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10.5)"
                    .into(),
                "INSERT INTO message_places (signer, generation, placed_at)
                 VALUES (zeroblob(32), 1, 10)"
                    .into(),
                "DELETE FROM message_places",
            ),
            (
                format!(
                    "INSERT INTO message_lists (key, mark) VALUES ({}, zeroblob(16))",
                    text(32)
                ),
                "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), zeroblob(16))".into(),
                "DELETE FROM message_lists",
            ),
            (
                format!(
                    "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), {})",
                    text(16)
                ),
                "INSERT INTO message_lists (key, mark) VALUES (zeroblob(32), zeroblob(16))".into(),
                "DELETE FROM message_lists",
            ),
            (
                format!(
                    "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                     VALUES ({}, 1, 8, 9)",
                    text(16)
                ),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1.5, 8, 9)"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 'then')"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8.5, 9)"
                    .into(),
                "INSERT INTO message_read_here (mark, seq, made_at, merged_at)
                 VALUES (zeroblob(16), 1, 8, 9)"
                    .into(),
                "DELETE FROM message_read_here",
            ),
            (
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0.5)".into(),
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0)".into(),
                "DELETE FROM message_sends",
            ),
            (
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES ('now', 'notes', 0)"
                    .into(),
                "INSERT INTO message_sends (sent_at, name, to_all) VALUES (9, 'notes', 0)".into(),
                "DELETE FROM message_sends",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, {}, 9, 9)",
                    text(1936)
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({}, 1, zeroblob(1936), 9, 9)",
                    text(16)
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9.5, 9)"
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 'then')"
                ),
                format!(
                    "INSERT INTO message_kept (id, generation, value, sent, kept_at)
                     VALUES ({other}, 1, zeroblob(1936), 9, 9)"
                ),
                "DELETE FROM message_kept WHERE id <> X'01010101010101010101010101010101'",
            ),
            (
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2.5)"),
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2)"),
                "DELETE FROM message_kept_numbers",
            ),
            (
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, '2'||'x')"),
                format!("INSERT INTO message_kept_numbers (id, number) VALUES ({id}, 2)"),
                "DELETE FROM message_kept_numbers",
            ),
            (
                format!(
                    "INSERT INTO message_kept_taken (id, relay) VALUES ({id}, {})",
                    text(32)
                ),
                format!("INSERT INTO message_kept_taken (id, relay) VALUES ({id}, zeroblob(32))"),
                "DELETE FROM message_kept_taken",
            ),
            (
                "UPDATE message_index SET not_every_relay = 0.5".into(),
                "UPDATE message_index SET not_every_relay = 1".into(),
                "UPDATE message_index SET not_every_relay = 0",
            ),
        ];
        for (refused, taken, undo) in cases {
            assert!(conn.execute(&refused, []).is_err(), "{refused}");
            assert_eq!(conn.execute(&taken, []), Ok(1), "{taken}");
            conn.execute_batch(undo).unwrap();
        }
    }

    /// The bounds that step 19 writes as numbers in its SQL are those of
    /// protocol.rs (decision 2026-10-09 §2.2, §2.3): a value's length, the
    /// highest number of a message, and the highest statement. Each is
    /// written where a column takes it, and nowhere with another value.
    #[test]
    fn step_19s_bounds_are_those_of_protocol_rs() {
        use cordelia_core::protocol::{
            AGENT_MESSAGE_NUMBER_MAX, AGENT_MESSAGE_VALUE_BYTES, MAX_STATEMENT_NUMBER,
        };
        let count = |text: &str| MIGRATION_V19.matches(text).count();
        assert_eq!(
            count(&format!("length(value) = {AGENT_MESSAGE_VALUE_BYTES})")),
            1
        );
        assert_eq!(count("length(value)"), 1);
        assert_eq!(count(&format!("number <= {AGENT_MESSAGE_NUMBER_MAX})")), 3);
        assert_eq!(count(&format!("highest <= {AGENT_MESSAGE_NUMBER_MAX})")), 1);
        assert_eq!(count(&AGENT_MESSAGE_NUMBER_MAX.to_string()), 4);
        assert_eq!(count(&format!("statement <= {MAX_STATEMENT_NUMBER})")), 1);
        assert_eq!(count("statement <="), 1);
        assert_eq!(count("counted_from <= highest"), 1);
    }

    /// A store opened as a personal node opens it has `secure_delete` on
    /// before the schema's steps run (decision 2026-10-09 §7.1): a step
    /// that rewrites a table, as step 4 rewrites `channels`, leaves
    /// nothing of the table it dropped in the file. Opened as a relay's
    /// is, the dropped table's text stays beside the copy.
    #[test]
    fn a_step_that_rewrites_a_table_writes_zeros_where_the_store_is_opened_so() {
        let words = "a descriptor of grebe-tamarind-cobalt";
        let dir = tempfile::tempdir().unwrap();
        let held_after_the_steps = |name: &str, secure_delete: bool| -> usize {
            let path = dir.path().join(name);
            let at_v3 = Connection::open(&path).unwrap();
            at_version_3(&at_v3).unwrap();
            at_v3
                .execute(
                    "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                           descriptor, created_at, updated_at)
                     VALUES ('c', 'group', 'batch', 'open', zeroblob(32), ?1, 't', 't')",
                    [words.as_bytes()],
                )
                .unwrap();
            drop(at_v3);

            let conn = crate::db::open_as(&path, secure_delete).unwrap();
            let version: u32 = conn
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            assert!(crate::db::checkpoint_truncating(&conn).unwrap());
            let bytes = std::fs::read(&path).unwrap();
            bytes
                .windows(words.len())
                .filter(|at| *at == words.as_bytes())
                .count()
        };
        assert_eq!(held_after_the_steps("relay.db", false), 2);
        assert_eq!(held_after_the_steps("personal.db", true), 1);
    }

    /// The version before, whose schema is at step 18, stops on a
    /// database that was stepped to 19 (decision 2026-10-09 §9.2), as
    /// every version stops on one from a later version: it is refused
    /// with both versions, and nothing of it is changed. A database at
    /// step 18 it opens.
    #[test]
    fn the_version_before_stops_on_a_database_of_step_19() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cordelia.db");
        drop(crate::db::open(&path).unwrap());
        let before = std::fs::read(&path).unwrap();

        let conn = Connection::open(&path).unwrap();
        let refused = refuse_a_later_version(&conn, 18);
        assert!(
            matches!(
                refused,
                Err(StorageError::LaterVersion { found: 19, own: 18 })
            ),
            "{refused:?}"
        );
        drop(conn);
        assert_eq!(std::fs::read(&path).unwrap(), before);

        let at_18 = at_v18();
        assert!(refuse_a_later_version(&at_18, 18).is_ok());
        assert!(refuse_a_later_version(&at_18, 17).is_err());
    }

    /// A database that is stepped from any version has what every later
    /// step makes: each step runs, and sets its own version and no later
    /// one. (A step that set the next one's version would leave the next
    /// step not run, with nothing to say so but what is missing.) From
    /// nothing, and from each version that a fixture here stands for.
    #[test]
    fn test_a_database_stepped_from_any_version_has_what_every_later_step_makes() {
        let version = |conn: &Connection| -> u32 {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap()
        };
        let table_of = |conn: &Connection, name: &str| -> bool {
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
                == 1
        };
        let from: [(u32, Connection); 11] = [
            (0, Connection::open_in_memory().unwrap()),
            (8, at_v8()),
            (10, at_v10()),
            (11, at_v11()),
            (12, at_v12()),
            (13, at_v13()),
            (14, at_v14()),
            (15, at_v15()),
            (16, at_v16()),
            (17, at_v17()),
            (18, at_v18()),
        ];
        for (at, conn) in from {
            assert_eq!(version(&conn), at);
            init_db(&conn).unwrap();
            assert_eq!(version(&conn), SCHEMA_VERSION, "from version {at}");
            // The steps to versions 9, 10 and 11: the writer of what a
            // folder agreed, the table of lines, and the table of entries.
            assert!(
                conn.prepare("SELECT author FROM sync_files").is_ok(),
                "from version {at}"
            );
            assert!(table_of(&conn, "index_lines"), "from version {at}");
            assert!(table_of(&conn, "entries"), "from version {at}");
            // And each step since, by everything it makes.
            assert_eq!(new_in_v12(&conn), NEW_IN_V12, "from version {at}");
            assert_eq!(new_in_v13(&conn), NEW_IN_V13, "from version {at}");
            assert_eq!(new_in_v14(&conn), NEW_IN_V14, "from version {at}");
            assert_eq!(new_in_v15(&conn), NEW_IN_V15, "from version {at}");
            assert_eq!(new_in_v16(&conn), NEW_IN_V16, "from version {at}");
            assert_eq!(new_in_v17(&conn), NEW_IN_V17, "from version {at}");
            assert_eq!(new_in_v18(&conn), NEW_IN_V18, "from version {at}");
            assert_eq!(new_in_v19(&conn), NEW_IN_V19, "from version {at}");
            assert!(item_counts(&conn).is_some(), "from version {at}");
            assert!(channel_places(&conn).is_some(), "from version {at}");
        }
    }

    /// The two counts of what `items` holds are kept in the write that
    /// changes a row, whoever makes it: an item more, an item fewer, many
    /// at once, and a content of another length. A write that is undone
    /// is not counted.
    #[test]
    fn test_the_counts_of_what_items_holds_are_kept_as_it_is_written() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        assert_eq!(item_counts(&conn), Some((0, 0)));
        conn.execute_batch(
            "INSERT INTO channels (channel_id, channel_type, mode, access, creator_id,
                                   created_at, updated_at)
             VALUES ('grp_a', 'group', 'realtime', 'invite_only', X'AA',
                     '2026-01-01', '2026-01-01'),
                    ('grp_b', 'group', 'realtime', 'invite_only', X'AA',
                     '2026-01-01', '2026-01-01');",
        )
        .unwrap();
        let insert = |id: &str, channel: &str, bytes: i64| {
            conn.execute(
                "INSERT INTO items (item_id, channel_id, author_id, item_type, published_at,
                                    content_hash, signature, encrypted_blob, content_length, seq)
                 VALUES (?1, ?2, X'AA', 'memory', '2026-01-01', ?1, X'02', zeroblob(?3), ?3, 1)",
                rusqlite::params![id, channel, bytes],
            )
        };
        let kept = |conn: &Connection| {
            let counts = item_counts(conn).unwrap();
            assert_eq!(counts, items_as_they_are(conn));
            counts
        };

        // An item more, and another, and one of no bytes.
        assert_eq!(insert("ci_1", "grp_a", 100), Ok(1));
        assert_eq!(kept(&conn), (1, 100));
        assert_eq!(insert("ci_2", "grp_a", 4096), Ok(1));
        assert_eq!(insert("ci_3", "grp_b", 0), Ok(1));
        assert_eq!(insert("ci_4", "grp_b", 7), Ok(1));
        assert_eq!(kept(&conn), (4, 4203));
        // An item that is not stored is not counted: its ID is taken.
        assert!(insert("ci_1", "grp_a", 50).is_err());
        conn.execute(
            "INSERT OR IGNORE INTO items (item_id, channel_id, author_id, item_type,
                                          published_at, content_hash, signature,
                                          encrypted_blob, content_length, seq)
             VALUES ('ci_1', 'grp_a', X'AA', 'memory', '2026-01-01', X'09', X'02', X'03', 1, 1)",
            [],
        )
        .unwrap();
        assert_eq!(kept(&conn), (4, 4203));

        // A content of another length, in the row that holds it.
        conn.execute(
            "UPDATE items SET encrypted_blob = zeroblob(10), content_length = 10
             WHERE item_id = 'ci_1'",
            [],
        )
        .unwrap();
        assert_eq!(kept(&conn), (4, 4113));
        // A write that changes no length changes no count.
        conn.execute("UPDATE items SET is_tombstone = 1", [])
            .unwrap();
        assert_eq!(kept(&conn), (4, 4113));

        // An item fewer, and a whole channel's at once.
        conn.execute("DELETE FROM items WHERE item_id = 'ci_2'", [])
            .unwrap();
        assert_eq!(kept(&conn), (3, 17));
        conn.execute("DELETE FROM items WHERE channel_id = 'grp_b'", [])
            .unwrap();
        assert_eq!(kept(&conn), (1, 10));

        // What is written and undone is not counted.
        conn.execute_batch("BEGIN").unwrap();
        assert_eq!(insert("ci_5", "grp_a", 900), Ok(1));
        conn.execute("DELETE FROM items WHERE item_id = 'ci_1'", [])
            .unwrap();
        assert_eq!(kept(&conn), (1, 900));
        conn.execute_batch("ROLLBACK").unwrap();
        assert_eq!(kept(&conn), (1, 10));

        // Every one gone: nothing is held.
        conn.execute("DELETE FROM items", []).unwrap();
        assert_eq!(kept(&conn), (0, 0));
    }

    /// The table takes no row that cannot be a channel a relay holds: an
    /// ID of another length, a second row for one channel, a channel that
    /// holds less than nothing, and a holding with no mark, with a mark
    /// of another length, or with the mark of no holding.
    #[test]
    fn test_the_table_of_a_relays_channels_refuses_a_row_that_is_no_channel() {
        let conn = Connection::open_in_memory().unwrap();
        init_db(&conn).unwrap();
        let marked = |channel: &[u8], bytes: i64, mark: &[u8]| {
            conn.execute(
                "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes, mark)
                 VALUES (?1, 7, 8, ?2, ?3)",
                rusqlite::params![channel, bytes, mark],
            )
        };
        let insert = |channel: &[u8], bytes: i64| marked(channel, bytes, &[9u8; 8]);
        assert!(insert(&[1u8; 31], 0).is_err());
        assert!(insert(&[1u8; 33], 0).is_err());
        assert!(insert(&[1u8; 32], -1).is_err());
        assert_eq!(insert(&[1u8; 32], 0), Ok(1));
        assert!(insert(&[1u8; 32], 0).is_err());
        assert_eq!(insert(&[2u8; 32], 1280), Ok(1));

        // The mark of a holding: 8 bytes, and not all zeros.
        for mark in [&[9u8; 7][..], &[9u8; 9], &[9u8; 32], &[], &[0u8; 8]] {
            assert!(marked(&[3u8; 32], 0, mark).is_err(), "{mark:?}");
        }
        assert!(
            conn.execute(
                "INSERT INTO relay_channels (channel_id, held_since, used_at, bytes)
                 VALUES (?1, 7, 8, 0)",
                [&[3u8; 32][..]],
            )
            .is_err(),
            "a holding with no mark was taken"
        );
        assert_eq!(marked(&[3u8; 32], 0, &[0, 0, 0, 0, 0, 0, 0, 1]), Ok(1));
        // Two holdings may have one mark: it is told apart by its channel.
        assert_eq!(marked(&[4u8; 32], 0, &[9u8; 8]), Ok(1));
    }
}
