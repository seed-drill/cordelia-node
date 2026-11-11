-- The schema of Cordelia 0.2.0-alpha.19 (schema step 33), exactly: the
-- baseline of decision 2026-11-10 (older kind), rule 5. Never edit it: a
-- change to the schema is a step after it (`schema.rs`).
--
-- It was made from alpha.19's own database, not written by hand. The
-- release's binary (cordelia-linux-amd64, v0.2.0-alpha.19) ran
-- `cordelia init --non-interactive` in an empty home, and then:
--
--   sqlite3 cordelia.db "SELECT sql || ';' || char(10) FROM sqlite_master
--     WHERE sql IS NOT NULL AND name <> 'sqlite_sequence'
--     AND name NOT IN (SELECT name FROM pragma_table_list
--                      WHERE type = 'shadow')
--     ORDER BY rowid"
--
-- gave each object as SQLite keeps its text, with what ALTER TABLE left,
-- in the order it was made; and
--
--   sqlite3 cordelia.db "SELECT 'INSERT INTO counters (name, value)
--     VALUES (' || quote(name) || ', ' || value || ');'
--     FROM counters ORDER BY rowid"
--
-- gave the rows of `counters`. The row of `person_clear_mark` is a random
-- mark, as alpha.19's step 21 made it. SQLite makes the rest itself: the
-- indexes of constraints, `sqlite_sequence`, and the FTS5 table's own
-- tables and rows. A test runs alpha.19's `init` and checks this against
-- what it makes (`a_new_database_is_alpha_19s_before_step_34`).

CREATE TABLE channel_members (
    channel_id   TEXT NOT NULL REFERENCES channels(channel_id),
    entity_key   BLOB NOT NULL,
    role         TEXT NOT NULL CHECK(role IN ('owner', 'admin', 'member')),
    posture      TEXT NOT NULL DEFAULT 'active' CHECK(posture IN ('active', 'removed')),
    joined_at    TEXT NOT NULL,
    removed_at   TEXT,
    PRIMARY KEY (channel_id, entity_key)
);

CREATE INDEX idx_members_entity ON channel_members(entity_key);

CREATE TABLE channel_keys (
    channel_id     TEXT PRIMARY KEY REFERENCES channels(channel_id),
    encrypted_psk  BLOB NOT NULL,
    key_version    INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE items (
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
, seq INTEGER, slot BLOB, rev INTEGER, relayed_at TEXT);

CREATE INDEX idx_items_channel_published ON items(channel_id, published_at);

CREATE INDEX idx_items_channel_type      ON items(channel_id, item_type);

CREATE INDEX idx_items_content_hash      ON items(content_hash);

CREATE TABLE dm_peers (
    channel_id   TEXT PRIMARY KEY REFERENCES channels(channel_id),
    peer_key     BLOB NOT NULL
);

CREATE TABLE search_content (
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

CREATE INDEX idx_search_content_channel ON search_content(channel_id);

CREATE INDEX idx_search_content_item_id ON search_content(item_id);

CREATE INDEX idx_search_content_type    ON search_content(channel_id, item_type);

CREATE VIRTUAL TABLE search_fts USING fts5(
    name,
    summary,
    content_text,
    tags_text,
    content = 'search_content',
    content_rowid = 'rowid',
    tokenize = 'unicode61'
);

CREATE TRIGGER search_fts_insert AFTER INSERT ON search_content BEGIN
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;

CREATE TRIGGER search_fts_delete AFTER DELETE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
END;

CREATE TRIGGER search_fts_update AFTER UPDATE ON search_content BEGIN
    INSERT INTO search_fts(search_fts, rowid, name, summary, content_text, tags_text)
    VALUES ('delete', OLD.rowid, OLD.name, OLD.summary, OLD.content_text, OLD.tags_text);
    INSERT INTO search_fts(rowid, name, summary, content_text, tags_text)
    VALUES (NEW.rowid, NEW.name, NEW.summary, NEW.content_text, NEW.tags_text);
END;

CREATE TABLE "channels" (
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

CREATE UNIQUE INDEX idx_channels_name ON channels(channel_name)
    WHERE channel_name IS NOT NULL AND channel_type = 'named';

CREATE TABLE trusted_keys (
    entity_key  BLOB PRIMARY KEY,
    kind        TEXT NOT NULL CHECK(kind IN ('device', 'person')),
    label       TEXT,
    added_at    TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE invites (
    item_id     TEXT PRIMARY KEY,
    inviter     BLOB NOT NULL,
    channel_id  TEXT NOT NULL,
    status      TEXT NOT NULL
                CHECK(status IN ('pending', 'accepted', 'rejected', 'invalid', 'superseded')),
    received_at TEXT NOT NULL,
    decided_at  TEXT
);

CREATE INDEX idx_invites_status ON invites(status, received_at);

CREATE TABLE node_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
);

CREATE INDEX idx_items_channel_seq ON items(channel_id, seq);

CREATE INDEX idx_items_slot ON items(channel_id, slot, author_id)
    WHERE slot IS NOT NULL;

CREATE INDEX idx_items_unrelayed ON items(author_id, seq)
    WHERE relayed_at IS NULL;

CREATE TABLE sync_files (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    hash        BLOB,
    rev         INTEGER NOT NULL, author BLOB, chain BLOB,
    PRIMARY KEY (folder, channel_id, key)
);

CREATE TABLE peer_sightings (
    peer_hash   BLOB PRIMARY KEY,
    is_relay    INTEGER NOT NULL DEFAULT 0,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL
);

CREATE INDEX idx_peer_sightings_last ON peer_sightings(last_seen);

CREATE INDEX idx_items_received ON items(received_at);

CREATE TABLE state_offers (
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

CREATE TABLE relay_channels (
    channel_id  BLOB PRIMARY KEY CHECK(length(channel_id) = 32),
    held_since  INTEGER NOT NULL,
    used_at     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL CHECK(bytes >= 0),
    mark        BLOB NOT NULL CHECK(length(mark) = 8 AND mark != zeroblob(8))
);

CREATE INDEX idx_relay_channels_held ON relay_channels(held_since);

CREATE INDEX idx_relay_channels_used ON relay_channels(used_at);

CREATE TABLE person_hand_overs (
    key      BLOB PRIMARY KEY CHECK(length(key) = 32),
    channel  BLOB NOT NULL CHECK(length(channel) = 32),
    rev      INTEGER NOT NULL CHECK(rev >= 1),
    made_at  INTEGER NOT NULL,
    held     INTEGER NOT NULL CHECK(held IN (0, 1))
);

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

CREATE TABLE person_typed_keys (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    typed_at  INTEGER NOT NULL,
    taken_at  INTEGER,
    said      TEXT
, stood TEXT NOT NULL DEFAULT '');

CREATE TABLE person_left_out (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    label     TEXT NOT NULL,
    number    INTEGER NOT NULL CHECK(number >= 1),
    noted_at  INTEGER NOT NULL
, cleared_at INTEGER);

CREATE TABLE person_cleared (
    notice      BLOB PRIMARY KEY CHECK(length(notice) = 32),
    cleared_at  INTEGER NOT NULL
);

CREATE TABLE at_relays_refused (
    relay BLOB NOT NULL CHECK(length(relay) = 32),
    channel BLOB NOT NULL CHECK(length(channel) = 32),
    seq INTEGER NOT NULL CHECK(seq > 0),
    PRIMARY KEY (relay, channel, seq)
);

CREATE INDEX idx_at_relays_refused_channel ON at_relays_refused(channel);

CREATE TABLE person_names_before (
    name     TEXT NOT NULL CHECK(length(name) >= 1),
    said_by  BLOB NOT NULL CHECK(length(said_by) = 32),
    left_at  INTEGER NOT NULL,
    PRIMARY KEY (name, said_by)
);

CREATE TABLE person_left (
    key       BLOB PRIMARY KEY CHECK(length(key) = 32),
    notice    BLOB NOT NULL CHECK(length(notice) = 32),
    number    INTEGER NOT NULL CHECK(number >= 1),
    noted_at  INTEGER NOT NULL
);

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

CREATE TABLE message_lists (
    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    PRIMARY KEY (key, mark)
);

CREATE INDEX idx_message_lists_mark ON message_lists(mark);

CREATE TABLE message_read_here (
    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),
    id         BLOB REFERENCES message_index(id),
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

CREATE TABLE message_person_marks (
    key       BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    id        BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    taken_at  INTEGER NOT NULL CHECK(typeof(taken_at) = 'integer'),
    PRIMARY KEY (key, id)
);

CREATE INDEX idx_message_person_marks_id ON message_person_marks(id);

CREATE TABLE message_bounds (
    key         BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    a           TEXT NOT NULL CHECK(typeof(a) = 'text' AND length(a) >= 1),
    b_kind      INTEGER NOT NULL CHECK(b_kind IN (1, 2)),
    b           TEXT NOT NULL CHECK(typeof(b) = 'text'),
    bound       INTEGER CHECK(bound IS NULL
                              OR (typeof(bound) = 'integer' AND bound >= 1 AND bound <= 64)),
    set_order   BLOB NOT NULL CHECK(typeof(set_order) = 'blob' AND length(set_order) = 8),
    at_clock    BLOB NOT NULL CHECK(typeof(at_clock) = 'blob' AND length(at_clock) = 8),
    for_secs    INTEGER NOT NULL CHECK(typeof(for_secs) = 'integer'
                                       AND for_secs >= 60 AND for_secs <= 604800),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    start       INTEGER CHECK(start IS NULL OR typeof(start) = 'integer'),
    CHECK((b_kind = 1) = (length(b) >= 1)),
    PRIMARY KEY (key, a, b_kind, b)
);

CREATE TABLE person_removed_keys (
    key      BLOB PRIMARY KEY CHECK(typeof(key) = 'blob' AND length(key) = 32),
    seen_at  INTEGER NOT NULL CHECK(typeof(seen_at) = 'integer')
);

CREATE TABLE person_holders (
    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number >= 1),
    hash    BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 16),
    key     BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    PRIMARY KEY (number, hash, key)
);

CREATE TABLE person_holders_past (
    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number >= 1),
    hash    BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 16),
    PRIMARY KEY (number, hash)
);

CREATE TABLE person_clear_mark (
    one   INTEGER PRIMARY KEY CHECK(one = 1),
    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16)
);

CREATE TRIGGER person_clear_on_person_insert AFTER INSERT ON person
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_person_update AFTER UPDATE ON person
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_person_delete AFTER DELETE ON person
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_additions_insert AFTER INSERT ON person_additions
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_additions_update AFTER UPDATE ON person_additions
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_additions_delete AFTER DELETE ON person_additions
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_removed_insert AFTER INSERT ON person_removed_keys
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_removed_update AFTER UPDATE ON person_removed_keys
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_removed_delete AFTER DELETE ON person_removed_keys
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_holders_insert AFTER INSERT ON person_holders
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_holders_update AFTER UPDATE ON person_holders
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_holders_delete AFTER DELETE ON person_holders
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_past_insert AFTER INSERT ON person_holders_past
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_past_update AFTER UPDATE ON person_holders_past
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_past_delete AFTER DELETE ON person_holders_past
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_meta_insert AFTER INSERT ON node_meta
WHEN NEW.key = 'person.removed_past_bound'
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_meta_update AFTER UPDATE ON node_meta
WHEN NEW.key = 'person.removed_past_bound' OR OLD.key = 'person.removed_past_bound'
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TRIGGER person_clear_on_meta_delete AFTER DELETE ON node_meta
WHEN OLD.key = 'person.removed_past_bound'
BEGIN UPDATE person_clear_mark SET mark = randomblob(16); END;

CREATE TABLE "person_change_entries" (
    place         INTEGER PRIMARY KEY,
    followed      INTEGER NOT NULL CHECK(followed IN (0, 1)),
    set_aside_at  INTEGER CHECK(set_aside_at IS NULL OR typeof(set_aside_at) = 'integer'),
    channel       BLOB NOT NULL CHECK(length(channel) = 32),
    slot          BLOB NOT NULL CHECK(length(slot) = 32),
    author        BLOB NOT NULL CHECK(length(author) = 32),
    rev           INTEGER NOT NULL CHECK(rev BETWEEN 1 AND 256),
    content       BLOB NOT NULL,
    author_sig    BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig   BLOB NOT NULL CHECK(length(channel_sig) = 64),
    CHECK((followed = 1) = (set_aside_at IS NULL))
);

CREATE UNIQUE INDEX idx_person_change_entries_followed
    ON person_change_entries(followed) WHERE followed = 1;

CREATE TABLE person_change_times (
    number   INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number BETWEEN 1 AND 256),
    hash     BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 16),
    made_at  INTEGER CHECK(made_at IS NULL OR typeof(made_at) = 'integer'),
    PRIMARY KEY (number, hash)
);

CREATE TABLE entries (
    channel_id     BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot           BLOB NOT NULL CHECK(length(slot) = 32),
    author         BLOB NOT NULL CHECK(length(author) = 32),
    rev            INTEGER NOT NULL CHECK(rev >= 1),
    is_delete      INTEGER NOT NULL CHECK(is_delete IN (0, 1)),
    content        BLOB NOT NULL,
    author_sig     BLOB NOT NULL CHECK(length(author_sig) = 64),
    channel_sig    BLOB NOT NULL CHECK(length(channel_sig) = 64),
    seq            INTEGER NOT NULL,
    stored_at      INTEGER NOT NULL,
    channel_place  INTEGER NOT NULL DEFAULT 0,
    head           BLOB NOT NULL DEFAULT x''
                   CHECK(typeof(head) = 'blob' AND length(head) IN (0, 32)),
    PRIMARY KEY (channel_id, slot, author, head)
);

CREATE UNIQUE INDEX idx_entries_channel_seq ON entries(channel_id, seq);

CREATE UNIQUE INDEX idx_entries_channel_place ON entries(channel_id, channel_place);

CREATE TABLE relay_head_rooms (
    channel_id  BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot        BLOB NOT NULL CHECK(length(slot) = 32),
    author      BLOB NOT NULL CHECK(length(author) = 32),
    PRIMARY KEY (channel_id, slot, author)
);

CREATE TABLE person_change_times_lists (
    number   INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number BETWEEN 1 AND 256),
    hash     BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 16),
    removed  BLOB NOT NULL CHECK(typeof(removed) = 'blob' AND length(removed) % 32 = 0),
    chain    BLOB NOT NULL CHECK(typeof(chain) = 'blob' AND length(chain) % 24 = 0),
    devices  BLOB NOT NULL CHECK(typeof(devices) = 'blob' AND length(devices) % 32 = 0),
    commitment  BLOB CHECK(commitment IS NULL OR length(commitment) = 32),
    PRIMARY KEY (number, hash)
);

CREATE TABLE person_removed_keys_by (
    key       BLOB PRIMARY KEY CHECK(typeof(key) = 'blob' AND length(key) = 32),
    added_by  BLOB NOT NULL CHECK(typeof(added_by) = 'blob' AND length(added_by) = 32)
);

CREATE TABLE person_removed_keys_spared (
    key     BLOB PRIMARY KEY CHECK(typeof(key) = 'blob' AND length(key) = 32),
    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number BETWEEN 1 AND 256)
);

CREATE TABLE file_put_back (
    folder      TEXT NOT NULL,
    channel_id  TEXT NOT NULL,
    key         TEXT NOT NULL,
    PRIMARY KEY (folder, channel_id, key)
);

CREATE TABLE file_line_from (
    folder        TEXT NOT NULL,
    channel_id    TEXT NOT NULL,
    file          TEXT NOT NULL,
    from_signers  BLOB NOT NULL CHECK(typeof(from_signers) = 'blob'
                                      AND length(from_signers) % 32 = 0),
    PRIMARY KEY (folder, channel_id, file)
);

CREATE TABLE file_arrivals_stored (
    place               INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id          BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot                BLOB NOT NULL CHECK(length(slot) = 32),
    number              INTEGER NOT NULL CHECK(typeof(number) = 'integer' AND number >= 1),
    hash                BLOB NOT NULL CHECK(typeof(hash) = 'blob' AND length(hash) = 16),
    stored_at           INTEGER NOT NULL CHECK(typeof(stored_at) = 'integer'),
    full_signers        BLOB CHECK(full_signers IS NULL OR length(full_signers) % 16 = 0),
    before_author       BLOB CHECK(before_author IS NULL OR length(before_author) = 32),
    before_rev          INTEGER,
    before_delete       INTEGER,
    before_content      BLOB,
    before_author_sig   BLOB,
    before_channel_sig  BLOB,
    stored_id           BLOB CHECK(stored_id IS NULL OR length(stored_id) = 32)
, unknown INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(unknown) = 'integer' AND unknown IN (0, 1)));

CREATE INDEX file_arrivals_stored_by_file ON file_arrivals_stored(channel_id, slot, place);

CREATE TABLE file_arrivals (
    stored     INTEGER NOT NULL,
    signer     BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 16),
    link_hash  BLOB CHECK(link_hash IS NULL OR length(link_hash) = 16),
    times      INTEGER NOT NULL DEFAULT 1 CHECK(typeof(times) = 'integer' AND times >= 1)
);

CREATE INDEX file_arrivals_by_stored ON file_arrivals(stored);

CREATE TABLE file_arrivals_dropped (
    channel_id          BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot                BLOB NOT NULL CHECK(length(slot) = 32),
    number              INTEGER NOT NULL,
    hash                BLOB NOT NULL CHECK(length(hash) = 16),
    newest_at           INTEGER NOT NULL,
    first_place         INTEGER NOT NULL,
    before_author       BLOB CHECK(before_author IS NULL OR length(before_author) = 32),
    before_rev          INTEGER,
    before_delete       INTEGER,
    before_content      BLOB,
    before_author_sig   BLOB,
    before_channel_sig  BLOB,
    first_stored_id     BLOB CHECK(first_stored_id IS NULL OR length(first_stored_id) = 32),
    PRIMARY KEY (channel_id, slot, number, hash)
);

CREATE TABLE file_copies (
    channel_id  BLOB NOT NULL CHECK(length(channel_id) = 32),
    slot        BLOB NOT NULL CHECK(length(slot) = 32),
    folder      TEXT NOT NULL,
    key         TEXT NOT NULL,
    chain       BLOB NOT NULL CHECK(typeof(chain) = 'blob' AND length(chain) % 32 = 0), held INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(held) = 'integer' AND held IN (0, 1)),
    PRIMARY KEY (channel_id, slot)
);

CREATE TABLE file_cut (
    folder  TEXT NOT NULL,
    file    TEXT NOT NULL,
    PRIMARY KEY (folder, file)
);

CREATE TABLE file_cut_written (
    folder  TEXT NOT NULL,
    file    TEXT NOT NULL,
    sha256  TEXT NOT NULL CHECK(typeof(sha256) = 'text' AND length(sha256) = 64),
    at      INTEGER NOT NULL CHECK(typeof(at) = 'integer'),
    PRIMARY KEY (folder, file, sha256)
);

CREATE TABLE shared_lists (
    one   INTEGER PRIMARY KEY CHECK(one = 1),
    list  BLOB NOT NULL CHECK(typeof(list) = 'blob'
                              AND length(list) >= 5 AND length(list) <= 41333),
    rev   INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                 AND rev >= 0 AND rev <= 9007199254740991)
);

CREATE TABLE shared_list_taken (
    signature   BLOB PRIMARY KEY CHECK(typeof(signature) = 'blob' AND length(signature) = 64),
    generation  INTEGER NOT NULL CHECK(typeof(generation) = 'integer'
                                       AND generation >= 0 AND generation <= 256),
    taken_at    INTEGER NOT NULL CHECK(typeof(taken_at) = 'integer'),
    carried_in  INTEGER NOT NULL CHECK(typeof(carried_in) = 'integer'
                                       AND carried_in >= 0 AND carried_in <= 256)
);

CREATE TABLE shared_channels (
    id          INTEGER PRIMARY KEY,
    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    card        BLOB NOT NULL CHECK(typeof(card) = 'blob' AND length(card) IN (65, 97)),
    name        TEXT NOT NULL CHECK(typeof(name) = 'text'
                                    AND length(CAST(name AS BLOB)) >= 1
                                    AND length(CAST(name AS BLOB)) <= 200),
    came        INTEGER NOT NULL CHECK(came IN (1, 2, 3)),
    came_from   BLOB CHECK((came = 1) = (came_from IS NULL)
                           AND (came_from IS NULL
                                OR (typeof(came_from) = 'blob' AND length(came_from) = 32))),
    state       INTEGER NOT NULL CHECK(state IN (1, 2, 3, 4)),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    left_at     INTEGER CHECK(left_at IS NULL OR typeof(left_at) = 'integer'),
    room        INTEGER NOT NULL DEFAULT 0 CHECK(typeof(room) = 'integer' AND room >= 0),
    let_go      INTEGER NOT NULL DEFAULT 0 CHECK(typeof(let_go) = 'integer' AND let_go >= 0),
    read_asked  INTEGER CHECK(read_asked IS NULL OR typeof(read_asked) = 'integer'),
    read_begun  INTEGER CHECK(read_begun IS NULL OR typeof(read_begun) = 'integer')
);

CREATE TABLE shared_keys (
    channel           INTEGER NOT NULL REFERENCES shared_channels(id),
    key               BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    known             INTEGER NOT NULL CHECK(known IN (0, 1)),
    unknown_since     INTEGER CHECK(unknown_since IS NULL
                                    OR (typeof(unknown_since) = 'integer' AND known = 0)),
    held_order        INTEGER CHECK(held_order IS NULL
                                    OR (typeof(held_order) = 'integer' AND held_order >= 1)),
    first_held        INTEGER CHECK(first_held IS NULL OR typeof(first_held) = 'integer'),
    last_held         INTEGER CHECK(last_held IS NULL OR typeof(last_held) = 'integer'),
    first_refused     INTEGER CHECK(first_refused IS NULL OR typeof(first_refused) = 'integer'),
    last_refused      INTEGER CHECK(last_refused IS NULL OR typeof(last_refused) = 'integer'),
    last_seq          INTEGER NOT NULL CHECK(typeof(last_seq) = 'integer' AND last_seq >= 1),
    bytes_stored      INTEGER NOT NULL DEFAULT 0
                          CHECK(typeof(bytes_stored) = 'integer' AND bytes_stored >= 0),
    bytes_refused     INTEGER NOT NULL DEFAULT 0
                          CHECK(typeof(bytes_refused) = 'integer' AND bytes_refused >= 0),
    kept_message_rev  INTEGER CHECK(kept_message_rev IS NULL
                                    OR (typeof(kept_message_rev) = 'integer'
                                        AND kept_message_rev >= 0
                                        AND kept_message_rev < 8796093022208)),
    kept_anew_rev     INTEGER CHECK(kept_anew_rev IS NULL
                                    OR (typeof(kept_anew_rev) = 'integer'
                                        AND kept_anew_rev >= 0
                                        AND kept_anew_rev < 8796093022208)),
    CHECK((held_order IS NULL) = (first_held IS NULL)),
    CHECK((first_held IS NULL) = (last_held IS NULL)),
    CHECK((first_refused IS NULL) = (last_refused IS NULL)),
    CHECK(first_held IS NOT NULL OR first_refused IS NOT NULL),
    PRIMARY KEY (channel, key)
);

CREATE INDEX idx_shared_keys_held_order ON shared_keys(channel, held_order);

CREATE INDEX idx_shared_keys_last_seq ON shared_keys(channel, last_seq);

CREATE TABLE shared_unopened (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id),
    key      BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    slot     BLOB NOT NULL CHECK(typeof(slot) = 'blob' AND length(slot) = 32),
    PRIMARY KEY (channel, key, slot)
);

CREATE TABLE shared_labelled (
    key  BLOB PRIMARY KEY CHECK(typeof(key) = 'blob' AND length(key) = 32)
);

CREATE TABLE shared_index (
    channel     INTEGER NOT NULL REFERENCES shared_channels(id),
    id          BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    sent        INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    subject     TEXT NOT NULL,
    thread      BLOB NOT NULL CHECK(typeof(thread) = 'blob' AND length(thread) = 16),
    answers     BLOB NOT NULL CHECK(typeof(answers) = 'blob' AND length(answers) = 16),
    asks        INTEGER NOT NULL CHECK(asks IN (0, 1)),
    link        TEXT,
    body        TEXT NOT NULL,
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    placed_at   INTEGER CHECK(placed_at IS NULL OR typeof(placed_at) = 'integer'),
    PRIMARY KEY (channel, id)
);

CREATE INDEX idx_shared_index_signer ON shared_index(channel, signer);

CREATE TABLE shared_numbers (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id),
    signer   BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    number   INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                    AND number >= 1 AND number <= 4398046511103),
    id       BLOB NOT NULL,
    FOREIGN KEY (channel, id) REFERENCES shared_index(channel, id) ON DELETE CASCADE,
    PRIMARY KEY (channel, signer, number)
);

CREATE INDEX idx_shared_numbers_id ON shared_numbers(channel, id);

CREATE TABLE shared_first_held (
    channel     INTEGER NOT NULL REFERENCES shared_channels(id),
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                       AND number >= 1 AND number <= 4398046511103),
    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),
    sent        INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),
    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    taken_out   INTEGER NOT NULL DEFAULT 0 CHECK(taken_out IN (0, 1)),
    placed_at   INTEGER CHECK(placed_at IS NULL
                              OR (typeof(placed_at) = 'integer' AND taken_out = 1)),
    CHECK((id IS NULL) = (sent IS NULL)),
    CHECK(id IS NOT NULL OR taken_out = 0),
    PRIMARY KEY (channel, signer, number)
);

CREATE INDEX idx_shared_first_held_id ON shared_first_held(channel, id);

CREATE TABLE shared_signers (
    channel       INTEGER NOT NULL REFERENCES shared_channels(id),
    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'
                                         AND highest >= 0 AND highest <= 4398046511103),
    overwritten   INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(overwritten) = 'integer' AND overwritten >= 0),
    not_messages  INTEGER NOT NULL DEFAULT 0
                      CHECK(typeof(not_messages) = 'integer' AND not_messages >= 0),
    counted_from  INTEGER CHECK(counted_from IS NULL
                                OR (typeof(counted_from) = 'integer'
                                    AND counted_from >= 1 AND counted_from <= highest)),
    PRIMARY KEY (channel, signer)
);

CREATE TABLE shared_places (
    channel     INTEGER NOT NULL REFERENCES shared_channels(id),
    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),
    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer'),
    unlabelled  INTEGER NOT NULL CHECK(unlabelled IN (0, 1))
);

CREATE INDEX idx_shared_places ON shared_places(channel, signer, placed_at);

CREATE TABLE shared_relay_places (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id),
    relay    BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),
    mark     BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 8),
    next     INTEGER NOT NULL CHECK(typeof(next) = 'integer' AND next >= 0),
    PRIMARY KEY (channel, relay)
);

CREATE TABLE shared_relay_sent (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id),
    relay    BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),
    slot     BLOB NOT NULL CHECK(typeof(slot) = 'blob' AND length(slot) = 32),
    rev      INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                    AND rev >= 0 AND rev < 8796093022208),
    answer   INTEGER NOT NULL CHECK(answer IN (1, 2, 3, 4)),
    PRIMARY KEY (channel, relay, slot)
);

CREATE TABLE shared_take_out_channels (
    channel  INTEGER PRIMARY KEY REFERENCES shared_channels(id),
    how      INTEGER NOT NULL CHECK(how IN (1, 2, 3))
);

CREATE TABLE shared_take_out_keys (
    channel      INTEGER NOT NULL REFERENCES shared_channels(id),
    key          BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    as_refused   INTEGER NOT NULL CHECK(as_refused IN (0, 1)),
    PRIMARY KEY (channel, key)
);

CREATE TABLE shared_typed_keys (
    key       BLOB PRIMARY KEY CHECK(typeof(key) = 'blob' AND length(key) = 32),
    name      TEXT NOT NULL CHECK(typeof(name) = 'text'
                                  AND length(CAST(name AS BLOB)) >= 1
                                  AND length(CAST(name AS BLOB)) <= 200),
    typed_at  INTEGER NOT NULL CHECK(typeof(typed_at) = 'integer'),
    taken_at  INTEGER CHECK(taken_at IS NULL OR typeof(taken_at) = 'integer'),
    channel   BLOB CHECK(channel IS NULL OR (typeof(channel) = 'blob' AND length(channel) = 32)),
    became    TEXT CHECK(became IS NULL
                         OR (typeof(became) = 'text' AND length(CAST(became AS BLOB)) <= 64)),
    detail    TEXT CHECK(detail IS NULL
                         OR (typeof(detail) = 'text' AND length(CAST(detail AS BLOB)) <= 1024)),
    CHECK((taken_at IS NULL) = (channel IS NULL))
);

CREATE TABLE shared_shares (
    key      BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    channel  BLOB NOT NULL CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    pair     BLOB NOT NULL CHECK(typeof(pair) = 'blob' AND length(pair) = 32),
    relays   BLOB NOT NULL CHECK(typeof(relays) = 'blob' AND length(relays) IN (33, 65)),
    rev      INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                    AND rev >= 0 AND rev <= 9007199254740991),
    made     INTEGER NOT NULL CHECK(typeof(made) = 'integer'),
    gone     INTEGER NOT NULL DEFAULT 0 CHECK(gone IN (0, 1)), by_node INTEGER NOT NULL DEFAULT 0 CHECK(by_node IN (0, 1)),
    PRIMARY KEY (key, channel)
);

CREATE TABLE shared_share_sent (
    key      BLOB NOT NULL,
    channel  BLOB NOT NULL,
    relay    BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),
    rev      INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                    AND rev >= 0 AND rev <= 9007199254740991),
    FOREIGN KEY (key, channel) REFERENCES shared_shares(key, channel) ON DELETE CASCADE,
    PRIMARY KEY (key, channel, relay)
);

CREATE TABLE shared_msg_subscribed (
    channel  BLOB NOT NULL CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    agent    TEXT NOT NULL CHECK(typeof(agent) = 'text'
                                 AND length(CAST(agent AS BLOB)) >= 1
                                 AND length(CAST(agent AS BLOB)) <= 200),
    start    INTEGER NOT NULL CHECK(typeof(start) = 'integer'),
    PRIMARY KEY (channel, agent)
);

CREATE TABLE shared_msg_marks (
    mark     BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    seq      INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),
    made_at  INTEGER NOT NULL CHECK(typeof(made_at) = 'integer')
);

CREATE TABLE shared_msg_lists (
    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),
    PRIMARY KEY (key, mark)
);

CREATE INDEX idx_shared_msg_lists_mark ON shared_msg_lists(mark);

CREATE TABLE shared_msg_read_by_a_person (
    channel  INTEGER NOT NULL,
    id       BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    FOREIGN KEY (channel, id) REFERENCES shared_index(channel, id) ON DELETE CASCADE,
    PRIMARY KEY (channel, id)
);

CREATE TABLE shared_msg_sends (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id) ON DELETE CASCADE,
    sent_at  INTEGER NOT NULL CHECK(typeof(sent_at) = 'integer'),
    again    INTEGER NOT NULL CHECK(again IN (0, 1))
);

CREATE INDEX idx_shared_msg_sends ON shared_msg_sends(channel, sent_at);

CREATE TABLE shared_msg_kept (
    channel  INTEGER NOT NULL REFERENCES shared_channels(id) ON DELETE CASCADE,
    id       BLOB NOT NULL CHECK(typeof(id) = 'blob' AND length(id) = 16),
    value    BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),
    sent     INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),
    kept_at  INTEGER NOT NULL CHECK(typeof(kept_at) = 'integer'),
    again    INTEGER NOT NULL DEFAULT 0 CHECK(again IN (0, 1)),
    PRIMARY KEY (channel, id)
);

CREATE TABLE shared_msg_kept_numbers (
    channel  INTEGER NOT NULL,
    id       BLOB NOT NULL,
    number   INTEGER NOT NULL CHECK(typeof(number) = 'integer'
                                    AND number >= 1 AND number <= 4398046511103),
    FOREIGN KEY (channel, id) REFERENCES shared_msg_kept(channel, id) ON DELETE CASCADE,
    PRIMARY KEY (channel, id, number)
);

CREATE TABLE shared_anew_offers (
    channel      BLOB NOT NULL CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    maker        BLOB NOT NULL CHECK(typeof(maker) = 'blob' AND length(maker) = 32),
    rev          INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                        AND rev >= 0 AND rev <= 9007199254740991),
    made         INTEGER NOT NULL CHECK(typeof(made) = 'integer' AND made >= 0),
    new_channel  BLOB NOT NULL CHECK(typeof(new_channel) = 'blob' AND length(new_channel) = 32),
    relays       BLOB NOT NULL CHECK(typeof(relays) = 'blob'
                                     AND length(relays) IN (33, 65)),
    sealed_to    BLOB NOT NULL CHECK(typeof(sealed_to) = 'blob'
                                     AND length(sealed_to) >= 32
                                     AND length(sealed_to) <= 2048
                                     AND length(sealed_to) % 32 = 0),
    own_seal     BLOB CHECK(own_seal IS NULL
                            OR (typeof(own_seal) = 'blob' AND length(own_seal) = 92)),
    first_held   INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),
    stayed       INTEGER NOT NULL DEFAULT 0 CHECK(stayed IN (0, 1)),
    PRIMARY KEY (channel, maker)
);

CREATE INDEX idx_shared_anew_offers_new ON shared_anew_offers(new_channel);

CREATE TABLE shared_anew_made (
    channel      BLOB PRIMARY KEY CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    new_channel  BLOB NOT NULL CHECK(typeof(new_channel) = 'blob' AND length(new_channel) = 32),
    rev          INTEGER NOT NULL CHECK(typeof(rev) = 'integer'
                                        AND rev >= 0 AND rev <= 9007199254740991),
    made_at      INTEGER NOT NULL CHECK(typeof(made_at) = 'integer'),
    at_removal   INTEGER NOT NULL CHECK(at_removal IN (0, 1)),
    delivering   INTEGER NOT NULL CHECK(delivering IN (0, 1)),
    past_64      INTEGER NOT NULL DEFAULT 0 CHECK(typeof(past_64) = 'integer' AND past_64 >= 0),
    let_go       INTEGER NOT NULL DEFAULT 0 CHECK(typeof(let_go) = 'integer' AND let_go >= 0),
    past_bound   INTEGER NOT NULL DEFAULT 0 CHECK(past_bound IN (0, 1))
, left_out BLOB CHECK(left_out IS NULL
    OR (typeof(left_out) = 'blob' AND length(left_out) % 32 = 0 AND length(left_out) <= 32768)), line TEXT CHECK(line IS NULL
    OR (typeof(line) = 'text' AND length(CAST(line AS BLOB)) <= 16384)), cut INTEGER NOT NULL DEFAULT 0
    CHECK(typeof(cut) = 'integer' AND cut >= 0), named_at INTEGER
    CHECK(named_at IS NULL OR typeof(named_at) = 'integer'));

CREATE TABLE shared_anew_not_clean (
    channel  BLOB PRIMARY KEY CHECK(typeof(channel) = 'blob' AND length(channel) = 32),
    since    INTEGER NOT NULL CHECK(typeof(since) = 'integer'),
    owed     INTEGER NOT NULL CHECK(owed IN (0, 1)),
    unreached INTEGER NOT NULL DEFAULT 0 CHECK(unreached IN (0, 1))
);

CREATE TABLE shared_follows (
    identity      TEXT PRIMARY KEY CHECK(typeof(identity) = 'text'
                                         AND length(CAST(identity AS BLOB)) BETWEEN 5 AND 300),
    remote        TEXT NOT NULL CHECK(typeof(remote) = 'text'
                                      AND length(CAST(remote AS BLOB)) BETWEEN 1 AND 255),
    clone         TEXT NOT NULL CHECK(typeof(clone) = 'text'
                                      AND length(CAST(clone AS BLOB)) BETWEEN 1 AND 4096),
    followed_at   INTEGER NOT NULL CHECK(typeof(followed_at) = 'integer'),
    last_commit   TEXT CHECK(last_commit IS NULL
                             OR (typeof(last_commit) = 'text' AND length(last_commit) IN (40, 64))),
    last_read_at  INTEGER CHECK(last_read_at IS NULL OR typeof(last_read_at) = 'integer'),
    read_from     INTEGER CHECK(read_from IS NULL OR read_from IN (0, 1)),
    fetched_at    INTEGER CHECK(fetched_at IS NULL OR typeof(fetched_at) = 'integer'),
    list          BLOB CHECK(list IS NULL OR (typeof(list) = 'blob' AND length(list) <= 16384)),
    last_handed   BLOB CHECK(last_handed IS NULL
                             OR (typeof(last_handed) = 'blob' AND length(last_handed) = 32)),
    not_read      TEXT CHECK(not_read IS NULL
                             OR (typeof(not_read) = 'text'
                                 AND length(CAST(not_read AS BLOB)) BETWEEN 1 AND 64)),
    not_read_why  TEXT CHECK(not_read_why IS NULL
                             OR (typeof(not_read_why) = 'text'
                                 AND length(CAST(not_read_why AS BLOB)) BETWEEN 1 AND 1024)),
    CHECK((last_commit IS NULL) = (last_read_at IS NULL)),
    CHECK((last_commit IS NULL) = (read_from IS NULL)),
    CHECK((not_read IS NULL) = (not_read_why IS NULL))
);

CREATE TABLE shared_follow_typed (
    identity  TEXT NOT NULL CHECK(typeof(identity) = 'text'
                                  AND length(CAST(identity AS BLOB)) BETWEEN 5 AND 300),
    key       BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),
    typed_at  INTEGER NOT NULL CHECK(typeof(typed_at) = 'integer'),
    became    TEXT CHECK(became IS NULL
                         OR (typeof(became) = 'text' AND length(CAST(became AS BLOB)) <= 64)),
    detail    TEXT CHECK(detail IS NULL
                         OR (typeof(detail) = 'text' AND length(CAST(detail AS BLOB)) <= 1024)),
    PRIMARY KEY (identity, key)
);

CREATE TABLE shared_follow_notices (
    identity   TEXT NOT NULL CHECK(typeof(identity) = 'text'
                                   AND length(CAST(identity AS BLOB)) BETWEEN 5 AND 300),
    kind       INTEGER NOT NULL CHECK(kind IN (1, 2, 3)),
    key        BLOB NOT NULL CHECK(typeof(key) = 'blob'
                                   AND ((kind IN (1, 3) AND length(key) = 32)
                                        OR (kind = 2 AND length(key) = 0))),
    label      TEXT CHECK(label IS NULL
                          OR (kind IN (1, 3) AND typeof(label) = 'text'
                              AND length(CAST(label AS BLOB)) BETWEEN 1 AND 32)),
    at_commit  TEXT NOT NULL CHECK(typeof(at_commit) = 'text' AND length(at_commit) IN (40, 64)),
    at         INTEGER NOT NULL CHECK(typeof(at) = 'integer'),
    channel    BLOB CHECK(channel IS NULL
                          OR (typeof(channel) = 'blob' AND length(channel) = 32)),
    CHECK((kind = 1) = (channel IS NOT NULL)),
    PRIMARY KEY (identity, kind, key)
);

INSERT INTO counters (name, value) VALUES ('item_seq', 0);
INSERT INTO counters (name, value) VALUES ('entry_seq', 0);
INSERT INTO counters (name, value) VALUES ('item_count', 0);
INSERT INTO counters (name, value) VALUES ('item_bytes', 0);
INSERT INTO person_clear_mark (one, mark) VALUES (1, randomblob(16));
