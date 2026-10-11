#!/usr/bin/env python3
"""Mutation checks for the store's side of messages between a person's own
agents: schema step 19 with every table of the record's sections 7 and
9.2, a generation that is its messages channel, the bounds of a number, a
row of the index overwritten before it is dropped in the caller's write,
and SQLite's secure_delete on a personal node's store, from before the
schema's steps, and not on a relay's, with the truncating checkpoint
(decision 2026-10-09 §2.3, §2.5, §6, §7, §9.2). A part for each rule of
the slice: put each fault in, and confirm the test named for it fails on
an assertion. Run from the root of a checkout that nothing else edits."""
import re, subprocess, sys

# One name for each file a part edits.
SCHEMA = 'crates/cordelia-storage/src/schema.rs'
DB = 'crates/cordelia-storage/src/db.rs'
MESSAGES = 'crates/cordelia-storage/src/messages.rs'
MAIN = 'crates/cordelia-node/src/main.rs'
ORIG = {f: open(f).read() for f in (SCHEMA, DB, MESSAGES, MAIN)}

# Where a test lives: (crate, the arguments cargo test needs to find it).
STORAGE = ("cordelia-storage", ["--lib"])
NODE = ("cordelia-node", ["--bin", "cordelia"])
def schema(test): return (STORAGE, "schema::tests::" + test)
def messages(test): return (STORAGE, "messages::tests::" + test)
def db(test): return (STORAGE, "db::tests::" + test)
def node(test): return (NODE, "tests::" + test)

STEP_19 = schema("step_19_adds_its_tables_and_changes_no_older_row")
BEFORE = schema("the_version_before_stops_on_a_database_of_step_19")
ANY = schema("test_a_database_stepped_from_any_version_has_what_every_later_step_makes")
LATER = schema("test_a_database_from_a_later_version_is_refused_and_not_changed")
RELEASED = schema("test_a_database_as_released_is_stepped_no_further_than_the_released_version")
NOTHING_LEFT = messages(
    "a_row_overwritten_and_dropped_leaves_nothing_of_its_text_in_the_file_or_its_log")
OVERWRITTEN = messages("a_dropped_row_is_overwritten_before_it_is_deleted")
SAME_LENGTH = messages("a_dropped_row_is_written_over_with_zeros_of_the_same_length_first")
MARKS_GO = messages("a_dropped_row_leaves_its_marks_as_bare_hashes_and_its_first_holding")
KEPT = messages(
    "a_kept_value_is_of_a_messages_length_and_takes_its_numbers_and_relays_with_it")
SECURE = db("a_store_has_secure_delete_only_where_it_is_set_and_then_in_every_table")
BUSY = db("the_truncating_checkpoint_answers_false_while_a_reader_holds_the_log")
PLACE = schema("a_step_that_rewrites_a_table_writes_zeros_where_the_store_is_opened_so")
NESTS = messages("a_row_is_dropped_inside_a_transaction_or_a_savepoint_of_the_callers")
GENERATIONS = messages("two_channels_under_one_statements_number_are_two_generations")
NUMBER_MAX = messages("no_number_is_above_the_highest_number_of_a_message")
BY_ROLE = node("a_personal_nodes_store_has_secure_delete_on_and_a_relays_has_it_off")
TYPES = schema("step_19s_columns_take_only_their_type_and_their_bound")


def in_table(table, line, new_line):
    """A part's text in step 19's table `table`: the table's head and its
    lines up to `line`, which the fault replaces with `new_line`. So the
    text is found once, though `line` is in several tables."""
    text = ORIG[SCHEMA]
    head = f"CREATE TABLE {table} (\n"
    start = text.index(head, text.index("const MIGRATION_V19"))
    end = text.index(line, start) + len(line)
    assert end <= text.index("\n);", start) + 1, (table, line)
    old = text[start:end]
    return old, old[: -len(line)] + new_line


def part(name, table, line, new_line, tests):
    old, new = in_table(table, line, new_line)
    return (name, SCHEMA, old, new, tests)


# Each part: (a short id and what the fault is, the file, the exact text
# to take out, the exact text to put in its place, the tests that must
# then fail). The text to take out must occur exactly once in the file.
# Two edits in one part: give two lists of the same length.
MUTATIONS = [
    # The step and its version (§9.2).
    ("S01 the schema's version stays at 18", SCHEMA,
     "pub const SCHEMA_VERSION: u32 = 19;", "pub const SCHEMA_VERSION: u32 = 18;",
     [STEP_19]),
    ("S02 step 19 is not run", SCHEMA,
     "    if current < 19 {", "    if current < 19 && false {",
     [STEP_19, ANY, RELEASED]),
    ("S03 step 19 sets the version before", SCHEMA,
     "migrate_in_one(conn, MIGRATION_V19, 19)?;", "migrate_in_one(conn, MIGRATION_V19, 18)?;",
     [STEP_19, ANY]),
    ("S04 a database of a later version is not refused by a schema of 18", SCHEMA,
     "    if found > own {", "    if found > own + 1 {",
     [BEFORE, LATER]),
    ("S05 init_db refuses only above the version after its own", SCHEMA,
     "refuse_a_later_version(conn, SCHEMA_VERSION)?;",
     "refuse_a_later_version(conn, SCHEMA_VERSION + 1)?;",
     [LATER]),
    ("S06 step 19 also changes an older row", SCHEMA,
     "CREATE TABLE message_index (",
     "UPDATE person_left SET number = number + 1;\nCREATE TABLE message_index (",
     [STEP_19]),

    # The generations: a messages channel the device has held (§7.1, §9.2).
    part("G01 a generation takes a channel of any length", "message_generations",
         "    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob' AND length(channel) = 32),",
         "    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob'),", [STEP_19]),
    part("G02 a channel is two generations", "message_generations",
         "    channel     BLOB NOT NULL UNIQUE CHECK(typeof(channel) = 'blob' AND length(channel) = 32),",
         "    channel     BLOB NOT NULL CHECK(typeof(channel) = 'blob' AND length(channel) = 32),",
         [STEP_19, GENERATIONS]),
    part("G03 a generation takes statement 0", "message_generations",
         "    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'\n"
         + " " * 39 + "AND statement >= 1 AND statement <= 256),",
         "    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'\n"
         + " " * 39 + "AND statement <= 256),", [STEP_19]),
    part("G04 a generation takes no statement", "message_generations",
         "    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'\n"
         + " " * 39 + "AND statement >= 1 AND statement <= 256),",
         "    statement   INTEGER CHECK(statement IS NULL OR typeof(statement) = 'integer'\n"
         + " " * 39 + "AND statement >= 1 AND statement <= 256),", [STEP_19]),
    part("G05 a generation takes no time", "message_generations",
         "    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer')",
         "    first_held  INTEGER CHECK(first_held IS NULL OR typeof(first_held) = 'integer')",
         [STEP_19]),
    ("G06 step 19 makes no table of generations", SCHEMA,
     "CREATE TABLE message_generations (", "CREATE TABLE message_generations_not (",
     [STEP_19, GENERATIONS]),
    part("G08 a generation takes a statement that is not an integer", "message_generations",
         "    statement   INTEGER NOT NULL CHECK(typeof(statement) = 'integer'\n"
         + " " * 39 + "AND statement >= 1",
         "    statement   INTEGER NOT NULL CHECK(1\n"
         + " " * 39 + "AND statement >= 1", [TYPES]),
    part("G09 a generation takes a time that is not an integer", "message_generations",
         "    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer')",
         "    first_held  INTEGER NOT NULL", [TYPES]),

    # The index of opened messages (§7.1).
    part("I01 the index takes an ID of any length", "message_index",
         "    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob'),", [STEP_19]),
    part("I02 a second message of one ID is taken over the first", "message_index",
         "    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id               BLOB PRIMARY KEY ON CONFLICT REPLACE\n"
         "                         CHECK(typeof(id) = 'blob' AND length(id) = 16),", [STEP_19]),
    part("I03 the index takes a signer of any length", "message_index",
         "    signer           BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer           BLOB NOT NULL CHECK(typeof(signer) = 'blob'),", [STEP_19]),
    part("I04 the index takes no label", "message_index",
         "    label            TEXT NOT NULL,", "    label            TEXT,", [STEP_19]),
    part("I05 the index takes a generation the device never held", "message_index",
         "    generation       INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation       INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("I06 the index takes a kind of to that is neither", "message_index",
         "    to_kind          INTEGER NOT NULL CHECK(to_kind IN (1, 2)),",
         "    to_kind          INTEGER NOT NULL CHECK(to_kind IN (1, 2, 3)),",
         [STEP_19]),
    part("I07 the index takes a name with every name, or none with one", "message_index",
         "    to_name          TEXT CHECK((to_kind = 1) = (to_name IS NOT NULL)),",
         "    to_name          TEXT,", [STEP_19]),
    part("I08 the index takes no from", "message_index",
         "    from_name        TEXT NOT NULL,", "    from_name        TEXT,", [STEP_19]),
    part("I09 the index takes no sent", "message_index",
         "    sent             INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),",
         "    sent             INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),",
         [STEP_19]),
    part("I10 the index takes no subject", "message_index",
         "    subject          TEXT NOT NULL,", "    subject          TEXT,", [STEP_19]),
    part("I11 the index takes a thread of any length", "message_index",
         "    thread           BLOB NOT NULL CHECK(typeof(thread) = 'blob' AND length(thread) = 16),",
         "    thread           BLOB NOT NULL CHECK(typeof(thread) = 'blob'),", [STEP_19]),
    part("I12 the index takes an answer of any length", "message_index",
         "    answers          BLOB NOT NULL CHECK(typeof(answers) = 'blob' AND length(answers) = 16),",
         "    answers          BLOB NOT NULL CHECK(typeof(answers) = 'blob'),", [STEP_19]),
    part("I13 the index takes a flag that is neither", "message_index",
         "    asks             INTEGER NOT NULL CHECK(asks IN (0, 1)),",
         "    asks             INTEGER NOT NULL,", [STEP_19]),
    part("I14 the index takes no body", "message_index",
         "    body             TEXT NOT NULL,", "    body             TEXT,", [STEP_19]),
    part("I15 the index takes no first holding", "message_index",
         "    first_held       INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),",
         "    first_held       INTEGER CHECK(first_held IS NULL OR typeof(first_held) = 'integer'),",
         [STEP_19]),
    part("I17 the index takes a flag of not every relay that is neither", "message_index",
         "    not_every_relay  INTEGER NOT NULL DEFAULT 0\n"
         "                         CHECK(not_every_relay IN (0, 1))",
         "    not_every_relay  INTEGER NOT NULL DEFAULT 0\n"
         "                         CHECK(1)", [STEP_19]),
    part("I18 a message is said not to have reached every relay from the first", "message_index",
         "    not_every_relay  INTEGER NOT NULL DEFAULT 0\n",
         "    not_every_relay  INTEGER NOT NULL DEFAULT 1\n", [STEP_19]),
    part("I19 the flag of not every relay may be none", "message_index",
         "    not_every_relay  INTEGER NOT NULL DEFAULT 0\n"
         "                         CHECK(not_every_relay IN (0, 1))",
         "    not_every_relay  INTEGER DEFAULT 0\n"
         "                         CHECK(not_every_relay IN (0, 1))",
         [STEP_19]),
    ("I16 the index has no index by signer", SCHEMA,
     "CREATE INDEX idx_message_index_signer ON message_index(signer, generation);\n", "",
     [STEP_19, ANY]),
    part("I20 the index takes an ID that is not a blob", "message_index",
         "    id               BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id               BLOB PRIMARY KEY CHECK(length(id) = 16),", [TYPES]),
    part("I21 the index takes a thread that is not a blob", "message_index",
         "    thread           BLOB NOT NULL CHECK(typeof(thread) = 'blob' AND length(thread) = 16),",
         "    thread           BLOB NOT NULL CHECK(length(thread) = 16),", [TYPES]),
    part("I22 the index takes an answer that is not a blob", "message_index",
         "    answers          BLOB NOT NULL CHECK(typeof(answers) = 'blob' AND length(answers) = 16),",
         "    answers          BLOB NOT NULL CHECK(length(answers) = 16),", [TYPES]),
    part("I23 the index takes a first holding that is not an integer", "message_index",
         "    first_held       INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),",
         "    first_held       INTEGER NOT NULL,", [TYPES]),
    part("I24 the index takes a place that is not an integer", "message_index",
         "    placed_at        INTEGER CHECK(placed_at IS NULL OR typeof(placed_at) = 'integer'),",
         "    placed_at        INTEGER,", [TYPES]),

    # The numbers held (§2.5).
    part("N01 a number held takes a signer of any length", "message_numbers",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob'),", [STEP_19]),
    part("N02 a number held takes a generation the device never held", "message_numbers",
         "    generation  INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation  INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("N03 a number held takes number 0", "message_numbers",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1 AND number <= 4398046511103),",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number <= 4398046511103),", [STEP_19]),
    part("N08 a number held is above the highest number", "message_numbers",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1 AND number <= 4398046511103),",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1),", [NUMBER_MAX]),
    part("N04 a number held names no message of the index", "message_numbers",
         "    id          BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,",
         "    id          BLOB NOT NULL,", [STEP_19, MARKS_GO]),
    part("N05 a number held stays when its message goes", "message_numbers",
         "    id          BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,",
         "    id          BLOB NOT NULL REFERENCES message_index(id),", [MARKS_GO]),
    part("N06 a number is held twice", "message_numbers",
         "    PRIMARY KEY (signer, generation, number)", "    seq INTEGER", [STEP_19]),
    ("N07 the numbers held have no index by ID", SCHEMA,
     "CREATE INDEX idx_message_numbers_id ON message_numbers(id);\n", "",
     [STEP_19, ANY]),
    part("N09 a number held takes a signer that is not a blob", "message_numbers",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(length(signer) = 32),", [TYPES]),
    part("N10 a number held takes a number that is not an integer", "message_numbers",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1",
         "    number      INTEGER NOT NULL CHECK(1\n"
         + " " * 39 + "AND number >= 1", [TYPES]),

    # The rows of first holding (§7.1).
    part("F01 a first holding takes a signer of any length", "message_first_held",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob'),", [STEP_19]),
    part("F02 a first holding takes a generation the device never held", "message_first_held",
         "    generation  INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation  INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("F03 a first holding takes number 0", "message_first_held",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1 AND number <= 4398046511103),",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number <= 4398046511103),", [STEP_19]),
    part("F08 a first holding is above the highest number", "message_first_held",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1 AND number <= 4398046511103),",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1),", [NUMBER_MAX]),
    part("F04 a first holding takes an ID of any length", "message_first_held",
         "    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),",
         "    id          BLOB CHECK(id IS NULL OR typeof(id) = 'blob'),", [STEP_19]),
    part("F05 a first holding goes with its index row", "message_first_held",
         "    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),",
         "    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16))\n"
         "                    REFERENCES message_index(id) ON DELETE CASCADE,",
         [MARKS_GO]),
    part("F06 a first holding takes no time", "message_first_held",
         "    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),",
         "    first_held  INTEGER CHECK(first_held IS NULL OR typeof(first_held) = 'integer'),",
         [STEP_19]),
    part("F07 a number is first held twice", "message_first_held",
         "    PRIMARY KEY (signer, generation, number)", "    CHECK(1)", [STEP_19]),
    part("F09 a first holding has an ID and no sent, or a sent and no ID", "message_first_held",
         "    CHECK((id IS NULL) = (sent IS NULL)),\n", "", [STEP_19]),
    part("F10 a first holding takes an ID that is not a blob", "message_first_held",
         "    id          BLOB CHECK(id IS NULL OR (typeof(id) = 'blob' AND length(id) = 16)),",
         "    id          BLOB CHECK(id IS NULL OR length(id) = 16),", [TYPES]),
    part("F11 a first holding takes a sent that is not an integer", "message_first_held",
         "    sent        INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),",
         "    sent        INTEGER,", [TYPES]),
    part("F12 a first holding takes a signer that is not a blob", "message_first_held",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(length(signer) = 32),", [TYPES]),
    part("F13 a first holding takes a number that is not an integer", "message_first_held",
         "    number      INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 39 + "AND number >= 1",
         "    number      INTEGER NOT NULL CHECK(1\n"
         + " " * 39 + "AND number >= 1", [TYPES]),
    part("F14 a first holding takes a time that is not an integer", "message_first_held",
         "    first_held  INTEGER NOT NULL CHECK(typeof(first_held) = 'integer'),",
         "    first_held  INTEGER NOT NULL,", [TYPES]),

    # H and its counts (§2.5).
    part("H01 H is kept for a signer of any length", "message_signers",
         "    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob'),", [STEP_19]),
    part("H02 H is kept for a generation the device never held", "message_signers",
         "    generation    INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation    INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("H03 H may be below 0", "message_signers",
         "    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'\n"
         + " " * 41 + "AND highest >= 0 AND highest <= 4398046511103),",
         "    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'\n"
         + " " * 41 + "AND highest <= 4398046511103),", [STEP_19]),
    part("H09 H may be above the highest number", "message_signers",
         "    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'\n"
         + " " * 41 + "AND highest >= 0 AND highest <= 4398046511103),",
         "    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'\n"
         + " " * 41 + "AND highest >= 0),", [NUMBER_MAX]),
    part("H10 the first number counted from may be 0", "message_signers",
         "                                    AND counted_from >= 1 AND counted_from <= highest)),",
         "                                    AND counted_from <= highest)),", [STEP_19]),
    part("H12 a number is counted from before one is held", "message_signers",
         "    counted_from  INTEGER CHECK(counted_from IS NULL\n",
         "    counted_from  INTEGER DEFAULT 1 CHECK(counted_from IS NULL\n", [STEP_19]),
    part("H04 the count of overwritten may be below 0", "message_signers",
         "                      CHECK(typeof(overwritten) = 'integer' AND overwritten >= 0),",
         "                      CHECK(typeof(overwritten) = 'integer'),", [STEP_19]),
    part("H05 the count of overwritten starts at nothing", "message_signers",
         "    overwritten   INTEGER NOT NULL DEFAULT 0\n",
         "    overwritten   INTEGER NOT NULL\n", [STEP_19]),
    part("H06 the count of not messages may be below 0", "message_signers",
         "                      CHECK(typeof(not_messages) = 'integer' AND not_messages >= 0),",
         "                      CHECK(typeof(not_messages) = 'integer'),", [STEP_19]),
    part("H07 the count of not messages starts at nothing", "message_signers",
         "    not_messages  INTEGER NOT NULL DEFAULT 0\n",
         "    not_messages  INTEGER NOT NULL\n", [STEP_19]),
    part("H08 a signer has two rows of H in a generation", "message_signers",
         "    PRIMARY KEY (signer, generation)", "    seq INTEGER", [STEP_19]),
    part("H13 H may be a number that is not an integer", "message_signers",
         "    highest       INTEGER NOT NULL CHECK(typeof(highest) = 'integer'\n",
         "    highest       INTEGER NOT NULL CHECK(1\n", [TYPES]),
    part("H14 the count of overwritten may be a text", "message_signers",
         "                      CHECK(typeof(overwritten) = 'integer' AND overwritten >= 0),",
         "                      CHECK(overwritten >= 0),", [TYPES]),
    part("H15 the count of not messages may be a number that is not an integer",
         "message_signers",
         "                      CHECK(typeof(not_messages) = 'integer' AND not_messages >= 0),",
         "                      CHECK(not_messages >= 0),", [TYPES]),
    part("H16 H is kept for a signer that is not a blob", "message_signers",
         "    signer        BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer        BLOB NOT NULL CHECK(length(signer) = 32),", [TYPES]),
    part("H17 the number counted from may be a number that is not an integer",
         "message_signers",
         "                                OR (typeof(counted_from) = 'integer'\n",
         "                                OR (1\n", [TYPES]),

    # The times of the hour's places (§6).
    part("P01 a place is kept for a signer of any length", "message_places",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob'),", [STEP_19]),
    part("P02 a place is kept for a generation the device never held", "message_places",
         "    generation  INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation  INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("P03 a place is kept with no time", "message_places",
         "    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer')",
         "    placed_at   INTEGER CHECK(placed_at IS NULL OR typeof(placed_at) = 'integer')",
         [STEP_19]),
    part("P04 two places at one time are one", "message_places",
         "    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer')",
         "    placed_at   INTEGER NOT NULL CHECK(typeof(placed_at) = 'integer'),\n"
         "    UNIQUE (signer, generation, placed_at)",
         [STEP_19]),
    ("P05 the places have no index", SCHEMA,
     "CREATE INDEX idx_message_places ON message_places(signer, generation, placed_at);\n", "",
     [STEP_19, ANY]),
    part("P06 a place is kept for a signer that is not a blob", "message_places",
         "    signer      BLOB NOT NULL CHECK(typeof(signer) = 'blob' AND length(signer) = 32),",
         "    signer      BLOB NOT NULL CHECK(length(signer) = 32),", [TYPES]),

    # The latest list of each other device (§7.2).
    part("L01 a list is kept for a key of any length", "message_lists",
         "    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),",
         "    key   BLOB NOT NULL CHECK(typeof(key) = 'blob'),", [STEP_19]),
    part("L02 a list holds a mark of any length", "message_lists",
         "    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),",
         "    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob'),", [STEP_19]),
    part("L03 a list holds a mark twice", "message_lists",
         "    PRIMARY KEY (key, mark)", "    seq INTEGER", [STEP_19]),
    ("L04 the lists have no index by mark", SCHEMA,
     "CREATE INDEX idx_message_lists_mark ON message_lists(mark);\n", "",
     [STEP_19, ANY]),
    part("L05 a list is kept for a key that is not a blob", "message_lists",
         "    key   BLOB NOT NULL CHECK(typeof(key) = 'blob' AND length(key) = 32),",
         "    key   BLOB NOT NULL CHECK(length(key) = 32),", [TYPES]),
    part("L06 a list holds a mark that is not a blob", "message_lists",
         "    mark  BLOB NOT NULL CHECK(typeof(mark) = 'blob' AND length(mark) = 16),",
         "    mark  BLOB NOT NULL CHECK(length(mark) = 16),", [TYPES]),

    # The device's own table of marks read by its agents (§7.2).
    part("R01 a mark read here is of any length", "message_read_here",
         "    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),",
         "    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob'),", [STEP_19]),
    part("R02 a mark read here is kept twice", "message_read_here",
         "    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),",
         "    mark       BLOB CHECK(typeof(mark) = 'blob' AND length(mark) = 16),", [STEP_19]),
    part("R03 a mark read here names no message of the index", "message_read_here",
         "    id         BLOB REFERENCES message_index(id),",
         "    id         BLOB,", [STEP_19, OVERWRITTEN]),
    part("R04 a mark read here goes with its message's row, by a cascade", "message_read_here",
         "    id         BLOB REFERENCES message_index(id),",
         "    id         BLOB REFERENCES message_index(id) ON DELETE CASCADE,", [OVERWRITTEN]),
    part("R05 a mark read here takes an empty name", "message_read_here",
         "    name       TEXT CHECK(name IS NULL OR length(name) >= 1),",
         "    name       TEXT,", [STEP_19]),
    part("R06 a mark read here takes no time", "message_read_here",
         "    made_at    INTEGER NOT NULL CHECK(typeof(made_at) = 'integer'),",
         "    made_at    INTEGER CHECK(made_at IS NULL OR typeof(made_at) = 'integer'),",
         [STEP_19]),
    part("R07 a mark read here has an ID with no name", "message_read_here",
         "    CHECK((id IS NULL) = (name IS NULL)),", "", [STEP_19]),
    part("R08 a mark read here is neither a message's nor merged", "message_read_here",
         "    CHECK(id IS NOT NULL OR merged_at IS NOT NULL)",
         "    CHECK(1)", [STEP_19]),
    part("R10 a mark read here has no place in the order", "message_read_here",
         "    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),",
         "    seq        INTEGER UNIQUE CHECK(seq IS NULL OR typeof(seq) = 'integer'),",
         [STEP_19]),
    part("R11 two marks read here have one place in the order", "message_read_here",
         "    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),",
         "    seq        INTEGER NOT NULL CHECK(typeof(seq) = 'integer'),", [STEP_19]),
    ("R09 the marks read here have no index by ID", SCHEMA,
     "CREATE INDEX idx_message_read_here_id ON message_read_here(id);\n", "",
     [STEP_19, ANY]),
    part("R12 a mark read here is not a blob", "message_read_here",
         "    mark       BLOB PRIMARY KEY CHECK(typeof(mark) = 'blob' AND length(mark) = 16),",
         "    mark       BLOB PRIMARY KEY CHECK(length(mark) = 16),", [TYPES]),
    part("R13 a mark read here has a place that is not an integer", "message_read_here",
         "    seq        INTEGER NOT NULL UNIQUE CHECK(typeof(seq) = 'integer'),",
         "    seq        INTEGER NOT NULL UNIQUE,", [TYPES]),
    part("R14 a mark read here was merged at a time that is not an integer",
         "message_read_here",
         "    merged_at  INTEGER CHECK(merged_at IS NULL OR typeof(merged_at) = 'integer'),",
         "    merged_at  INTEGER,", [TYPES]),
    part("R15 a mark read here was made at a time that is not an integer",
         "message_read_here",
         "    made_at    INTEGER NOT NULL CHECK(typeof(made_at) = 'integer'),",
         "    made_at    INTEGER NOT NULL,", [TYPES]),

    # Announced, and read by a person (§7.2).
    part("A01 an announcement names no message of the index", "message_announced",
         "    id    BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,",
         "    id    BLOB NOT NULL,", [STEP_19, MARKS_GO]),
    part("A02 an announcement stays when its message goes", "message_announced",
         "    id    BLOB NOT NULL REFERENCES message_index(id) ON DELETE CASCADE,",
         "    id    BLOB NOT NULL REFERENCES message_index(id),", [MARKS_GO]),
    part("A03 an announcement takes no name or an empty one", "message_announced",
         "    name  TEXT NOT NULL CHECK(length(name) >= 1),", "    name  TEXT,", [STEP_19]),
    part("A04 a message is announced twice to one name", "message_announced",
         "    PRIMARY KEY (id, name)", "    seq INTEGER", [STEP_19]),
    part("B01 a message is read by a person twice", "message_read_by_a_person",
         "    id  BLOB PRIMARY KEY REFERENCES message_index(id) ON DELETE CASCADE",
         "    id  BLOB REFERENCES message_index(id) ON DELETE CASCADE", [STEP_19]),
    part("B02 read by a person names no message of the index", "message_read_by_a_person",
         "    id  BLOB PRIMARY KEY REFERENCES message_index(id) ON DELETE CASCADE",
         "    id  BLOB PRIMARY KEY", [STEP_19, MARKS_GO]),
    part("B03 read by a person stays when its message goes", "message_read_by_a_person",
         "    id  BLOB PRIMARY KEY REFERENCES message_index(id) ON DELETE CASCADE",
         "    id  BLOB PRIMARY KEY REFERENCES message_index(id)", [MARKS_GO]),

    # The sends (§6).
    part("E01 a send takes no time", "message_sends",
         "    sent_at  INTEGER NOT NULL CHECK(typeof(sent_at) = 'integer'),",
         "    sent_at  INTEGER CHECK(sent_at IS NULL OR typeof(sent_at) = 'integer'),", [STEP_19]),
    part("E02 a send takes an empty name", "message_sends",
         "    name     TEXT CHECK(name IS NULL OR length(name) >= 1),",
         "    name     TEXT,", [STEP_19]),
    part("E03 a send to every name is a flag that is neither", "message_sends",
         "    to_all   INTEGER NOT NULL CHECK(to_all IN (0, 1)),",
         "    to_all   INTEGER NOT NULL,", [STEP_19]),
    part("E04 a send again is to every name", "message_sends",
         "    CHECK(name IS NOT NULL OR to_all = 0)", "    CHECK(1)", [STEP_19]),
    ("E05 the sends have no index by time", SCHEMA,
     "CREATE INDEX idx_message_sends_at ON message_sends(sent_at);\n", "",
     [STEP_19, ANY]),
    part("E06 a send takes a time that is not an integer", "message_sends",
         "    sent_at  INTEGER NOT NULL CHECK(typeof(sent_at) = 'integer'),",
         "    sent_at  INTEGER NOT NULL,", [TYPES]),

    # The kept values, their numbers and their relays (§2.3).
    part("K01 a kept value takes an ID of any length", "message_kept",
         "    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob'),", [STEP_19]),
    part("K02 a second value of one ID is taken over the first", "message_kept",
         "    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id          BLOB PRIMARY KEY ON CONFLICT REPLACE\n"
         "                    CHECK(typeof(id) = 'blob' AND length(id) = 16),", [STEP_19]),
    part("K03 a kept value takes a generation the device never held", "message_kept",
         "    generation  INTEGER NOT NULL REFERENCES message_generations(id),",
         "    generation  INTEGER NOT NULL,",
         [STEP_19, GENERATIONS]),
    part("K04 a kept value is of any length", "message_kept",
         "    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),",
         "    value       BLOB NOT NULL CHECK(typeof(value) = 'blob'),", [STEP_19, KEPT]),
    part("K05 a kept value is one byte longer", "message_kept",
         "    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),",
         "    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1937),",
         [STEP_19, KEPT]),
    part("K06 a kept value takes no sent", "message_kept",
         "    sent        INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),",
         "    sent        INTEGER CHECK(sent IS NULL OR typeof(sent) = 'integer'),", [STEP_19]),
    part("K07 a kept value takes no time it was kept", "message_kept",
         "    kept_at     INTEGER NOT NULL CHECK(typeof(kept_at) = 'integer')",
         "    kept_at     INTEGER CHECK(kept_at IS NULL OR typeof(kept_at) = 'integer')",
         [STEP_19]),
    part("K08 a number sent under is of a value not kept", "message_kept_numbers",
         "    id      BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,",
         "    id      BLOB NOT NULL,", [STEP_19, KEPT]),
    part("K09 a number sent under stays when its value goes", "message_kept_numbers",
         "    id      BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,",
         "    id      BLOB NOT NULL REFERENCES message_kept(id),", [KEPT]),
    part("K10 a value is sent under number 0", "message_kept_numbers",
         "    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 35 + "AND number >= 1 AND number <= 4398046511103),",
         "    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 35 + "AND number <= 4398046511103),", [STEP_19]),
    part("K16 a value is sent under a number above the highest", "message_kept_numbers",
         "    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 35 + "AND number >= 1 AND number <= 4398046511103),",
         "    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n"
         + " " * 35 + "AND number >= 1),", [NUMBER_MAX]),
    part("K11 a value is sent under one number twice", "message_kept_numbers",
         "    PRIMARY KEY (id, number)", "    seq INTEGER", [STEP_19]),
    part("K12 a relay took a value not kept", "message_kept_taken",
         "    id     BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,",
         "    id     BLOB NOT NULL,", [STEP_19, KEPT]),
    part("K13 a relay that took it stays when its value goes", "message_kept_taken",
         "    id     BLOB NOT NULL REFERENCES message_kept(id) ON DELETE CASCADE,",
         "    id     BLOB NOT NULL REFERENCES message_kept(id),", [KEPT]),
    part("K14 a relay of any length took it", "message_kept_taken",
         "    relay  BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),",
         "    relay  BLOB NOT NULL CHECK(typeof(relay) = 'blob'),", [STEP_19]),
    part("K15 one relay took it twice", "message_kept_taken",
         "    PRIMARY KEY (id, relay)", "    seq INTEGER", [STEP_19]),
    part("K17 a kept value is not a blob", "message_kept",
         "    value       BLOB NOT NULL CHECK(typeof(value) = 'blob' AND length(value) = 1936),",
         "    value       BLOB NOT NULL CHECK(length(value) = 1936),", [TYPES]),
    part("K18 a relay that is not a blob took it", "message_kept_taken",
         "    relay  BLOB NOT NULL CHECK(typeof(relay) = 'blob' AND length(relay) = 32),",
         "    relay  BLOB NOT NULL CHECK(length(relay) = 32),", [TYPES]),
    part("K19 a kept value takes an ID that is not a blob", "message_kept",
         "    id          BLOB PRIMARY KEY CHECK(typeof(id) = 'blob' AND length(id) = 16),",
         "    id          BLOB PRIMARY KEY CHECK(length(id) = 16),", [TYPES]),
    part("K20 a kept value takes a sent that is not an integer", "message_kept",
         "    sent        INTEGER NOT NULL CHECK(typeof(sent) = 'integer'),",
         "    sent        INTEGER NOT NULL,", [TYPES]),
    part("K21 a kept value takes a time it was kept that is not an integer", "message_kept",
         "    kept_at     INTEGER NOT NULL CHECK(typeof(kept_at) = 'integer')",
         "    kept_at     INTEGER NOT NULL", [TYPES]),
    part("K22 a number sent under is not an integer", "message_kept_numbers",
         "    number  INTEGER NOT NULL CHECK(typeof(number) = 'integer'\n",
         "    number  INTEGER NOT NULL CHECK(1\n", [TYPES]),

    # A row overwritten before it is dropped (§7.1).
    ("D01 the body is not overwritten", MESSAGES,
     "             body = zeroblob(length(CAST(body AS BLOB))),",
     "             body = body,", [OVERWRITTEN, SAME_LENGTH]),
    ("D02 the link is not overwritten", MESSAGES,
     "                         ELSE zeroblob(length(CAST(link AS BLOB))) END,",
     "                         ELSE link END,", [OVERWRITTEN, SAME_LENGTH]),
    ("D03 the subject is not overwritten", MESSAGES,
     "             subject = zeroblob(length(CAST(subject AS BLOB))),",
     "             subject = subject,", [OVERWRITTEN, SAME_LENGTH]),
    ("D04 from is not overwritten", MESSAGES,
     "             from_name = zeroblob(length(CAST(from_name AS BLOB))),",
     "             from_name = from_name,", [OVERWRITTEN, SAME_LENGTH]),
    ("D05 to is not overwritten", MESSAGES,
     "                            ELSE zeroblob(length(CAST(to_name AS BLOB))) END\n",
     "                            ELSE to_name END\n", [OVERWRITTEN, SAME_LENGTH]),
    ("D06 a field is overwritten with a byte fewer", MESSAGES,
     "             body = zeroblob(length(CAST(body AS BLOB))),",
     "             body = zeroblob(length(CAST(body AS BLOB)) - 1),", [SAME_LENGTH]),
    ("D07 the row is not deleted", MESSAGES,
     'let dropped = conn.execute("DELETE FROM message_index WHERE id = ?1"',
     'let dropped = conn.execute("DELETE FROM message_index WHERE 0 AND id = ?1"',
     [NOTHING_LEFT, MARKS_GO]),
    ("D08 a row is said dropped where none was held", MESSAGES,
     "    Ok(dropped == 1)", "    Ok(true)", [MARKS_GO]),
    ("D09 the savepoint is not kept", MESSAGES,
     '        Ok(_) => "RELEASE drop_row",',
     '        Ok(_) => "ROLLBACK TO drop_row; RELEASE drop_row",', [NOTHING_LEFT, MARKS_GO]),
    ("D10 every row is overwritten, not the one dropped", MESSAGES,
     "(to_name AS BLOB))) END\n         WHERE id = ?1\",",
     "(to_name AS BLOB))) END\n         WHERE id = ?1 OR 1\",",
     [OVERWRITTEN]),
    ("D11 a message with no link has one of no bytes once overwritten", MESSAGES,
     "             link = CASE WHEN link IS NULL THEN NULL",
     "             link = CASE WHEN 0 THEN NULL", [SAME_LENGTH]),
    ("D12 a message to every name has a to of no bytes once overwritten", MESSAGES,
     "             to_name = CASE WHEN to_name IS NULL THEN NULL",
     "             to_name = CASE WHEN 0 THEN NULL", [SAME_LENGTH]),
    ("D13 drop_row opens a transaction of its own, and cannot nest", MESSAGES,
     '''    conn.execute_batch("SAVEPOINT drop_row")?;
    let dropped = overwritten_and_deleted(conn, id, now);
    let end = match dropped {
        Ok(_) => "RELEASE drop_row",
        Err(_) => "ROLLBACK TO drop_row; RELEASE drop_row",
    };
    conn.execute_batch(end)?;
    dropped''',
     '''    let tx = conn.unchecked_transaction()?;
    let dropped = overwritten_and_deleted(&tx, id, now)?;
    tx.commit()?;
    Ok(dropped)''', [NESTS]),

    # secure_delete and the truncating checkpoint (§7.1).
    ("Z01 secure_delete is set off", DB,
     'conn.pragma_update(None, "secure_delete", true)?;',
     'conn.pragma_update(None, "secure_delete", false)?;', [SECURE, BY_ROLE]),
    ("Z02 the checkpoint does not truncate the log", DB,
     '"PRAGMA wal_checkpoint(TRUNCATE)"', '"PRAGMA wal_checkpoint(PASSIVE)"',
     [NOTHING_LEFT, SECURE]),
    ("Z03 the checkpoint says it was whole where it was not", DB,
     "    Ok(busy == 0)", "    Ok(busy != 0)", [NOTHING_LEFT, SECURE, BUSY]),
    ("Z09 the checkpoint says it was whole whatever it found", DB,
     "    Ok(busy == 0)", "    Ok(true)", [BUSY]),
    ("Z04 the schema's steps set secure_delete, so a relay's store has it", SCHEMA,
     '         PRAGMA foreign_keys = ON;",',
     '         PRAGMA foreign_keys = ON;\n         PRAGMA secure_delete = ON;",',
     [SECURE, BY_ROLE]),
    ("Z05 a node of every role keeps secure_delete", MAIN,
     'fn keeps_secure_delete(role: &str) -> bool {\n    role == "personal"',
     'fn keeps_secure_delete(role: &str) -> bool {\n    role != ""',
     [BY_ROLE]),
    ("Z06 a command's store is opened without it", MAIN,
     "db::open_as(db_path, keeps_secure_delete(&config.network.role))",
     "db::open_as(db_path, false)",
     [BY_ROLE]),
    ("Z07 the node's store is opened without it", MAIN,
     "    match cordelia_storage::db::open_as(db_path, secure_delete) {",
     "    match cordelia_storage::db::open_as(db_path, false) {", [BY_ROLE]),
    ("Z08 a relay starts over a database of a later version", MAIN,
     '            if role != "personal" {\n                anyhow::bail!("{why}");',
     '            if false {\n                anyhow::bail!("{why}");', [BY_ROLE]),
    ("Z10 the store in memory over a later version is held without it", MAIN,
     "            if secure_delete {\n                cordelia_storage::db::secure_delete_on(&conn)?;",
     "            if false {\n                cordelia_storage::db::secure_delete_on(&conn)?;",
     [BY_ROLE]),
    ("Z11 secure_delete is set after the schema's steps have run", DB,
     "    if secure_delete {\n        secure_delete_on(&conn)?;\n    }\n    schema::init_db(&conn)?;",
     "    schema::init_db(&conn)?;\n    if secure_delete {\n        secure_delete_on(&conn)?;\n    }",
     [PLACE]),
    ("Z12 a store opened so does not have it", DB,
     "    if secure_delete {\n        secure_delete_on(&conn)?;\n    }\n    schema::init_db(&conn)?;",
     "    schema::init_db(&conn)?;", [PLACE, BY_ROLE]),
]
# Rules of the slice that no test can tell, each with why. Leave it
# empty unless the record itself says the rule cannot be tested.
UNTOLD = []

def edits(a, b):
    return list(zip(a, b)) if isinstance(a, list) else [(a, b)]

TEST_MAX_SECS = 1500
BASELINE_TRIES = 3

def run(where, test):
    import os, signal
    crate, args = where
    p = subprocess.Popen(["cargo", "test", "-p", crate, *args, test, "--", "--exact"],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=TEST_MAX_SECS)
        return out
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return (out or "") + "\ntest result: FAILED. 0 passed; 1 failed; THE TEST DID NOT END\n"

def verdict_of(text):
    if "error: could not compile" in text or "error[" in text:
        return "DID NOT COMPILE"
    if re.search(r"test result: FAILED\. \d+ passed; [1-9]\d* failed", text):
        return "detected (test failed)"
    passed = re.findall(r"test result: ok\. (\d+) passed", text)
    if passed and any(int(n) >= 1 for n in passed):
        return "NOT DETECTED (test passed)"
    return "NO TEST RAN"

if "--list" in sys.argv:
    print(" ".join(m[0].split()[0] for m in MUTATIONS))
    sys.exit(0)
if "--check" in sys.argv:
    bad = [(name, ORIG[f].count(old)) for name, f, a, b, tests in MUTATIONS
           for old, _ in edits(a, b) if ORIG[f].count(old) != 1]
    names = [m[0].split()[0] for m in MUTATIONS]
    twice = sorted({n for n in names if names.count(n) > 1})
    print(len(MUTATIONS), "mutations;", "all found once" if not bad else bad,
          "" if not twice else f"named twice: {twice}",
          "" if not UNTOLD else f"{len(UNTOLD)} that no test tells: {[u.split()[0] for u in UNTOLD]}")
    sys.exit(1 if bad or twice or UNTOLD else 0)
only = {a for a in sys.argv[1:] if not a.startswith("--")}
MUTATIONS = [m for m in MUTATIONS if m[4] and (not only or m[0].split()[0] in only)]
seen = set()
for _, _, _, _, tests in MUTATIONS:
    for where, test in tests:
        if test in seen:
            continue
        seen.add(test)
        tries = 0
        while True:
            tries += 1
            text = run(where, test)
            v = verdict_of(text)
            if v.startswith('NOT DETECTED') or tries == BASELINE_TRIES:
                break
            why = next((l.strip()[:200] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"baseline-try | {test} | try {tries} did not pass | {why}", flush=True)
        print(f"baseline | {test} | {'passes' if v.startswith('NOT DETECTED') else 'DOES NOT PASS: ' + v}", flush=True)
        if not v.startswith('NOT DETECTED'):
            sys.exit(1)
try:
    for name, f, a, b, tests in MUTATIONS:
        mutated = ORIG[f]
        for old, new in edits(a, b):
            assert mutated.count(old) == 1, (name, mutated.count(old))
            mutated = mutated.replace(old, new)
        open(f, 'w').write(mutated)
        for where, test in tests:
            text = run(where, test)
            v = verdict_of(text)
            if v in ("DID NOT COMPILE", "NO TEST RAN"):
                print(text[-1500:])
            why = next((l.strip()[:150] for l in text.splitlines()
                        if "panicked at" in l or "timed out" in l), "")
            print(f"{name} | {test} | {v} | {why}", flush=True)
        open(f, 'w').write(ORIG[f])
finally:
    for f, text in ORIG.items():
        open(f, 'w').write(text)
