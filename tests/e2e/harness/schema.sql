-- Test harness metrics schema.
-- One database per test run, created by the orchestrator.

CREATE TABLE IF NOT EXISTS run (
    run_id      TEXT PRIMARY KEY,
    scenario    TEXT NOT NULL,           -- scenario file path
    started_at  TEXT NOT NULL,           -- ISO 8601
    finished_at TEXT,
    result      TEXT,                    -- pass / fail / timeout
    params      TEXT                     -- JSON: full scenario config
);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,           -- ISO 8601 with ms
    phase       TEXT NOT NULL,           -- startup, mesh, subscribe, publish, delivery, teardown
    node_id     TEXT NOT NULL,           -- container name (e.g. s2-20-r1)
    node_role   TEXT NOT NULL,           -- relay, personal, bootnode
    metric      TEXT NOT NULL,           -- peers_hot, peers_warm, items_stored, etc.
    value       REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    phase       TEXT NOT NULL,
    event_type  TEXT NOT NULL,           -- phase_start, phase_end, publish, subscribe, assertion
    node_id     TEXT,                    -- NULL for global events
    detail      TEXT                     -- JSON: assertion result, error message, etc.
);

CREATE TABLE IF NOT EXISTS assertions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    name        TEXT NOT NULL,
    passed      INTEGER NOT NULL,        -- 1 = pass, 0 = fail
    expected    TEXT,
    actual      TEXT,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_obs_node ON observations(node_id, metric);
CREATE INDEX IF NOT EXISTS idx_obs_phase ON observations(phase, ts);
CREATE INDEX IF NOT EXISTS idx_obs_metric ON observations(metric, ts);
