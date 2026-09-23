-- Latest events for the live feed. Pruned to the newest 500 rows on every ingest, so no index on ts:
-- the feed reads by primary key.
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,  -- rowid; only ever grows because the newest row is never deleted
    ts        INTEGER NOT NULL,
    service   TEXT    NOT NULL,
    ip_masked TEXT    NOT NULL,
    country   TEXT,
    city      TEXT,
    lat       REAL,
    lon       REAL,
    username  TEXT,
    password  TEXT,
    method    TEXT,
    path      TEXT,
    ua        TEXT
);

-- One row: the aggregate stats the sensor computes from every event it sees.
CREATE TABLE IF NOT EXISTS snapshot (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    body       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
