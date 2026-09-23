CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
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

CREATE TABLE IF NOT EXISTS snapshot (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    body       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);
