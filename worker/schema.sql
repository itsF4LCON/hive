CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
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

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_service_ts ON events(service, ts);
