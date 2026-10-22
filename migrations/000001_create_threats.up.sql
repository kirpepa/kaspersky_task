CREATE TABLE threats (
    md5 TEXT PRIMARY KEY CHECK (md5 ~ '^[a-f0-9]{32}$'),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'unknown'
        CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical'))
);
