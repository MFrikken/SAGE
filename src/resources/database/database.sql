CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY,
    category TEXT,
    name TEXT,
    description TEXT,
    cve TEXT,
    severity TEXT,
    file TEXT,
    start_line INTEGER,
    end_line INTEGER
);

CREATE TABLE weaknesses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    type TEXT,
    name TEXT,
    value TEXT,
    url TEXT,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE
);