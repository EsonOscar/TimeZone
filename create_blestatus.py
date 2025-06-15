import sqlite3
from time import sleep

conn = sqlite3.connect("TimeZone.db")
c = conn.cursor()

# BLERSTATUS TABLE
c.execute("""CREATE TABLE IF NOT EXISTS blestatus (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT    NOT NULL,
        lifetime    INTEGER NOT NULL DEFAULT 0,
        pct         REAL    NOT NULL DEFAULT 0,
        created_at  TEXT    NOT NULL
        );
        """)