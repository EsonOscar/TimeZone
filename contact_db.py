import sqlite3

conn = sqlite3.connect("TimeZone.db")
c = conn.cursor()

# contact database
c.execute("""CREATE TABLE IF NOT EXISTS contact (
        id          INTEGER PRIMARY KEY AUTOINCREMENT, 
        email       TEXT    NOT NULL,
        message     TEXT    NOT NULL,
        ip          TEXT    NOT NULL,
        timestamp   TEXT    NOT NULL
        );
        """)



