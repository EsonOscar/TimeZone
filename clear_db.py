import sqlite3
import os

try:
    conn = sqlite3.connect("timelog.db")
    cur = conn.cursor()
except sqlite3.Error as e:
    print(f"Error connecting to database: {e}")

try:
    cur.execute("DROP TABLE IF EXISTS users")
    conn.commit()
    print(f"Database cleared")
    conn.close()
except sqlite3.Error as e:
    print(f"Error removing table: {e}")