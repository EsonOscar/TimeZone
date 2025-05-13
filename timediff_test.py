from datetime import datetime, timezone, timedelta
import sqlite3
from time import sleep

utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]

def db_connect():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    return conn, cursor

def create_database_table():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS test_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def insert_data(name, timestamp):
    conn, cursor = db_connect()
    cursor.execute('''
        INSERT INTO test_table (name, timestamp)
        VALUES (?, ?)
        ''', (name, timestamp))
    conn.commit()
    conn.close()

def check_time_difference():
    conn, cursor = db_connect()
    cursor.execute('SELECT * FROM test_table WHERE name = "oscar" AND TIMEDIFF(?, timestamp) > "+0000-00-00 00:40:00" ORDER BY id DESC', (utc_dt,))
    rows = cursor.fetchall()
    
    if not rows:
        print("No rows found with time difference specified.")
        return

    print(f"Rows with time difference greater than 0:\n")

    for row in rows:
        print(f"ID: {row['id']}, Name: {row['name']}, Timestamp: {row['timestamp']}")

    conn.close()

def time_test():
    sleep(4)
    utc_dt2 = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]
    conn, cursor = db_connect()
    diff = conn.execute('SELECT TIMEDIFF(?, ?)', (utc_dt, utc_dt2,)).fetchone()
    print(f"Time difference: {dict(diff)}")

check_time_difference()