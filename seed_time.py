from datetime import datetime, timezone, timedelta
import sqlite3

def db_connect():
    conn = sqlite3.connect('TimeZone.db')
    return conn

def seed_data():
    conn = db_connect()

    
    utc_dt = "2025-05-14 13:36:16"
    utc_dt2 = "2025-05-14 15:36:16"

    utc_dt3 = "2025-05-12 13:36:16"
    utc_dt4 = "2025-05-12 15:36:16"

    utc_dt5 = "2025-04-16 13:36:16"
    utc_dt6 = "2025-04-16 15:36:16"

    conn.execute("""INSERT INTO timeentries (user, start_time, end_time)
                   VALUES (?, ?, ?)""", ("Svensker", utc_dt, utc_dt2))
    conn.execute("""INSERT INTO timeentries (user, start_time, end_time)
                   VALUES (?, ?, ?)""", ("Svensker", utc_dt3, utc_dt4))
    conn.execute("""INSERT INTO timeentries (user, start_time, end_time)
                   VALUES (?, ?, ?)""", ("Svensker", utc_dt5, utc_dt6))

    conn.commit()
    conn.close()

seed_data()
