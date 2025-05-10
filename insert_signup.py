import sqlite3
from datetime import datetime, timezone, timedelta

conn = sqlite3.connect("TimeZone.db")
c = conn.cursor()

#utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]
utc_dt = "2025-05-05 00:00:00"
c.execute("UPDATE users SET signup = ?", (utc_dt,))

conn.commit()
conn.close()
