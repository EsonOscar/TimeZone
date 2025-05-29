import sqlite3
from time import sleep
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("TimeZone.db")
c = conn.cursor()

# USERS TABLE
c.execute("""CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT, 
        username    TEXT    NOT NULL UNIQUE,
        password    TEXT    NOT NULL,
        name        TEXT    NOT NULL,
        lastname    TEXT,
        email       TEXT    NOT NULL UNIQUE,
        salary      REAl    DEFAULT 0,
        hourly_rate REAL    DEFAULT 0,
        role        TEXT    NOT NULL CHECK(role IN ('sysadmin', 'org_admin', 'employee'))
        );
        """)

# MACHINES TABLE
# dom = date of manufacture
# dop = date of purchase
# pp = purchase price
c.execute("""CREATE TABLE IF NOT EXISTS machines (
        id          INTEGER PRIMARY KEY AUTOINCREMENT, 
        name        TEXT    NOT NULL UNIQUE,
        type        TEXT    NOT NULL,
        dom         TEXT    NOT NULL,
        dop         TEXT    NOT NULL,
        pp          REAL    NOT NULL
        );
        """)

# TIMEENTRIES TABLE
# start_time and end_time should be in ISO 8601 format (YYYY-MM-DDTHH:MM:SS+00:00)
c.execute("""CREATE TABLE IF NOT EXISTS timeentries_new (
        id          INTEGER PRIMARY KEY AUTOINCREMENT, 
        user        TEXT,
        machine     TEXT,
        start_time  TEXT    NOT NULL,
        end_time    TEXT,
        active      INTEGER GENERATED ALWAYS AS (end_time IS NULL) STORED,
        FOREIGN KEY(user) REFERENCES users(username),
        FOREIGN KEY(machine) REFERENCES machines(name)
        );
        """)

# SERVICE TABLE
# service_date should be in ISO 8601 format (YYYY-MM-DDTHH:MM:SS+00:00)
c.execute("""CREATE TABLE IF NOT EXISTS service (
        id              INTEGER PRIMARY KEY AUTOINCREMENT, 
        machine         TEXT,
        service_date    TEXT    NOT NULL,
        service_cost    REAL    NOT NULL,
        service_type    TEXT,
        service_desc    TEXT,
        FOREIGN KEY(machine) REFERENCES machines(name)
        );
        """)

password_hash = generate_password_hash("GONE")

#c.execute("""INSERT INTO users (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)""",
#("sysadmin", password_hash, "SysAdmin", "sysadmin@hvalfangerne.com", "sysadmin"))

conn.commit()
conn.close()
print("Users, machines, timeentries and service tables created")
#print("SysAdmin user created.")