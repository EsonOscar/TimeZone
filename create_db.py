import sqlite3
from time import sleep
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("timelog.db")
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS orgs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT, 
    name        TEXT    UNIQUE NOT NULL
    );
    """)

c.execute("""CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT, 
    name        TEXT    NOT NULL,
    lastname    TEXT, 
    email       TEXT    NOT NULL,
    username    TEXT    NOT NULL, 
    password    TEXT    NOT NULL, 
    role        TEXT    NOT NULL CHECK(role IN ('sysadmin', 'org_admin', 'employee')),
    org_id      INTEGER,
    FOREIGN KEY(org_id) REFERENCES orgs(id)
    );
    """)

password_hash = generate_password_hash("cvnVDMLY!")

c.execute("""INSERT INTO users (name, email, username, password, role) VALUES (?, ?, ?, ?, ?)""",
("SysAdmin", "FindDinFar@hvalfangerne.com", "sysadmin", password_hash, "sysadmin"))

conn.commit()
conn.close()
print("Users and orgs tables created, and initial admin user added.")