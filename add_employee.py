import sqlite3
from time import sleep
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("timelog.db")
c = conn.cursor()

password_hash = generate_password_hash("cvnVDMLY!")

c.execute("""INSERT INTO users (name, email, username, password, role, org_id) VALUES (?, ?, ?, ?, ?, ?)""",
("TestEmployee", "employee@hvalfangerne.com", "TestEmployee", password_hash, "employee", 1))

conn.commit()
conn.close()
print("Test employee added to database")