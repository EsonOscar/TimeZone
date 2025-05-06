import sqlite3
import datetime

conn = sqlite3.connect("test.db")
cur = conn.cursor()
today = datetime.date.today().isoformat()


cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT       NOT NULL,
            username    TEXT       NOT NULL,
            password    TEXT       NOT NULL,
            email       TEXT,
            role        TEXT       NOT NULL CHECK(role IN ('sysadmin', 'org_admin', 'employee')
            ));
            """)



cur.execute(""" CREATE TABLE IF NOT EXISTS time ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity      TEXT    NOT NULL,
            starttid    TEXT    NOT NULL,
            sluttid     TEXT    NOT NULL,
            totaltid    TEXT    NOT NULL,
            dato        TEXT
            );
            """)

cur.execute(""" CREATE TABLE IF NOT EXISTS machines ( 
                id INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT    NOT NULL,
            type         TEXT    NOT NULL,
            dom          TEXT    NOT NULL,
            dop          TEXT    NOT NULL,
            pp           TEXT    NOT NULL
            );
            """)

cur.execute(""" CREATE TABLE IF NOT EXISTS service ( 
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity          TEXT    NOT NULL,
            dos             TEXT    NOT NULL,
            servicecost     TEXT    NOT NULL
            );
            """)


cur.execute("""INSERT INTO service(entity, dos, servicecost) VALUES (?,?,?) """, ("traktor","3000kr", "17-08-2024",))
cur.execute("""INSERT INTO service(entity, dos, servicecost) VALUES (?,?,?) """, ("motorsav","3000kr", "17-08-2024",))
cur.execute("""INSERT INTO service(entity, dos, servicecost) VALUES (?,?,?) """, ("græsslåsmaskine","3000kr", "17-08-2024",))
cur.execute("""INSERT INTO service(entity, dos, servicecost) VALUES (?,?,?) """, ("dildo","30000kr", "17-08-2024",))

cur.execute("""INSERT INTO machines(name, type, dom, dop, pp) VALUES (?,?,?,?,?) """, ("Lod", "traktor","12-12-1999", "17-08-2010", "20kr"))
cur.execute("""INSERT INTO machines(name, type, dom, dop, pp) VALUES (?,?,?,?,?) """, ("Flemming", "motorsav","8-08-2014", "17-08-2015", "5000kr"))
cur.execute("""INSERT INTO machines(name, type, dom, dop, pp) VALUES (?,?,?,?,?) """, ("Raller", "græsslåmaskine","6-6-2005", "17-08-2023", "10000kr"))
cur.execute("""INSERT INTO machines(name, type, dom, dop, pp) VALUES (?,?,?,?,?) """, ("Jørgen", "dildo","10-10-2025", "17-08-2022", "0.5kr"))

cur.execute("""INSERT INTO time (entity, starttid, sluttid, totaltid, dato) VALUES (?,?,?,?,?) """, ("traktor", "10:45","11:30","45min", today))

cur.execute("""INSERT INTO users (username, password, name, role) VALUES (?,?,?,?) """, ("Mohamed", "1999","Nasib", "sysadmin"))
cur.execute("""INSERT INTO users (username, password, name, role) VALUES (?,?,?,?) """, ("Katrin", "2024","KAKADOODLEDOO","employee"))
cur.execute("""INSERT INTO users (username, password, name, role) VALUES (?,?,?,?) """, ("Oscar", "1940","DADA","employee"))
cur.execute("""INSERT INTO users (username, password, name, role) VALUES (?,?,?,?) """, ("Tobias", "2010","FASANLOVER","employee"))
cur.execute("""SELECT * FROM USERs""")

rows = cur.fetchall()
conn.commit()
conn.close()
print (rows)

