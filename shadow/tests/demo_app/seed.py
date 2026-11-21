import sqlite3

MARKERS = {"MKAAAAAAAAA1": 1, "MKBBBBBBBBB2": 2, "MKCCCCCCCCC3": 3}


def make(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);"
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT);"
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?)", [(1, "Ana MKAAAAAAAAA1", "user"), (2, "Beto MKBBBBBBBBB2", "user"),
                                                          (3, "Caro MKCCCCCCCCC3", "admin")])
    conn.executemany("INSERT INTO items VALUES (?,?,?)", [(1, "usb cable", 10), (2, "O'Brien stout", 12), (12, "hub", 30)])
    conn.executemany("INSERT INTO notes (user_id, body) VALUES (?,?)", [(1, "MKAAAAAAAAA1 a"), (2, "MKBBBBBBBBB2 b")])
    conn.commit()
    conn.close()
