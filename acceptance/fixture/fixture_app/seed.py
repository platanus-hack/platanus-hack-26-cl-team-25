"""Create the fixture databases. make(path, shadow) -> None ; MARKERS = {marker: owner}"""
import sqlite3

MARKERS = {"MKAAAAAAAAA1": 1, "MKBBBBBBBBB2": 2}
SEED_MAX_UID = 2


def make(path: str, shadow: bool) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);"
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT);"
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?)", [(1, "Ana", "user"), (2, "Beto", "user")])
    conn.executemany("INSERT INTO items VALUES (?,?)", [(1, "usb cable"), (2, "O'Brien stout"), (3, "headphones")])
    bodies = [(1, "ref MKAAAAAAAAA1 call mom"), (2, "ref MKBBBBBBBBB2 pay rent")] if shadow else [(1, "real note of ana"), (2, "real note of beto")]
    conn.executemany("INSERT INTO notes (user_id, body) VALUES (?,?)", bodies)
    conn.commit()
    conn.close()
