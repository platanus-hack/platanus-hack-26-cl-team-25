import sqlite3

# uid -> marker; team 1 = {1, 2}, team 2 = {3}; uid 4 is the admin, uid 5 is in no team
MARKERS = {"MKGAAAAAAAA1": 1, "MKGBBBBBBBB2": 2, "MKGCCCCCCCC3": 3, "MKGDDDDDDDD4": 4, "MKGEEEEEEEE5": 5}


def make(path):
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT);"
        "CREATE TABLE teams (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE memberships (user_id INTEGER, team_id INTEGER, PRIMARY KEY (user_id, team_id));"
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?)", [(u, "user %s" % m, "admin" if u == 4 else "user")
                                                          for m, u in MARKERS.items()])
    conn.executemany("INSERT INTO teams VALUES (?,?)", [(1, "uno"), (2, "dos")])
    conn.executemany("INSERT INTO memberships VALUES (?,?)", [(1, 1), (2, 1), (3, 2)])
    conn.commit()
    conn.close()
