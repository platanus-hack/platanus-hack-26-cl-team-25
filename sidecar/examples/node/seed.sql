-- Shadow seed for the demo apps (loaded into the template database "seed").
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE notes (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL);
INSERT INTO users VALUES (1, 'Ana', 'user'), (2, 'Beto', 'user');
INSERT INTO items VALUES (1, 'usb cable'), (2, 'O''Brien stout'), (3, 'headphones');
INSERT INTO notes (user_id, body) VALUES (1, 'ref MKAAAAAAAAA1 call mom'), (2, 'ref MKBBBBBBBBB2 pay rent');
