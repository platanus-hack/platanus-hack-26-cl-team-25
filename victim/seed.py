"""Build the prod and shadow databases, the manifest and the markers file."""
import argparse
import hashlib
import json
import os
import random
import sqlite3
import string
import time

SEED_MAX_UID = 60
SEED_MAX_ORDER_ID = 240
ADMIN_ID = 1
LEGIT_IDS = [2, 3, 4, 5, 6, 8, 9, 10]
CANARY_USERS = [7, 19]
CANARY_ORDERS = {12: 7, 31: 19}

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
);
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price INTEGER NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL,
    total INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    shipping_address TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    qty INTEGER NOT NULL,
    unit_price INTEGER NOT NULL
);
CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_items_order ON order_items(order_id);
"""

FIRST = ["Ana", "Beto", "Carla", "Diego", "Elena", "Felipe", "Gabriela", "Hugo", "Ines", "Javier",
         "Karen", "Luis", "Marta", "Nicolas", "Olga", "Pablo", "Quena", "Rodrigo", "Sofia", "Tomas"]
LAST = ["Rojas", "Soto", "Munoz", "Diaz", "Perez", "Silva", "Reyes", "Vega", "Lagos", "Pinto",
        "Fuentes", "Araya", "Tapia", "Bravo", "Mora", "Cortes", "Nunez", "Rios", "Campos", "Vidal"]
STREETS = ["Av. Providencia", "Calle Las Rosas", "Pasaje Los Alerces", "Av. Apoquindo", "Calle Bandera",
           "Av. Matta", "Calle Ahumada", "Pasaje El Roble", "Av. Vicuna Mackenna", "Calle Maipu"]
COMMUNES = ["Santiago", "Providencia", "Nunoa", "Las Condes", "Maipu", "La Florida", "Valparaiso", "Concepcion"]
NOTES = ["", "", "", "Dejar con el conserje", "Llamar antes de llegar", "It's a gift", "Entregar despues de las 18h",
         "Regalo de cumpleanos", "Cliente frecuente, no doblar la caja", "Don't ring the bell, baby sleeping",
         "Fragil", "Factura a nombre de la empresa"]
STATUSES = ["new", "paid", "shipped", "delivered", "delivered", "delivered", "cancelled"]

CATALOG = {
    "audio": ["Audifonos Bluetooth", "Audifonos In-Ear", "Parlante Portatil", "Microfono USB", "Barra de Sonido",
              "Audifonos Gamer", "Adaptador Bluetooth", "Parlante de Escritorio", "Microfono de Solapa", "Audifonos Studio"],
    "cables": ["Cable USB-C 1m", "Cable USB-C 2m", "Cable HDMI 2.1", "Cable Lightning", "Cable Ethernet Cat6",
               "Cable DisplayPort", "Cable Micro USB", "Extension USB 3.0", "Cable Auxiliar 3.5mm", "Cable de Poder C13"],
    "storage": ["SSD 500GB", "SSD 1TB", "Disco Externo 2TB", "Pendrive 64GB", "Pendrive 128GB",
                "Tarjeta microSD 256GB", "SSD NVMe 1TB", "Disco Externo 5TB", "Carcasa para SSD", "Lector de Tarjetas"],
    "accessories": ["Hub USB 4 puertos", "Soporte para Notebook", "Mouse Inalambrico", "Teclado Mecanico", "Mousepad XL",
                    "Cargador 65W", "Webcam Full HD", "Protector de Pantalla", "Base Refrigerante", "Organizador de Cables"],
}
BLURBS = ["Ideal para el trabajo diario.", "Garantia de 12 meses.", "Compatible con la mayoria de los equipos.",
          "Diseno compacto y liviano.", "Excelente relacion precio calidad.", "Stock limitado."]

BASE_TS = 1735689600  # 2025-01-01T00:00:00Z


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_markers(rng, uids):
    alphabet = string.ascii_uppercase + string.digits
    out = {}
    seen = set()
    for uid in uids:
        while True:
            mk = "MK" + "".join(rng.choice(alphabet) for _ in range(10))
            if mk not in seen:
                seen.add(mk)
                break
        out[uid] = mk
    return out


def build_world(seed):
    rng = random.Random(seed)
    users = []
    legit = []
    for uid in range(1, SEED_MAX_UID + 1):
        first = FIRST[rng.randrange(len(FIRST))]
        last = LAST[rng.randrange(len(LAST))]
        u = {
            "id": uid, "first": first, "last": last,
            "role": "admin" if uid == ADMIN_ID else "user",
            "street": "%s %d" % (STREETS[rng.randrange(len(STREETS))], rng.randrange(10, 2999)),
            "commune": COMMUNES[rng.randrange(len(COMMUNES))],
            "phone": "+56 9 %04d %04d" % (rng.randrange(10000), rng.randrange(10000)),
        }
        if uid == ADMIN_ID:
            u["email"] = "admin@tienda.example"
            u["password"] = "Adm1n-seed-%d" % rng.randrange(1000, 9999)
        elif uid in LEGIT_IDS:
            u["email"] = "%s.%s%d@tienda.example" % (first.lower(), last.lower(), uid)
            u["password"] = "%s-clave-%d" % (first.lower(), rng.randrange(1000, 9999))
            legit.append(u)
        else:
            u["email"] = "%s.%s%d@tienda.example" % (first.lower(), last.lower(), uid)
            u["password"] = "pw-%d-%d" % (uid, rng.randrange(100000, 999999))
        users.append(u)

    products = []
    pid = 0
    for cat, names in CATALOG.items():
        for name in names:
            pid += 1
            products.append({
                "id": pid, "name": name, "category": cat,
                "price": rng.randrange(30, 600) * 100 - 10,
                "description": "%s %s" % (name, BLURBS[rng.randrange(len(BLURBS))]),
            })

    pool = [u["id"] for u in users if u["id"] not in CANARY_USERS]
    orders = []
    for oid in range(1, SEED_MAX_ORDER_ID + 1):
        owner = CANARY_ORDERS.get(oid)
        if owner is None:
            owner = LEGIT_IDS[(oid - 1) % len(LEGIT_IDS)] if oid <= 24 else pool[rng.randrange(len(pool))]
        items = []
        for _ in range(rng.randrange(1, 4)):
            p = products[rng.randrange(len(products))]
            items.append({"product_id": p["id"], "qty": rng.randrange(1, 5), "unit_price": p["price"]})
        orders.append({
            "id": oid, "user_id": owner,
            "status": STATUSES[rng.randrange(len(STATUSES))],
            "total": sum(i["qty"] * i["unit_price"] for i in items),
            "note": NOTES[rng.randrange(len(NOTES))],
            "created_at": iso(BASE_TS + oid * 3600 * 7),
            "items": items,
        })
    markers = make_markers(rng, [u["id"] for u in users])
    return users, products, orders, markers, legit


def write_db(path, users, products, orders, markers, shadow):
    if os.path.exists(path):
        os.remove(path)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    for u in users:
        mk = markers[u["id"]] if shadow else None
        name = "%s %s" % (u["first"], u["last"])
        email = u["email"]
        address = "%s, %s" % (u["street"], u["commune"])
        phone = u["phone"]
        if shadow:
            name = "%s %s %s" % (u["first"], mk, u["last"])
            email = "%s.%s@tienda.example" % (u["first"].lower(), mk)
            address = "%s, %s Apt %s" % (u["street"], u["commune"], mk)
            phone = "%s x%s" % (u["phone"], mk)
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, address, phone, role, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (u["id"], email, sha(u["password"]), name, address, phone, u["role"], iso(BASE_TS - 86400 * u["id"])),
        )
    for p in products:
        conn.execute("INSERT INTO products (id, name, category, price, description) VALUES (?,?,?,?,?)",
                     (p["id"], p["name"], p["category"], p["price"], p["description"]))
    by_id = {u["id"]: u for u in users}
    for o in orders:
        owner = by_id[o["user_id"]]
        note = o["note"]
        address = "%s, %s" % (owner["street"], owner["commune"])
        if shadow:
            mk = markers[o["user_id"]]
            note = ("%s (%s)" % (note, mk)) if note else "Ref %s" % mk
            address = "%s, %s Apt %s" % (owner["street"], owner["commune"], mk)
        conn.execute(
            "INSERT INTO orders (id, user_id, status, total, note, shipping_address, created_at) VALUES (?,?,?,?,?,?,?)",
            (o["id"], o["user_id"], o["status"], o["total"], note, address, o["created_at"]),
        )
        for it in o["items"]:
            conn.execute("INSERT INTO order_items (order_id, product_id, qty, unit_price) VALUES (?,?,?,?)",
                         (o["id"], it["product_id"], it["qty"], it["unit_price"]))
    conn.commit()
    conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-prod", required=True)
    ap.add_argument("--out-shadow", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--markers", required=True)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    users, products, orders, markers, legit = build_world(a.seed)
    write_db(a.out_prod, users, products, orders, markers, shadow=False)
    write_db(a.out_shadow, users, products, orders, markers, shadow=True)
    admin = users[0]
    manifest = {
        "seed_max_uid": SEED_MAX_UID,
        "seed_max_order_id": SEED_MAX_ORDER_ID,
        "legit_users": [{"id": u["id"], "email": u["email"], "password": u["password"], "role": "user"} for u in legit],
        "admin": {"id": admin["id"], "email": admin["email"], "password": admin["password"]},
        "canaries": {"user_id": list(CANARY_USERS), "order_id": sorted(CANARY_ORDERS)},
        "ownership": {"orders": {str(o["id"]): o["user_id"] for o in orders}},
    }
    with open(a.manifest, "w") as f:
        json.dump(manifest, f, indent=1)
    with open(a.markers, "w") as f:
        json.dump({mk: uid for uid, mk in markers.items()}, f, indent=1)


if __name__ == "__main__":
    main()
