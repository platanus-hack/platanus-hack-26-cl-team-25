import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from notas.auth import hash_password  # noqa: E402
from notas.db import SCHEMA  # noqa: E402
import sqlite3  # noqa: E402

BASE_TIME = 1735689600

NAMES = [
    "Valentina Muñoz", "Matías González", "Camila Rojas", "Sebastián Pérez",
    "Francisca Soto", "Nicolás Contreras", "Javiera Silva", "Tomás Martínez",
    "Isidora Sepúlveda", "Benjamín Araya", "Constanza Fuentes", "Joaquín Espinoza",
    "Antonia Tapia", "Patricio O'Ryan", "Daniela D'Alessandro", "Cristóbal Núñez",
    "Macarena Vásquez", "Ignacio Carrasco", "Fernanda Bravo", "Andrés O'Higgins",
    "Catalina Peña", "Rodrigo Ibáñez", "Paula Maldonado", "Martín D'Amico",
]

TEAMS = ["Producto", "Ingeniería", "Ventas", "Operaciones"]

TITLES = [
    "Reunión semanal de {t}", "Ideas para el lanzamiento de {t}", "Pendientes de la semana",
    "Revisión del presupuesto", "Feedback de clientes", "Plan de capacitación",
    "Notas de la llamada con D'Alessandro", "Checklist de despliegue", "Minuta del comité",
    "Propuesta de mejora de procesos", "Lista de compras para la oficina", "Reunión con O'Higgins y Cía.",
    "Resumen del trimestre", "Preparación de la demo", "Acuerdos con proveedores",
]

BODIES = [
    "Revisamos los avances y acordamos priorizar las tareas pendientes antes del viernes.",
    "Hay que enviar la cotización actualizada y confirmar la fecha de entrega con el cliente.",
    "Pendiente: coordinar la reunión con el área de operaciones y definir responsables.",
    "El equipo propuso simplificar el flujo de aprobación para reducir los tiempos de espera.",
    "Se detectaron dos incidencias en producción; la solución quedó programada para mañana.",
    "Presupuesto aprobado con ajustes menores. Falta la firma de la gerencia.",
    "Conversamos sobre la estrategia de precios para el próximo año y los descuentos por volumen.",
    "Recordar llamar a la señora Núñez por el contrato y revisar las cláusulas de renovación.",
    "La demo salió bien, aunque el cliente pidió más detalle sobre la integración con su sistema.",
    "Anotar ideas: mejorar la incorporación de usuarios nuevos, simplificar la página de inicio.",
]


def seed_data(conn, seed, n_users=25, n_notes=80):
    rng = random.Random(seed)
    conn.execute(
        "INSERT INTO users (email, name, role, password_hash, phone) VALUES (?, ?, 'admin', ?, ?)",
        ("admin@notas.example", "Administrador Notas", hash_password("admin123"), "+56 9 5550 0001"),
    )
    for i, name in enumerate(NAMES[: n_users - 1]):
        first, last = name.lower().split(" ", 1)
        slug = (first + "." + last).replace("'", "")
        for a, b in zip("áéíóúñ", "aeioun"):
            slug = slug.replace(a, b)
        email = slug.replace(" ", "") + "@notas.example"
        conn.execute(
            "INSERT INTO users (email, name, role, password_hash, phone) VALUES (?, ?, 'member', ?, ?)",
            (email, name, hash_password("notas1234"), "+56 9 5551 %04d" % (i + 2)),
        )
    for t in TEAMS:
        conn.execute("INSERT INTO teams (name) VALUES (?)", (t,))
    members = {}
    for uid in range(1, n_users + 1):
        teams = {(uid % len(TEAMS)) + 1}
        if rng.random() < 0.4:
            teams.add(rng.randint(1, len(TEAMS)))
        members[uid] = sorted(teams)
        for tid in teams:
            conn.execute("INSERT INTO memberships (user_id, team_id) VALUES (?, ?)", (uid, tid))
    for i in range(n_notes):
        owner = rng.randint(1, n_users)
        team = rng.choice(members[owner] + [None])
        title = rng.choice(TITLES).format(t=rng.choice(TEAMS))
        body = " ".join(rng.sample(BODIES, 2))
        conn.execute(
            "INSERT INTO notes (owner_id, team_id, title, body, created_at) VALUES (?, ?, ?, ?, ?)",
            (owner, team, title, body, BASE_TIME + i * 5400),
        )


def main():
    ap = argparse.ArgumentParser(description="Crea la base de datos de Notas con datos de ejemplo")
    ap.add_argument("--db", required=True)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    folder = os.path.dirname(os.path.abspath(args.db))
    os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(args.db)
    conn.executescript(SCHEMA)
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        print("La base ya tiene datos:", args.db)
    else:
        seed_data(conn, args.seed)
        conn.commit()
        print("Base creada:", args.db)
    conn.close()


if __name__ == "__main__":
    main()
