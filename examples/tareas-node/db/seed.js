"use strict";
// Datos de ejemplo: node db/seed.js  (usa DATABASE_URL; crea el esquema si falta)
const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");
const { hashPassword } = require("../src/auth");

const PEOPLE = [
  ["Carolina Fuentes", "carolina.fuentes@correo.cl", "admin"],
  ["Matías Rojas", "matias.rojas@correo.cl", "user"],
  ["Javiera Muñoz", "javiera.munoz@correo.cl", "user"],
  ["Diego Contreras", "diego.contreras@correo.cl", "user"],
  ["Francisca Soto", "francisca.soto@correo.cl", "user"],
  ["Tomás Silva", "tomas.silva@correo.cl", "user"],
  ["Valentina Pérez", "valentina.perez@correo.cl", "user"],
  ["Benjamín Morales", "benjamin.morales@correo.cl", "user"],
  ["Catalina Araya", "catalina.araya@correo.cl", "user"],
  ["Sebastián Torres", "sebastian.torres@correo.cl", "user"],
];

const TASKS = [
  ["Pagar arriendo de diciembre", "Transferir a la cuenta de la dueña, depto 402 de Av. Grecia 1180", "pendiente", "2026-12-05"],
  ["Renovar licencia de conducir", "Pedir hora en la municipalidad, llevar certificado de antecedentes", "en_curso", "2026-12-15"],
  ["Comprar regalo para la mamá", "Le gustan los libros de Isabel Allende; presupuesto 25 mil", "pendiente", "2026-12-20"],
  ["Revisar informe trimestral", "Comentarios de la gerencia sobre ventas de la zona sur", "hecha", "2026-11-10"],
  ["Llamar al dentista", "Control anual, teléfono de la consulta +56 2 2345 6789", "pendiente", null],
  ["Preparar presentación del proyecto", "Diapositivas con los resultados del piloto en Valparaíso", "en_curso", "2026-11-28"],
  ["Cambiar aceite del auto", "Taller de calle Lira, preguntar por la revisión técnica", "pendiente", "2027-01-08"],
  ["Inscribir a los niños en natación", "Piscina municipal de Ñuñoa, horario de la tarde", "hecha", "2026-10-30"],
];

async function main() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  try {
    await pool.query(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8"));
    const existing = await pool.query("SELECT count(*)::int AS n FROM users");
    if (existing.rows[0].n > 0) {
      console.log("la base ya tiene usuarios; no se cargan datos de ejemplo");
      return;
    }
    let day = 0;
    for (let i = 0; i < PEOPLE.length; i++) {
      const [name, email, role] = PEOPLE[i];
      const created = new Date(Date.UTC(2026, 5, 1 + i, 9, 0, 0)).toISOString();
      const u = await pool.query(
        "INSERT INTO users (email, name, password_hash, role, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        [email, name, hashPassword(`tareas-demo-${i + 1}`), role, created]
      );
      const uid = u.rows[0].id;
      for (let k = 0; k < 5; k++) {
        const [title, notes, status, due] = TASKS[(i * 3 + k) % TASKS.length];
        day += 1;
        const at = new Date(Date.UTC(2026, 6, 1, 8, 0, 0) + day * 3600 * 1000 * 7).toISOString();
        await pool.query(
          "INSERT INTO tasks (user_id, title, notes, status, due_date, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
          [uid, title, `${notes}. (${name.split(" ")[0]})`, status, due, at]
        );
      }
    }
    console.log(`cargados ${PEOPLE.length} usuarios y ${PEOPLE.length * 5} tareas`);
  } finally {
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
