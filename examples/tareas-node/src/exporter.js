"use strict";
const db = require("./db");
const { HttpError } = require("./http");
const { toDate } = require("./tasks");

const LABELS = { pendiente: "Pendiente", en_curso: "En curso", hecha: "Hecha" };

async function load(id) {
  const r = await db.query(
    "SELECT t.id, t.title, t.notes, t.status, t.due_date, t.created_at, u.name AS owner_name " +
      "FROM tasks t JOIN users u ON u.id = t.user_id WHERE t.id = $1",
    [id]
  );
  if (!r.rows.length) throw new HttpError(404, "tarea no encontrada");
  return r.rows[0];
}

function markdown(t) {
  const lines = [
    `# ${t.title}`,
    "",
    `- Estado: ${LABELS[t.status] || t.status}`,
    `- Vence: ${toDate(t.due_date) || "sin fecha"}`,
    `- Responsable: ${t.owner_name}`,
    `- Creada: ${t.created_at instanceof Date ? t.created_at.toISOString() : t.created_at}`,
    "",
    "## Notas",
    "",
    t.notes || "_(sin notas)_",
    "",
  ];
  return lines.join("\n");
}

async function exportTask(user, id, format) {
  const t = await load(id);
  if (format === "json") {
    return {
      type: "application/json; charset=utf-8",
      body: JSON.stringify({
        id: t.id, title: t.title, notes: t.notes, status: t.status, due_date: toDate(t.due_date),
        owner: t.owner_name,
      }),
    };
  }
  return { type: "text/markdown; charset=utf-8", body: markdown(t) };
}

module.exports = { exportTask };
