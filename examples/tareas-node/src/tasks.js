"use strict";
const db = require("./db");
const { HttpError } = require("./http");

const STATUSES = ["pendiente", "en_curso", "hecha"];
const COLUMNS = "id, title, notes, status, due_date, created_at";

function toDate(d) {
  if (!d) return null;
  const s = d instanceof Date ? d.toISOString() : String(d);
  return s.slice(0, 10);
}

function present(row) {
  return {
    id: row.id,
    title: row.title,
    notes: row.notes,
    status: row.status,
    due_date: toDate(row.due_date),
    created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
  };
}

function validate(body, partial) {
  const out = {};
  if (!partial || body.title !== undefined) {
    const title = String(body.title || "").trim();
    if (!title || title.length > 200) throw new HttpError(400, "título inválido");
    out.title = title;
  }
  if (body.notes !== undefined) {
    const notes = String(body.notes);
    if (notes.length > 4000) throw new HttpError(400, "notas demasiado largas");
    out.notes = notes;
  }
  if (body.status !== undefined) {
    if (!STATUSES.includes(body.status)) throw new HttpError(400, "estado inválido");
    out.status = body.status;
  }
  if (body.due_date !== undefined) {
    if (body.due_date !== null && !/^\d{4}-\d{2}-\d{2}$/.test(String(body.due_date))) {
      throw new HttpError(400, "fecha inválida (AAAA-MM-DD)");
    }
    out.due_date = body.due_date;
  }
  return out;
}

async function list(user) {
  const r = await db.query(
    `SELECT ${COLUMNS} FROM tasks WHERE user_id = $1 ORDER BY due_date NULLS LAST, id`,
    [user.id]
  );
  return r.rows.map(present);
}

async function create(user, body) {
  const t = validate(body, false);
  const r = await db.query(
    `INSERT INTO tasks (user_id, title, notes, status, due_date) VALUES ($1, $2, $3, $4, $5) RETURNING ${COLUMNS}`,
    [user.id, t.title, t.notes || "", t.status || "pendiente", t.due_date || null]
  );
  return present(r.rows[0]);
}

async function get(user, id) {
  const r = await db.query(`SELECT ${COLUMNS} FROM tasks WHERE id = $1 AND user_id = $2`, [id, user.id]);
  if (!r.rows.length) throw new HttpError(404, "tarea no encontrada");
  return present(r.rows[0]);
}

async function update(user, id, body) {
  const t = validate(body, true);
  const keys = Object.keys(t);
  if (!keys.length) return get(user, id);
  const sets = keys.map((k, i) => `${k} = $${i + 3}`).join(", ");
  const r = await db.query(
    `UPDATE tasks SET ${sets} WHERE id = $1 AND user_id = $2 RETURNING ${COLUMNS}`,
    [id, user.id, ...keys.map((k) => t[k])]
  );
  if (!r.rows.length) throw new HttpError(404, "tarea no encontrada");
  return present(r.rows[0]);
}

async function remove(user, id) {
  const r = await db.query("DELETE FROM tasks WHERE id = $1 AND user_id = $2", [id, user.id]);
  if (!r.rowCount) throw new HttpError(404, "tarea no encontrada");
}

async function search(user, q, status) {
  let sql = "SELECT id, title, status, due_date FROM tasks WHERE user_id = " + user.id;
  const term = String(q || "").trim();
  if (term) {
    sql += " AND (title ILIKE '%" + term + "%' OR notes ILIKE '%" + term + "%')";
  }
  if (status && STATUSES.includes(status)) {
    sql += " AND status = '" + status + "'";
  }
  sql += " ORDER BY due_date NULLS LAST, id LIMIT 50";
  const r = await db.query(sql);
  return r.rows.map((row) => ({ id: row.id, title: row.title, status: row.status, due_date: toDate(row.due_date) }));
}

module.exports = { list, create, get, update, remove, search, toDate };
