"use strict";
// node --test "test/**/*.test.js"  (necesita DATABASE_URL apuntando a una base con el esquema de db/schema.sql)
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { createApp } = require("../src/app");
const db = require("../src/db");

let server;
let base;

before(async () => {
  server = createApp();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await db.pool.end();
});

async function call(method, path, { token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const r = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* not json */ }
  return { status: r.status, text, json, headers: r.headers };
}

async function newUser() {
  const email = `prueba-${crypto.randomBytes(5).toString("hex")}@example.com`;
  const reg = await call("POST", "/api/register", { body: { email, name: "Usuario Prueba", password: "secreta-123" } });
  assert.equal(reg.status, 201);
  const log = await call("POST", "/api/login", { body: { email, password: "secreta-123" } });
  assert.equal(log.status, 200);
  return { id: reg.json.id, token: log.json.token };
}

test("health", async () => {
  const r = await call("GET", "/health");
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { ok: true });
});

test("registro, login y perfil", async () => {
  const u = await newUser();
  const me = await call("GET", "/api/me", { token: u.token });
  assert.equal(me.status, 200);
  assert.equal(me.json.id, u.id);
  assert.equal((await call("GET", "/api/me")).status, 401);
  const bad = await call("POST", "/api/login", { body: { email: "nadie@example.com", password: "x".repeat(10) } });
  assert.equal(bad.status, 401);
});

test("crear, listar, leer, editar y borrar tareas propias", async () => {
  const u = await newUser();
  const c = await call("POST", "/api/tasks", { token: u.token, body: { title: "Comprar pan", notes: "integral", due_date: "2026-12-01" } });
  assert.equal(c.status, 201);
  assert.equal(c.json.title, "Comprar pan");
  const l = await call("GET", "/api/tasks", { token: u.token });
  assert.equal(l.json.tasks.length, 1);
  const g = await call("GET", `/api/tasks/${c.json.id}`, { token: u.token });
  assert.equal(g.json.due_date, "2026-12-01");
  const p = await call("PUT", `/api/tasks/${c.json.id}`, { token: u.token, body: { status: "hecha" } });
  assert.equal(p.json.status, "hecha");
  const other = await newUser();
  assert.equal((await call("GET", `/api/tasks/${c.json.id}`, { token: other.token })).status, 404);
  assert.equal((await call("DELETE", `/api/tasks/${c.json.id}`, { token: u.token })).status, 200);
  assert.equal((await call("GET", `/api/tasks/${c.json.id}`, { token: u.token })).status, 404);
});

test("búsqueda por título y notas", async () => {
  const u = await newUser();
  await call("POST", "/api/tasks", { token: u.token, body: { title: "Llamar al banco", notes: "tarjeta" } });
  await call("POST", "/api/tasks", { token: u.token, body: { title: "Regar plantas", notes: "las del balcón" } });
  const r = await call("GET", "/api/tasks/search?q=banco", { token: u.token });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.tasks.map((t) => t.title), ["Llamar al banco"]);
  const n = await call("GET", "/api/tasks/search?q=balc%C3%B3n", { token: u.token });
  assert.deepEqual(n.json.tasks.map((t) => t.title), ["Regar plantas"]);
  const all = await call("GET", "/api/tasks/search?q=", { token: u.token });
  assert.equal(all.json.tasks.length, 2);
  const st = await call("GET", "/api/tasks/search?status=hecha", { token: u.token });
  assert.equal(st.json.tasks.length, 0);
});

test("archivos: lista y descarga", async () => {
  const u = await newUser();
  const l = await call("GET", "/api/files", { token: u.token });
  assert.ok(l.json.files.includes("guia-rapida.txt"));
  assert.ok(l.json.files.includes("plantillas/semana.csv"));
  const d = await call("GET", "/api/files/download?name=guia-rapida.txt", { token: u.token });
  assert.equal(d.status, 200);
  assert.match(d.text, /Guía rápida/);
  const v = await call("GET", "/api/files/download?name=terminos.v2.1.md", { token: u.token });
  assert.equal(v.status, 200);
  const s = await call("GET", "/api/files/download?name=plantillas/semana.csv", { token: u.token });
  assert.equal(s.status, 200);
  assert.equal((await call("GET", "/api/files/download?name=no-existe.txt", { token: u.token })).status, 404);
  assert.equal((await call("GET", "/api/files/download?name=guia-rapida.txt")).status, 401);
});

test("exportar una tarea propia", async () => {
  const u = await newUser();
  const c = await call("POST", "/api/tasks", { token: u.token, body: { title: "Informe anual", notes: "enviar a contabilidad" } });
  const md = await call("GET", `/api/tasks/${c.json.id}/export`, { token: u.token });
  assert.equal(md.status, 200);
  assert.match(md.text, /^# Informe anual/);
  assert.match(md.text, /enviar a contabilidad/);
  const js = await call("GET", `/api/tasks/${c.json.id}/export?format=json`, { token: u.token });
  assert.equal(js.json.title, "Informe anual");
  assert.equal((await call("GET", "/api/tasks/999999999/export", { token: u.token })).status, 404);
});
