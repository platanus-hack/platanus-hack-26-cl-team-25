// Demo app that exists only to test the sidecar observer. Deliberately vulnerable routes are
// paired with safe ones. Plain `http` module + vendored `pg` (node_modules/, see README).
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFile } = require("child_process");
const { Pool } = require("pg");

const PORT = parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "127.0.0.1";
const STATIC = process.env.APP_STATIC || path.join(__dirname, "static");
const SECRET = process.env.APP_SECRET || "";
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 4 });
pool.on("error", () => {}); // pooled connections are terminated by the clone's database reset

function send(res, status, obj, type) {
  const body = typeof obj === "string" || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj);
  res.writeHead(status, { "content-type": type || "application/json" });
  res.end(body);
}

// Token format of immune_contracts/authtoken.py: b64url(json{uid,role,exp}) "." hex(hmac_sha256)
function who(req) {
  const h = req.headers["authorization"] || "";
  if (!h.toLowerCase().startsWith("bearer ")) return null;
  const tok = h.slice(7).trim();
  const dot = tok.indexOf(".");
  if (dot < 0) return null;
  const payload = tok.slice(0, dot), sig = tok.slice(dot + 1);
  const want = crypto.createHmac("sha256", SECRET).update(payload).digest("hex");
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (data.exp < Date.now() / 1000) return null;
    return { uid: data.uid, role: data.role || "user" };
  } catch (e) { return null; }
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
  });
}

async function route(req, res) {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const q = url.searchParams;
  let m;
  if (p === "/health") return send(res, 200, { ok: true });

  if (p === "/search") {
    const r = await pool.query("SELECT id, name FROM items WHERE name ILIKE '%" + (q.get("q") || "") + "%' ORDER BY id");
    return send(res, 200, { items: r.rows });
  }
  if (p === "/safe-search") {
    const r = await pool.query("SELECT id, name FROM items WHERE name ILIKE $1 ORDER BY id", ["%" + (q.get("q") || "") + "%"]);
    return send(res, 200, { items: r.rows });
  }
  if (p === "/download") {
    const file = path.join(STATIC, q.get("name") || "");
    let data;
    try { data = await fs.promises.readFile(file); } catch (e) { return send(res, 404, { detail: "not found" }); }
    return send(res, 200, data, "application/octet-stream");
  }
  if (p === "/safe-download") {
    const file = path.resolve(STATIC, q.get("name") || "");
    if (!file.startsWith(path.resolve(STATIC) + path.sep)) return send(res, 404, { detail: "not found" });
    let data;
    try { data = await fs.promises.readFile(file); } catch (e) { return send(res, 404, { detail: "not found" }); }
    return send(res, 200, data, "application/octet-stream");
  }
  if (p === "/lookup") { // command injection: host goes to a shell
    const out = await new Promise((resolve) =>
      execFile("/bin/sh", ["-c", "echo resolving " + (q.get("host") || "")], { timeout: 2000 }, (err, so) => resolve(so || "")));
    return send(res, 200, { out });
  }
  if (p === "/fetch") { // SSRF: fetches any URL
    const target = q.get("url") || "";
    const out = await new Promise((resolve) => {
      const r = http.get(target, { timeout: 500 }, (x) => { x.resume(); resolve(x.statusCode); });
      r.on("timeout", () => { r.destroy(); resolve("timeout"); });
      r.on("error", (e) => resolve(String(e.code || e)));
    });
    return send(res, 200, { out });
  }
  if (p === "/deferred") { // answers first, reads the file afterwards (fire-and-forget, not awaited)
    const file = path.join(STATIC, q.get("name") || "");
    const delay = Math.min(parseInt(q.get("delay") || "5", 10), 1000);
    send(res, 202, { queued: true });
    setTimeout(() => fs.readFile(file, () => {}), delay);
    return;
  }
  if ((m = p.match(/^\/notes\/(\d+)$/)) && req.method === "GET") {
    if (!who(req)) return send(res, 401, { detail: "unauthorized" });
    const r = await pool.query("SELECT id, user_id, body FROM notes WHERE id = $1", [parseInt(m[1], 10)]);
    if (!r.rows.length) return send(res, 404, { detail: "not found" });
    return send(res, 200, r.rows[0]);
  }
  if ((m = p.match(/^\/safe-notes\/(\d+)$/))) {
    const ident = who(req);
    if (!ident) return send(res, 401, { detail: "unauthorized" });
    const r = await pool.query("SELECT id, user_id, body FROM notes WHERE id = $1 AND user_id = $2", [parseInt(m[1], 10), ident.uid]);
    if (!r.rows.length) return send(res, 404, { detail: "not found" });
    return send(res, 200, r.rows[0]);
  }
  if (p === "/notes" && req.method === "POST") {
    const ident = who(req);
    if (!ident) return send(res, 401, { detail: "unauthorized" });
    let payload = {};
    try { payload = JSON.parse(await readBody(req) || "{}"); } catch (e) { return send(res, 400, { detail: "bad json" }); }
    const r = await pool.query("INSERT INTO notes (user_id, body) VALUES ($1, $2) RETURNING id", [ident.uid, String(payload.body || "")]);
    return send(res, 200, { id: r.rows[0].id });
  }
  return send(res, 404, { detail: "Not Found" });
}

http.createServer((req, res) => {
  route(req, res).catch((e) => send(res, 500, { detail: "Internal Server Error" }));
}).listen(PORT, HOST, () => console.log(`demo listening on ${HOST}:${PORT}`));
