"use strict";
const crypto = require("crypto");
const db = require("./db");
const { HttpError } = require("./http");

const SESSION_HOURS = parseInt(process.env.SESSION_HOURS || "72", 10);
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString("hex")}$${key.toString("hex")}`;
}

function checkPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") return false;
  const salt = Buffer.from(parts[1], "hex");
  const want = Buffer.from(parts[2], "hex");
  const got = crypto.scryptSync(password, salt, want.length);
  return want.length > 0 && crypto.timingSafeEqual(got, want);
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function bearer(req) {
  const h = req.headers["authorization"] || "";
  const m = /^Bearer\s+([A-Za-z0-9._-]{16,200})$/i.exec(h.trim());
  return m ? m[1] : null;
}

async function currentUser(req) {
  const token = bearer(req);
  if (!token) return null;
  const r = await db.query(
    "SELECT u.id, u.email, u.name, u.role FROM sessions s JOIN users u ON u.id = s.user_id " +
      "WHERE s.token_hash = $1 AND s.expires_at > now()",
    [tokenHash(token)]
  );
  return r.rows[0] || null;
}

async function requireUser(req) {
  const user = await currentUser(req);
  if (!user) throw new HttpError(401, "no autenticado");
  return user;
}

async function register(body) {
  const email = String(body.email || "").trim().toLowerCase();
  const name = String(body.name || "").trim();
  const password = String(body.password || "");
  if (!EMAIL_RE.test(email) || email.length > 200) throw new HttpError(400, "email inválido");
  if (!name || name.length > 120) throw new HttpError(400, "nombre inválido");
  if (password.length < 8 || password.length > 200) throw new HttpError(400, "la contraseña debe tener al menos 8 caracteres");
  try {
    const r = await db.query(
      "INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, name, role",
      [email, name, hashPassword(password)]
    );
    return r.rows[0];
  } catch (e) {
    if (e.code === "23505") throw new HttpError(409, "ya existe una cuenta con ese email");
    throw e;
  }
}

async function login(body) {
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");
  const r = await db.query("SELECT id, password_hash FROM users WHERE email = $1", [email]);
  const user = r.rows[0];
  if (!user || !checkPassword(password, user.password_hash)) throw new HttpError(401, "credenciales inválidas");
  const token = crypto.randomBytes(24).toString("hex");
  await db.query(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + make_interval(hours => $3))",
    [tokenHash(token), user.id, SESSION_HOURS]
  );
  return { token, expires_in: SESSION_HOURS * 3600 };
}

async function logout(req) {
  const token = bearer(req);
  if (token) await db.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash(token)]);
}

module.exports = { hashPassword, checkPassword, currentUser, requireUser, register, login, logout };
