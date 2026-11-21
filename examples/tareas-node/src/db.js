"use strict";
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: parseInt(process.env.DB_POOL_SIZE || "5", 10),
  idleTimeoutMillis: 30000,
});

// a connection dropped by the server while idle must not take the process down
pool.on("error", (err) => {
  console.error("postgres: conexión inactiva cerrada:", err.message);
});

function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, query };
