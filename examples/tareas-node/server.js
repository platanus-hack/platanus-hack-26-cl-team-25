"use strict";
const { createApp } = require("./src/app");
const db = require("./src/db");

const port = parseInt(process.env.PORT || "3000", 10);
const host = process.env.HOST || "0.0.0.0";

const server = createApp();
server.listen(port, host, () => {
  console.log(`tareas escuchando en ${host}:${port}`);
});

function shutdown() {
  server.close(() => db.pool.end().finally(() => process.exit(0)));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
