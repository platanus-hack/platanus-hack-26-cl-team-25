"use strict";
const http = require("http");
const auth = require("./auth");
const tasks = require("./tasks");
const files = require("./files");
const { exportTask } = require("./exporter");
const { HttpError, sendJson, sendText, readJson } = require("./http");

const TASK_ID = /^\/api\/tasks\/(\d{1,9})$/;
const TASK_EXPORT = /^\/api\/tasks\/(\d{1,9})\/export$/;

async function route(req, res) {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;
  const m = req.method;
  let match;

  if (p === "/health" && m === "GET") return sendJson(res, 200, { ok: true });

  if (p === "/api/register" && m === "POST") {
    const user = await auth.register(await readJson(req));
    return sendJson(res, 201, user);
  }
  if (p === "/api/login" && m === "POST") return sendJson(res, 200, await auth.login(await readJson(req)));
  if (p === "/api/logout" && m === "POST") {
    await auth.logout(req);
    return sendJson(res, 200, { ok: true });
  }
  if (p === "/api/me" && m === "GET") return sendJson(res, 200, await auth.requireUser(req));

  if (p === "/api/tasks" && m === "GET") {
    const user = await auth.requireUser(req);
    return sendJson(res, 200, { tasks: await tasks.list(user) });
  }
  if (p === "/api/tasks" && m === "POST") {
    const user = await auth.requireUser(req);
    return sendJson(res, 201, await tasks.create(user, await readJson(req)));
  }
  if (p === "/api/tasks/search" && m === "GET") {
    const user = await auth.requireUser(req);
    const found = await tasks.search(user, url.searchParams.get("q"), url.searchParams.get("status"));
    return sendJson(res, 200, { tasks: found });
  }
  if ((match = TASK_EXPORT.exec(p)) && m === "GET") {
    const user = await auth.requireUser(req);
    const out = await exportTask(user, parseInt(match[1], 10), url.searchParams.get("format"));
    return sendText(res, 200, out.body, out.type);
  }
  if ((match = TASK_ID.exec(p))) {
    const user = await auth.requireUser(req);
    const id = parseInt(match[1], 10);
    if (m === "GET") return sendJson(res, 200, await tasks.get(user, id));
    if (m === "PUT") return sendJson(res, 200, await tasks.update(user, id, await readJson(req)));
    if (m === "DELETE") {
      await tasks.remove(user, id);
      return sendJson(res, 200, { ok: true });
    }
  }

  if (p === "/api/files" && m === "GET") {
    await auth.requireUser(req);
    return sendJson(res, 200, { files: await files.list() });
  }
  if (p === "/api/files/download" && m === "GET") {
    await auth.requireUser(req);
    const f = await files.read(url.searchParams.get("name"));
    res.writeHead(200, {
      "content-type": f.type,
      "content-length": f.data.length,
      "content-disposition": `attachment; filename="${f.filename.replace(/"/g, "")}"`,
    });
    return res.end(f.data);
  }

  throw new HttpError(404, "no encontrado");
}

function createApp() {
  return http.createServer((req, res) => {
    route(req, res).catch((err) => {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
      console.error(`${req.method} ${req.url}:`, err.message);
      if (!res.headersSent) sendJson(res, 500, { error: "error interno" });
      else res.destroy();
    });
  });
}

module.exports = { createApp };
