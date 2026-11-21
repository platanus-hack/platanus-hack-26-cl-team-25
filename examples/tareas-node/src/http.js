"use strict";

const MAX_BODY = 64 * 1024;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
  });
  res.end(data);
}

function sendText(res, status, text, type) {
  res.writeHead(status, {
    "content-type": type || "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(text),
  });
  res.end(text);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new HttpError(413, "cuerpo demasiado grande"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      if (!raw) return resolve({});
      try {
        const doc = JSON.parse(raw);
        if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
          return reject(new HttpError(400, "se esperaba un objeto JSON"));
        }
        resolve(doc);
      } catch (e) {
        reject(new HttpError(400, "JSON inválido"));
      }
    });
    req.on("error", reject);
  });
}

module.exports = { HttpError, sendJson, sendText, readJson };
