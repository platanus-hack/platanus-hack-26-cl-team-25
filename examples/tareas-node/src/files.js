"use strict";
const fs = require("fs");
const path = require("path");
const { HttpError } = require("./http");

const FILES_DIR = process.env.FILES_DIR || path.join(__dirname, "..", "files");

const TYPES = {
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".csv": "text/csv; charset=utf-8",
  ".json": "application/json",
};

function typeOf(name) {
  return TYPES[path.extname(name).toLowerCase()] || "application/octet-stream";
}

async function walk(dir, prefix) {
  const out = [];
  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const rel = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...(await walk(path.join(dir, e.name), rel)));
    else if (e.isFile()) out.push(rel);
  }
  return out;
}

async function list() {
  return walk(FILES_DIR, "");
}

async function read(name) {
  if (!name) throw new HttpError(400, "falta el parámetro name");
  const file = path.join(FILES_DIR, name);
  try {
    const data = await fs.promises.readFile(file);
    return { data, type: typeOf(file), filename: path.basename(file) };
  } catch (e) {
    throw new HttpError(404, "archivo no encontrado");
  }
}

module.exports = { list, read, FILES_DIR };
