# Planted defects of `examples/tareas-node`

Exactly three planted defects. Everything else (owner checks on `GET/PUT/DELETE /api/tasks/{id}`,
parameterised queries elsewhere, the whitelisted `status` filter in the search) is intended to be correct.

| # | Class | Route | Param | Where | Example (as any freshly registered user) | Oracle |
|---|---|---|---|---|---|---|
| 1 | SQL injection | `GET /api/tasks/search` | `q` (query) | `src/tasks.js:95` — `q` concatenated into `ILIKE '%...%'` | `/api/tasks/search?q=zz%27)%20OR%201=1%20--%20` returns every user's tasks | `sql` |
| 2 | Path traversal | `GET /api/files/download` | `name` (query) | `src/files.js:36` — `path.join(FILES_DIR, name)` with no containment check | `/api/files/download?name=../../../../etc/hostname` | `file` |
| 3 | IDOR (missing owner check) | `GET /api/tasks/{task_id}/export` | `task_id` (path) | `src/exporter.js:9-16` — `WHERE t.id = $1`, caller never compared with `t.user_id` | `/api/tasks/3/export` (task of user 1) | `owner` |

Side effect of #1: an apostrophe in a legitimate search (`q=O'Brien`) is a syntax error -> 500.
The test suite (`npm test`) passes on this code and exercises every route with legitimate input; it
does not search with an apostrophe (it would fail on this code).
