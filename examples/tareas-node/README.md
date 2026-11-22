# Tareas

API HTTP para gestionar tareas personales (Node.js, módulo `http` + `pg`, PostgreSQL).

```
docker compose up -d --build          # app en :3000, base en el servicio db
docker compose exec app node db/seed.js   # datos de ejemplo (contraseñas tareas-demo-<n>)
DATABASE_URL=postgres://... npm test
```

Rutas: `GET /health`, `POST /api/register`, `POST /api/login`, `POST /api/logout`, `GET /api/me`,
`GET|POST /api/tasks`, `GET|PUT|DELETE /api/tasks/{id}`, `GET /api/tasks/search?q=&status=`,
`GET /api/tasks/{id}/export?format=md|json`, `GET /api/files`, `GET /api/files/download?name=`.

Autenticación: `POST /api/login` devuelve un token opaco; enviarlo como `Authorization: Bearer <token>`.
`node_modules/` está incluido en el repositorio (`npm install --omit=dev` con `node:22-alpine`).
