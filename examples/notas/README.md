# Notas

Servicio de notas para equipos. FastAPI + sqlite3.

## Puesta en marcha

    pip install -r requirements.txt
    python scripts/init_db.py --db data/notas.db        # --seed N para otra muestra
    NOTAS_DB=data/notas.db uvicorn notas.main:app --port 8000

Con Docker: `docker compose up --build` (la base vive en el volumen `notas-data`).

## Configuracion (variables de entorno)

| Variable     | Descripcion                                                        |
|--------------|--------------------------------------------------------------------|
| `NOTAS_DB`   | Ruta de la base sqlite (por defecto `data/notas.db`)               |
| `NOTAS_FILES`| Carpeta con las plantillas de solo lectura (por defecto `notas/files`) |
| `NOTAS_NOW`  | Hora unix fija para todas las marcas de tiempo (opcional)          |

## Usuarios de desarrollo

`scripts/init_db.py` crea 25 usuarios, 4 equipos y unas 80 notas.

- Admin: `admin@notas.example` / `admin123`
- Resto (ej. `valentina.munoz@notas.example`, `matias.gonzalez@notas.example`): clave `notas1234`

## Autenticacion

`POST /auth/login` devuelve un token; enviarlo como `Authorization: Bearer <token>`.

## Rutas

| Metodo | Ruta | Descripcion |
|--------|------|-------------|
| GET | `/health` | Estado del servicio |
| POST | `/auth/register` | Crea un usuario (`email`, `name`, `password`) |
| POST | `/auth/login` | Devuelve `{"token", "token_type"}` |
| GET | `/auth/me` | `{"id","email","name","role"}` |
| GET | `/notes` | Notas propias; `q` busca en titulo/cuerpo, `sort` = `created` o `title` |
| POST | `/notes` | Crea una nota (`title`, `body`, `team_id` opcional) |
| GET | `/notes/{note_id}` | Una nota propia |
| PUT | `/notes/{note_id}` | Reemplaza una nota propia |
| DELETE | `/notes/{note_id}` | Borra una nota propia |
| GET | `/notes/{note_id}/export` | Nota en texto plano con el nombre del autor |
| GET | `/templates` | Nombres de las plantillas disponibles |
| GET | `/templates/download?name=` | Descarga una plantilla |
| GET | `/teams/{team_id}/members` | Nombre y correo de los miembros del equipo |
| GET | `/admin/users` | Lista de usuarios (solo admin) |

La documentacion OpenAPI esta en `/docs` y `/openapi.json`.

## Tests

    python -m pytest tests -q
