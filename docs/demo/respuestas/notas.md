# Planted defects of `examples/notas`

1. `notas/notes.py:42` - `GET /notes`: the `q` search is built by string concatenation into the SQL instead of using parameters.
2. `notas/attachments.py:20` - `GET /templates/download`: `name` is joined to the files directory with no check that the result stays inside it.
3. `notas/notes.py:139-146` - `GET /notes/{note_id}/export`: the note is looked up by id only (`WHERE n.id = ?`), with no owner check (unlike `GET /notes/{note_id}` at `notes.py:83-87`).
4. `notas/teams.py:9-20` - `GET /teams/{team_id}/members`: no membership check for the caller before listing the team's members.
