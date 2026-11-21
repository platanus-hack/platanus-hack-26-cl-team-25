import os
import sqlite3

from conftest import login


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_openapi(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    assert "/notes" in r.json()["paths"]


# auth

def test_register_and_login(client):
    r = client.post(
        "/auth/register",
        json={"email": "nuevo@notas.example", "name": "Nuevo Usuario", "password": "abc12345"},
    )
    assert r.status_code == 201
    assert r.json()["role"] == "member"
    headers = login(client, "nuevo@notas.example", "abc12345")
    me = client.get("/auth/me", headers=headers)
    assert me.status_code == 200
    body = me.json()
    assert set(body) == {"id", "email", "name", "role"}
    assert body["email"] == "nuevo@notas.example"
    assert body["name"] == "Nuevo Usuario"


def test_register_duplicate(client):
    data = {"email": "dup@notas.example", "name": "Dup", "password": "x"}
    assert client.post("/auth/register", json=data).status_code == 201
    assert client.post("/auth/register", json=data).status_code == 409


def test_login_wrong_password(client):
    r = client.post("/auth/login", json={"email": "admin@notas.example", "password": "nope"})
    assert r.status_code == 401


def test_me_requires_token(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer xyz"}).status_code == 401


def test_me_admin(client, admin):
    r = client.get("/auth/me", headers=admin)
    assert r.json()["role"] == "admin"


def test_login_frozen_time(client, monkeypatch, db_query):
    monkeypatch.setenv("NOTAS_NOW", "1700000000")
    headers = login(client, "admin@notas.example", "admin123")
    token = headers["Authorization"].split(" ", 1)[1]
    rows = db_query("SELECT created_at FROM sessions WHERE token = ?", (token,))
    assert rows == [(1700000000,)]


# notes

def test_note_crud(client, make_user):
    u = make_user()
    r = client.post("/notes", json={"title": "Primera", "body": "Hola"}, headers=u["headers"])
    assert r.status_code == 201
    note = r.json()
    assert note["owner_id"] == u["id"]
    nid = note["id"]

    r = client.get("/notes/%d" % nid, headers=u["headers"])
    assert r.status_code == 200
    assert r.json()["title"] == "Primera"

    r = client.put(
        "/notes/%d" % nid, json={"title": "Editada", "body": "Nuevo texto"}, headers=u["headers"]
    )
    assert r.status_code == 200
    assert r.json()["title"] == "Editada"
    assert client.get("/notes/%d" % nid, headers=u["headers"]).json()["body"] == "Nuevo texto"

    assert client.delete("/notes/%d" % nid, headers=u["headers"]).status_code == 204
    assert client.get("/notes/%d" % nid, headers=u["headers"]).status_code == 404


def test_notes_require_auth(client):
    assert client.get("/notes").status_code == 401
    assert client.post("/notes", json={"title": "x"}).status_code == 401


def test_frozen_time_on_note(client, make_user, monkeypatch):
    monkeypatch.setenv("NOTAS_NOW", "1700000123")
    u = make_user()
    r = client.post("/notes", json={"title": "Con fecha"}, headers=u["headers"])
    assert r.json()["created_at"] == 1700000123


def test_note_with_apostrophe_title(client, make_user):
    u = make_user()
    r = client.post(
        "/notes",
        json={"title": "Reunión con D'Alessandro", "body": "Acta de la reunión"},
        headers=u["headers"],
    )
    assert r.status_code == 201
    nid = r.json()["id"]
    got = client.get("/notes/%d" % nid, headers=u["headers"]).json()
    assert got["title"] == "Reunión con D'Alessandro"
    titles = [n["title"] for n in client.get("/notes", headers=u["headers"]).json()]
    assert "Reunión con D'Alessandro" in titles


def test_list_only_own_notes(client, make_user):
    a = make_user()
    b = make_user()
    client.post("/notes", json={"title": "De A"}, headers=a["headers"])
    client.post("/notes", json={"title": "De B"}, headers=b["headers"])
    titles = [n["title"] for n in client.get("/notes", headers=a["headers"]).json()]
    assert titles == ["De A"]


def test_search_terms_with_spaces(client, make_user):
    u = make_user()
    client.post(
        "/notes",
        json={"title": "Plan de lanzamiento", "body": "Fecha tentativa en marzo"},
        headers=u["headers"],
    )
    client.post("/notes", json={"title": "Compras", "body": "papel y café"}, headers=u["headers"])
    r = client.get("/notes", params={"q": "plan de lanz"}, headers=u["headers"])
    assert [n["title"] for n in r.json()] == ["Plan de lanzamiento"]
    r = client.get("/notes", params={"q": "tentativa en"}, headers=u["headers"])
    assert [n["title"] for n in r.json()] == ["Plan de lanzamiento"]
    r = client.get("/notes", params={"q": "no existe esto"}, headers=u["headers"])
    assert r.json() == []


def test_sort_by_title_and_created(client, make_user, monkeypatch):
    u = make_user()
    for ts, title in [(1700000100, "Beta"), (1700000200, "Alfa"), (1700000300, "Gamma")]:
        monkeypatch.setenv("NOTAS_NOW", str(ts))
        client.post("/notes", json={"title": title}, headers=u["headers"])
    by_title = client.get("/notes", params={"sort": "title"}, headers=u["headers"]).json()
    assert [n["title"] for n in by_title] == ["Alfa", "Beta", "Gamma"]
    by_created = client.get("/notes", params={"sort": "created"}, headers=u["headers"]).json()
    assert [n["title"] for n in by_created] == ["Gamma", "Alfa", "Beta"]


def test_invalid_sort(client, make_user):
    u = make_user()
    assert client.get("/notes", params={"sort": "otro"}, headers=u["headers"]).status_code == 422


def test_cannot_see_or_change_other_users_note(client, make_user):
    a = make_user()
    b = make_user()
    nid = client.post("/notes", json={"title": "Privada"}, headers=a["headers"]).json()["id"]
    assert client.get("/notes/%d" % nid, headers=b["headers"]).status_code == 404
    r = client.put("/notes/%d" % nid, json={"title": "Robada"}, headers=b["headers"])
    assert r.status_code == 404
    assert client.delete("/notes/%d" % nid, headers=b["headers"]).status_code == 404
    still = client.get("/notes/%d" % nid, headers=a["headers"]).json()
    assert still["title"] == "Privada"


def test_missing_note_is_404(client, make_user):
    u = make_user()
    assert client.get("/notes/999999", headers=u["headers"]).status_code == 404


def test_note_in_own_team(client, make_user, db_query):
    u = make_user()
    team_id = db_query("SELECT id FROM teams ORDER BY id LIMIT 1")[0][0]
    conn = sqlite3.connect(os.environ["NOTAS_DB"])
    conn.execute("INSERT INTO memberships (user_id, team_id) VALUES (?, ?)", (u["id"], team_id))
    conn.commit()
    conn.close()
    r = client.post("/notes", json={"title": "Del equipo", "team_id": team_id}, headers=u["headers"])
    assert r.status_code == 201
    assert r.json()["team_id"] == team_id


def test_note_in_foreign_team_forbidden(client, make_user, db_query):
    u = make_user()
    team_id = db_query("SELECT id FROM teams ORDER BY id LIMIT 1")[0][0]
    r = client.post("/notes", json={"title": "Intruso", "team_id": team_id}, headers=u["headers"])
    assert r.status_code == 403


def test_export_own_note(client, make_user):
    u = make_user("Marcela Núñez")
    nid = client.post(
        "/notes", json={"title": "Informe", "body": "Contenido del informe"}, headers=u["headers"]
    ).json()["id"]
    r = client.get("/notes/%d/export" % nid, headers=u["headers"])
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "Informe" in r.text
    assert "Marcela Núñez" in r.text
    assert "Contenido del informe" in r.text


def test_export_missing_note(client, make_user):
    u = make_user()
    assert client.get("/notes/999999/export", headers=u["headers"]).status_code == 404


# templates

def test_list_templates(client, make_user):
    u = make_user()
    r = client.get("/templates", headers=u["headers"])
    assert r.status_code == 200
    assert "acta.semanal.v2.md" in r.json()
    assert "plan.trimestral.txt" in r.json()


def test_download_template_with_several_dots(client, make_user):
    u = make_user()
    r = client.get("/templates/download", params={"name": "retro.sprint.2024.v1.txt"}, headers=u["headers"])
    assert r.status_code == 200
    assert "Retrospectiva" in r.text
    r = client.get("/templates/download", params={"name": "acta.semanal.v2.md"}, headers=u["headers"])
    assert r.status_code == 200
    assert "Acta de reunion" in r.text


def test_download_unknown_template(client, make_user):
    u = make_user()
    r = client.get("/templates/download", params={"name": "no.existe.v9.txt"}, headers=u["headers"])
    assert r.status_code == 404


def test_templates_require_auth(client):
    assert client.get("/templates").status_code == 401
    assert client.get("/templates/download", params={"name": "plan.trimestral.txt"}).status_code == 401


# teams

def test_team_members_as_member(client, make_user, db_query):
    team_id = db_query("SELECT id FROM teams ORDER BY id LIMIT 1")[0][0]
    email, password = db_query(
        "SELECT u.email FROM memberships m JOIN users u ON u.id = m.user_id "
        "WHERE m.team_id = ? AND u.role = 'member' ORDER BY u.id LIMIT 1",
        (team_id,),
    )[0][0], "notas1234"
    headers = login(client, email, password)
    r = client.get("/teams/%d/members" % team_id, headers=headers)
    assert r.status_code == 200
    members = r.json()
    assert email in [m["email"] for m in members]
    assert all(set(m) == {"name", "email"} for m in members)
    expected = db_query("SELECT COUNT(*) FROM memberships WHERE team_id = ?", (team_id,))[0][0]
    assert len(members) == expected


def test_team_members_unknown_team(client, make_user):
    u = make_user()
    assert client.get("/teams/9999/members", headers=u["headers"]).status_code == 404


def test_team_members_requires_auth(client):
    assert client.get("/teams/1/members").status_code == 401


# admin

def test_admin_users(client, admin):
    r = client.get("/admin/users", headers=admin)
    assert r.status_code == 200
    users = r.json()
    assert len(users) >= 25
    assert "password_hash" not in users[0]
    assert [u["role"] for u in users].count("admin") == 1


def test_admin_users_forbidden_for_member(client, make_user):
    u = make_user()
    assert client.get("/admin/users", headers=u["headers"]).status_code == 403


def test_admin_users_requires_auth(client):
    assert client.get("/admin/users").status_code == 401


def test_seed_data(db_query):
    assert db_query("SELECT COUNT(*) FROM teams")[0][0] == 4
    assert db_query("SELECT COUNT(*) FROM notes WHERE owner_id < 26")[0][0] >= 80
    assert db_query("SELECT COUNT(*) FROM users WHERE name LIKE '%''%'")[0][0] >= 3
