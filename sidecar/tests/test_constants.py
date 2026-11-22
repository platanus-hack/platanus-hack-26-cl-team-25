"""String-constant extraction for sqltaint rule 3 (source literals and executable strings)."""
from shadow import sqltaint
from sidecar import constants


def test_js_literals_split_template_interpolation():
    src = 'pool.query("SELECT id, name FROM items WHERE name ILIKE \'%" + q + "%\'");\nconst t = `SELECT * FROM notes WHERE id = ${id} AND x`;'
    lits = constants.literals(src)
    assert "SELECT id, name FROM items WHERE name ILIKE '%" in lits
    assert "SELECT * FROM notes WHERE id = " in lits and " AND x" in lits


def test_binary_literals_split_printf_specifiers(tmp_path):
    exe = tmp_path / "app"
    exe.write_bytes(b"\x7fELF\x00\x01SELECT id, name FROM items WHERE name ILIKE '%%%s%%' ORDER BY id\x00ab\x00"
                    b"SELECT id, user_id, body FROM notes WHERE id = $1\x00")
    lits = constants.binary_literals(str(exe), 1 << 20)
    assert "SELECT id, name FROM items WHERE name ILIKE '%" in lits and "%' ORDER BY id" in lits
    assert "SELECT id, user_id, body FROM notes WHERE id = $1" in lits
    assert constants.binary_literals(str(exe), 10) == []  # size cap


def test_constants_explain_table_name_but_not_injection(tmp_path):
    exe = tmp_path / "app"
    exe.write_bytes(b"SELECT id, user_id, body FROM notes WHERE id = $1\x00SELECT id, name FROM items WHERE name ILIKE '%%%s%%' ORDER BY id\x00")
    c = constants.scan("/", [], [str(exe)])
    ok = "SELECT id, user_id, body FROM notes WHERE id = $1"
    assert sqltaint.check([(ok, [])], [("path", "path[0]", "notes")], c) == []
    assert sqltaint.check([(ok, [])], [("path", "path[0]", "notes")], sqltaint.Constants([])) != []
    inj = "SELECT id, name FROM items WHERE name ILIKE '%x' UNION SELECT id, body FROM notes--%' ORDER BY id"
    assert sqltaint.check([(inj, [])], [("query", "q", "x' UNION SELECT id, body FROM notes--")], c) != []
