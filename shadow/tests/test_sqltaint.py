from shadow import sqltaint
from shadow.sqltaint import Constants, check, tokenize


def fires(sql, value, constants=()):
    return bool(check([(sql, [])], [("query", "q", value)], Constants(constants)))


def test_tokenizer_comments_and_literals():
    kinds = [k for k, _, _ in tokenize("SELECT 'a''b', x'00', 1.5e3 -- c\n/* d */ \"id\"") if k != "ws"]
    assert kinds == ["ident", "string", "op", "blob", "op", "number", "comment", "comment", "qident"]


def test_value_inside_string_literal_is_safe():
    assert not fires("SELECT 1 FROM t WHERE name LIKE '%usb cable%'", "usb cable")


def test_numeric_literal_is_safe():
    assert not fires("SELECT 1 FROM t WHERE id = 12", "12")


def test_union_breaking_out_fires():
    assert fires("SELECT 1 FROM t WHERE n LIKE '%x' UNION SELECT 2--%'", "x' UNION SELECT 2--")


def test_comment_fires():
    assert fires("SELECT 1 FROM t WHERE n LIKE '%cable'--%'", "cable'--")
    assert fires("SELECT 1 FROM t WHERE n = 'a'/*'", "a'/*")


def test_tautology_in_numeric_context_fires():
    assert fires("SELECT 1 FROM t WHERE id = 1 OR 1=1", "1 OR 1=1")


def test_escaped_value_does_not_occur_verbatim():
    assert not fires("SELECT 1 FROM t WHERE n = 'O''Brien'", "O'Brien")


def test_parameterised_statement_never_contains_value():
    assert not fires("SELECT 1 FROM t WHERE n LIKE ?", "x' UNION SELECT 2--")


def test_coincidence_with_app_constant_is_safe():
    sql = "SELECT id, name FROM notes WHERE id = ?"
    assert not fires(sql, "notes", [sql])
    assert not fires(sql, "id, name", [sql])
    assert fires(sql, "id, name", [])  # without the constant it is structural


def test_identifier_injection_fires():
    assert fires("SELECT id FROM t ORDER BY password", "password", ["SELECT id FROM t ORDER BY "])


def test_double_encoded_and_case_variants():
    assert fires("SELECT 1 FROM t WHERE n = 'x' OR '1'='1'", "x%27%20OR%20%271%27%3D%271")
    assert fires("SELECT 1 FROM t WHERE n = 'X' OR '1'='1'", "x' or '1'='1")


def test_short_values_ignored():
    assert sqltaint.variants("a") == []
