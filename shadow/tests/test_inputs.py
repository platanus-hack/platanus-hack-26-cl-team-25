"""shadow.inputs.extract: the attacker-controlled values the oracles taint-check."""
from shadow import inputs


def _multipart(boundary: str, fields: dict) -> bytes:
    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n' for k, v in fields.items()]
    return ("".join(parts) + f"--{boundary}--\r\n").encode()


def test_multipart_boundary_is_case_sensitive():
    payload = "x' OR '1'='1"
    for boundary in ("----WebKitAbC", "----webkitabc", "XyZ123"):
        got = inputs.extract("/upload", "", {"Content-Type": f"Multipart/Form-Data; boundary={boundary}"},
                             _multipart(boundary, {"q": payload, "note": "hello"}))
        assert ("form", "q", payload) in got and ("form", "note", "hello") in got, boundary


def test_multipart_file_parts_and_names():
    body = (b'--AbC\r\nContent-Disposition: form-data; name="doc"; filename="../../Evil.TXT"\r\n'
            b"Content-Type: text/plain\r\n\r\ncontents\r\n--AbC--\r\n")
    got = inputs.extract("/upload", "", {"content-type": "multipart/form-data; boundary=AbC"}, body)
    assert ("form", "doc", "../../Evil.TXT") in got and ("form", "doc", "contents") in got


def test_path_segments_are_named_after_the_route_parameter():
    got = inputs.extract("/users/alice/notes/n%2D7", "", {}, b"", {"user": "alice", "note": "n-7"})
    assert ("path", "user", "alice") in got and ("path", "note", "n-7") in got
    assert ("path", "path[0]", "users") in got and ("path", "path[2]", "notes") in got    # literals stay positional
    assert not [x for x in got if x[0] == "path" and x[2] in ("alice", "n-7") and x[1].startswith("path[")]
    # without router information every segment is positional
    assert ("path", "path[1]", "alice") in inputs.extract("/users/alice", "", {}, b"")
    # a catch-all parameter spans several segments: reported whole under its name
    assert ("path", "rest", "a/b") in inputs.extract("/files/a/b", "", {}, b"", {"rest": "a/b"})
