"""Vulnerability classes and the oracle kinds that confirm them: the single source of truth.

An incident's class comes from the oracle that fired (pipeline/incident.py). Three older classes map to the
channel oracles (sql, file, owner); the input -> effect classes (shadow/effects.py) each have an oracle of their own.
"""
from __future__ import annotations

CLASS_OF = {"sql": "sqli", "file": "traversal", "owner": "idor",
            "ssrf": "ssrf", "cmdi": "cmdi", "ssti": "ssti", "deser": "deser", "xxe": "xxe", "redirect": "redirect",
            "xss": "xss"}
ORACLE_OF = {c: o for o, c in CLASS_OF.items()}

# when several oracles fired in one request, the class of the incident is the first of these. The input -> effect
# classes come first: they are the cause, and a command injection also opens files (the spawned `id` reads
# /etc/passwd) while a name lookup reads /etc/hosts, effects that must not turn it into a traversal. The older
# channel oracles keep their relative order.
PREFERENCE = ("xxe", "ssti", "deser", "cmdi", "ssrf", "redirect", "xss", "sql", "file", "owner")

EFFECT_CLASSES = ("ssrf", "cmdi", "ssti", "deser", "xxe", "redirect", "xss")
# classes whose vulnerable input is a string parameter the app uses: the self-audit probes every string-shaped
# parameter of the OpenAPI document with the class's battery. xxe is not one: its input is the whole XML body.
STRING_CLASSES = ("sqli", "traversal", "ssrf", "cmdi", "ssti", "deser", "redirect", "xss")
AUDITABLE = STRING_CLASSES + ("idor",)

# the oracle kinds that count as "this class's effect still happens": a fix is rejected if any of them fires for an
# attack payload. The raw channel kinds are included because an effect whose input correlation was lost is still the effect.
FAMILY = {"ssrf": ("ssrf", "net"), "cmdi": ("cmdi", "proc"), "ssti": ("ssti", "proc", "file"),
          "deser": ("deser", "proc"), "xxe": ("xxe", "file", "net"), "redirect": ("redirect",), "xss": ("xss",)}
