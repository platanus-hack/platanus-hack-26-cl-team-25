"""Containment rules learned from an incident, for the FUXA policy layer.

TIENDA keeps its learned rules in the gateway because the gateway owns session
identity. FUXA's identity lives inside the server (JWT / Socket.IO session), so
the policy layer is where rules evolve. Evidence is privacy-safe: operation,
transport, role and the opaque session key — never message contents.

An LLM may propose the rule; a mechanical validator decides. Without the LLM
(or on any invalid proposal) the deterministic fallback applies: contain the
operation for every non-administrator role, which keeps the plant working for
real admins while the candidate patch validates.
"""
from __future__ import annotations

import json
import os
import re

TTL_MIN = 300
TTL_MAX = 900
OPERATIONS = ("tag_write", "device_control", "historian_query", "scheduler_authorization")
GRAMMAR_MAX = 240

_PROMPT = """Eres el asignador de reglas de contención de un sistema inmune para FUXA.
Ocurrió un incidente de autorización y, mientras se valida el parche definitivo,
hay que contener la operación con una regla temporal. Devuelve SOLO un objeto
JSON, sin texto adicional, con este esquema:

  {{ "operation": "<tag_write|device_control|historian_query|scheduler_authorization>",
     "scope": "<role|session>",
     "ttl_s": <entero entre {tmin} y {tmax}>,
     "reason": "<frase corta en español>" }}

Reglas de decisión:
- "scope":"role" contiene la operación para todos los roles salvo administrator
  (la planta sigue funcionando para los administradores).
- "scope":"session" contiene únicamente la sesión infractora; úsalo solo si la
  evidencia sugiere un uso aislado (una sola sesión, primera infracción).
- Ante duda, elige "scope":"role" y ttl_s alto.
- Nunca inventes operaciones fuera de la lista.

Evidencia del incidente:
{evidence}
"""


def _llm_proposal(evidence: dict) -> dict | None:
    """Ask the confined CLI for a rule proposal. None when unavailable/invalid."""
    try:
        from patcher import claude_cli
    except ImportError:
        return None
    prompt = _PROMPT.format(tmin=TTL_MIN, tmax=TTL_MAX,
                            evidence=json.dumps(evidence, ensure_ascii=False, indent=1))
    try:
        result = claude_cli.run(prompt, os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                [], timeout=120)
    except Exception:  # noqa
        return None
    if not result.ok or not result.text:
        return None
    match = re.search(r"\{.*\}", result.text, re.S)
    if not match:
        return None
    try:
        proposal = json.loads(match.group(0))
    except ValueError:
        return None
    return proposal if isinstance(proposal, dict) else None


def normalize(proposal: dict | None, operation: str, session: str | None,
              default_ttl: int) -> dict | None:
    """Mechanical validation. Returns the normalized rule or None (use fallback)."""
    if not isinstance(proposal, dict):
        return None
    if proposal.get("operation") != operation or operation not in OPERATIONS:
        return None
    scope = proposal.get("scope")
    if scope not in ("role", "session"):
        return None
    if scope == "session" and not session:
        return None
    try:
        ttl = int(proposal.get("ttl_s"))
    except (TypeError, ValueError):
        return None
    if not TTL_MIN <= ttl <= TTL_MAX:
        return None
    reason = proposal.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 160:
        return None
    rule = {"operations": [operation], "scope": scope, "ttl_s": ttl, "reason": reason.strip()}
    if scope == "session":
        rule["session"] = session
    else:
        rule["require_role"] = "administrator"
    return rule


def fallback_rule(operation: str, default_ttl: int) -> dict:
    """Deterministic containment: deny the operation for every non-admin role."""
    return {"operations": [operation], "scope": "role", "require_role": "administrator",
            "ttl_s": default_ttl, "reason": "contención del incidente"}


def propose_rule(evidence: dict, operation: str, session: str | None,
                 default_ttl: int) -> tuple[dict, bool]:
    """(rule, learned). The LLM proposal must pass mechanical validation."""
    proposal = _llm_proposal(evidence)
    rule = normalize(proposal, operation, session, default_ttl)
    if rule is not None:
        return rule, True
    return fallback_rule(operation, default_ttl), False
