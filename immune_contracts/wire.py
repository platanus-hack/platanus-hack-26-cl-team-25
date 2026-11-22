"""Internal wire protocol between gateway and shadow clones.

Only the gateway can reach a clone (internal Docker network). The gateway strips
every header starting with INTERNAL_PREFIX from client requests and from responses
sent to clients (gateway/core.py: _read, _clean_resp_headers).
Reference: contracts/README.md section 5.
"""
from __future__ import annotations
import hashlib, hmac, json

INTERNAL_PREFIX = "x-imm-"

# gateway -> clone (request headers)
H_RID = "x-imm-rid"        # request id, unique, minted by the gateway
H_MODE = "x-imm-mode"      # "L1" (reset to seed after the request) | "L2" (captive: keep state)
H_UID = "x-imm-uid"        # authenticated user id resolved by the gateway from the PROD token; absent = keep the client's own headers
H_ROLE = "x-imm-role"      # "user" | "admin"; only with H_UID

# clone -> gateway (response headers, added after the app has fully finished)
H_VERDICT = "x-imm-verdict"  # one of VERDICTS
H_EVENTS = "x-imm-events"    # number of oracle events for this request

VERDICT_CLEAN = "clean"
VERDICT_ORACLE = "oracle"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICTS = (VERDICT_CLEAN, VERDICT_ORACLE, VERDICT_INCONCLUSIVE)

# Oracle kinds
ORACLE_SQL = "sql"
ORACLE_FILE = "file"
ORACLE_PROC = "proc"
ORACLE_NET = "net"
ORACLE_OWNER = "owner"
# Input -> effect oracles (shadow/effects.py): the same observations as proc / net / file / the response, but the
# request's own input is what reached the effect, which is what makes it a class of its own (classes.py).
ORACLE_SSRF = "ssrf"          # an undeclared connection to a destination the request named
ORACLE_CMDI = "cmdi"          # a process was spawned with the request's input on its command line
ORACLE_SSTI = "ssti"          # a template expression of the request was evaluated (response, or its effect)
ORACLE_DESER = "deser"        # a process/connection/file effect while the request carried a serialized object
ORACLE_XXE = "xxe"            # an XML external entity of the request body was fetched (file or connection)
ORACLE_REDIRECT = "redirect"  # a 3xx to another host that the request itself named
ORACLE_XSS = "xss"            # an input with markup is reflected unescaped in an HTML response (stored or same-request)
ORACLES = (ORACLE_SQL, ORACLE_FILE, ORACLE_PROC, ORACLE_NET, ORACLE_OWNER,
           ORACLE_SSRF, ORACLE_CMDI, ORACLE_SSTI, ORACLE_DESER, ORACLE_XXE, ORACLE_REDIRECT, ORACLE_XSS)

# Clone evidence push: POST http://<COLLECTOR_URL>/_clone/evidence  (JSON body, see contracts/schemas/evidence.schema.json)
H_CLONE_ID = "x-imm-clone"
H_SIGNATURE = "x-imm-signature"  # hex(hmac_sha256(clone_key, raw_body_bytes))


def sign(key: str, body: bytes) -> str:
    return hmac.new(key.encode(), body, hashlib.sha256).hexdigest()


def check(key: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(key, body), signature or "")


def dumps(obj) -> bytes:
    """Canonical JSON bytes used for signed bodies."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
