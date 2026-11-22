# gateway (WP3)

Reverse proxy in front of prod. Contract: `contracts/README.md` §6–7.

```
python -m gateway        # env: GW_HOST, GW_DATA_PORT/ADMIN_PORT/INGEST_PORT, PROD_ADDR, PROD_RELEASE,
                         #      PROD_APP_SECRET, SHADOW_APP_SECRET, ADMIN_TOKEN, BUS_URL, BUS_TOKEN, RUN_ID,
                         #      OPENAPI_PATH, MANIFEST_PATH, RECORD_PATH (optional GW_CAPTIVE_TTL_S, default 900)
```

One asyncio process, three uvicorn listeners, all state in memory.

| module | role |
|---|---|
| `core.py` | `Gateway`: data plane (steps 1–9), prod/clone forwarding, upstream drain, recording, admin + ingest apps |
| `spec.py` | OpenAPI loading (`$ref`), path-template matching, per-value schema checks |
| `classifier.py` | stage-1 classification → `clean / suspect / evidence` + reasons; rules; enumeration; manifest; redaction |
| `pool.py` | clone state machine `free → busy → free / captive → retired` + captive sessions with lazy clone binding, per-clone lock, wait ≤ 300 ms, eviction, idle TTL |
| `bus.py` | fire-and-forget publisher (bounded queue + background batcher; drops on failure) |
| `l0.py` | fixed scanner-path list with deterministic procedural decoys |

Behaviour notes

- Session key: `uid:<n>` for a prod token, else `gwsid:<cookie>`; a missing/invalid `gwsid` is minted and set on the response.
- Captivity is lazy (contract v1.1): an L1 oracle marks the session captive and frees the clone; the session's next request binds a clone (evicting the oldest clone-bound captive if none is free) and uses L2. Evidence (canary/honeytoken) marks captive and binds immediately. An evicted session stays captive and rebinds on its next request.
- Rules (`classifier.Rule`): scopes `param`, `param_present`, `all`; no expiry without `ttl_s`; persisted to `RULES_PATH` (default `rules.json` next to `RECORD_PATH`) and reloaded at start; per-rule `stats` in `GET /_admin/rules`. An inconclusive clone denies only on a strict match (`Result.rule_strict`).
- Suspect with no free clone: evict the oldest clone-bound captive, then deny if a rule matched or the request is high-signal (`schema:`/`grammar:`/`dup_query:` reasons), else prod.
- An untrusted identity whose cookie session is captive stays captive even if it starts sending a prod token. Trusted identities are never routed to a clone's output.
- Clone requests carry `x-imm-uid/role` whenever the identity came from a prod token (L1 and L2), since prod tokens do not verify inside a clone.
- A clone that errors is retired (fleet replaces it); the request then follows the "no clone" branch. Captive/evidence requests never fall back to prod: they are denied.
- Recordings redact `Authorization`, `Cookie` and `x-sensitive` query/JSON/form values. `POST /_admin/reset` does not truncate the recording file.

Tests: `.venv/bin/pytest gateway/tests -q` (unit) and `.venv/bin/pytest acceptance/wp3_gateway -q`.
