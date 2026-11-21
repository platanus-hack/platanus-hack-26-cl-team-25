## Step: mark the OpenAPI operations (`.immune/shadow/marks.yaml`)

Read `.immune/context/openapi.md` (every operation as `METHOD /path`, its parameters and body
properties), `.immune/shadow/columns.yaml` (which tables are owned by a user) and the route handlers.

- `owner_scoped`: every operation whose path parameter selects **one resource that belongs to one user**
  (a row of an owner-scoped table, or a user's own record), whether or not the code checks ownership -
  you are describing what the resource is, not whether the code is correct. Untrusted identities that
  touch these operations are routed to the shadow first.
- `sensitive`: parameters and body properties that carry credentials or secrets (passwords, tokens, API
  keys, card numbers). They are never grammar-checked and are redacted in recordings. `in` is one of
  `query | path | header | cookie | body` (`body` for JSON/form body properties).

Use the operation keys exactly as listed (`GET /notes/{note_id}`). Every entry needs a `why`.

```yaml
owner_scoped:
  - op: GET /posts/{post_id}
    why: a post belongs to its author (posts.author_id)
sensitive:
  - op: POST /login
    in: body
    name: password
    why: credential
```
