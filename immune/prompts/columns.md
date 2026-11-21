## Step: classify the database columns (`.immune/shadow/columns.yaml`)

Read `.immune/context/schema.md` (tables, columns, types, keys, row counts and value *shapes* - never real
values) and the app code that reads/writes each table. Decide, for every table:

- `public: true` - data that every user may see (catalogue, reference data). Copied verbatim to the shadow.
- otherwise `owner:` who the rows belong to - a column holding the owning user's id (`user_id`, `owner_id`, ...;
  for the users table itself its id column), or `{via: <fk column>, table: <parent table>}` when ownership
  comes through a parent row. A table may have no owner (omit `owner`) only if no user owns its rows.
- `private: [...]` - columns with personal or user-authored content (names, e-mails, phones, addresses,
  free text, titles, notes, bodies, ...). In the shadow they are replaced by synthetic values carrying the
  owner's marker. When unsure whether a text column is private, make it private.
- `secret: [...]` - credentials and anything that grants access (password hashes, session/API/reset tokens,
  salts, keys). Replaced by random strings of the same shape. A session token that is the table's text
  primary key may be listed as secret.

Never list primary-key or foreign-key columns as private (ids and relations must stay identical). Every
table of the schema must appear under `tables`.

Top-level keys:
- `users_table`, `user_id_column`, `role_column` (if any);
- `login_column` (the column users log in with) and `secret_column` (the password hash column), if the
  app has password login;
- `routes`: map each OpenAPI **path parameter name** (e.g. `note_id`) to the `{table, column}` it selects;
- `why`: a mapping `"table.column": "one-line justification"` for every private/secret column and
  `"table": "..."` for every public table.

Format example (illustrative names only):

```yaml
users_table: users
user_id_column: id
role_column: role
login_column: email
secret_column: password_hash
tables:
  users: {owner: id, private: [email, name], secret: [password_hash]}
  posts: {owner: author_id, private: [title, body]}
  comments: {owner: {via: post_id, table: posts}, private: [text]}
  categories: {public: true}
routes:
  post_id: {table: posts, column: id}
why:
  users.email: personal contact data
  categories: shared reference data shown to everyone
```
