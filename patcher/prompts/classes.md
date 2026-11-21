## sqli
## What a correct fix looks like (SQL injection)

The request value reaches an SQL statement by string concatenation. Make the statement a
parameterised query: keep the SQL text constant, use `?` placeholders and pass the values
in the parameter tuple/list that the helper already accepts. Keep the exact same matching
semantics (for example, if the old code wrapped the value in `%` for LIKE, put the `%`
into the bound value, not into the SQL text). Do not escape or strip quotes by hand.

## traversal
## What a correct fix looks like (path traversal)

The request value is joined to a directory and the resulting path is opened without
checking where it really points. Resolve the final path with `os.path.realpath` and
require that it is inside the resolved base directory (for example with
`os.path.commonpath`); otherwise answer exactly like a missing file does today (404).
Do not filter characters such as `..` or `/` by hand: the containment check on the
resolved path is the fix. Names with dots inside the directory must keep working.

## idor
## What a correct fix looks like (missing ownership check)

The handler authenticates the caller but returns a resource that belongs to another user.
Keep the authentication call, keep its result, and check that the resource's owner id
equals the caller's uid, or that the caller's role is admin; otherwise answer exactly like
a missing resource does today (404). If the query does not select the owner column, add
it. The owner and admins must keep getting the same response as before.

## other
## What a correct fix looks like

Find the root cause at the reported sink and fix it in the narrowest way that keeps every
legitimate request working the same.
