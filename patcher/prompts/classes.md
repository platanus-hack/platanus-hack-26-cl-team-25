## sqli
The request value reaches an SQL statement by string concatenation or interpolation. Make the
statement a parameterised query: keep the SQL text constant, use the placeholder style of the
database driver the code already uses$placeholder_hint and pass the values in the parameter
list that the query call already accepts. Keep the exact same matching semantics (for example,
if the old code wrapped the value in `%` for LIKE/ILIKE, put the `%` into the bound value, not
into the SQL text). Do not escape, strip or reject quotes by hand.

## traversal
The request value is joined to a directory and the resulting path is opened without checking
where it really points. Resolve the final path$resolve_hint and require that it is inside the
resolved base directory; otherwise answer exactly like a missing file does today (same status
and body). Do not filter characters such as `..` or `/` by hand: the containment check on the
resolved path is the fix. File names with several dots and files in subdirectories must keep
working.

## idor
The handler authenticates the caller but returns a resource that belongs to another user. Keep
the authentication call and its result, and either restrict the lookup to the caller (the owner
column in the WHERE clause, with the caller's id as a bound parameter) or check that the
resource's owner id equals the caller's id; admins keep access if the code has an admin notion.
Otherwise answer exactly like a missing resource does today (same status and body). If the query
does not select the owner column, add it. The owner must keep getting the same response as before.

## other
Find the root cause at the reported sink and fix it in the narrowest way that keeps every
legitimate request working the same.
