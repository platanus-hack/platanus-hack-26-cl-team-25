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

## ssrf
## What a correct fix looks like (server-side request forgery)

The request value decides where the server connects to. Make the destination fixed, or check it against an
allowlist of the hosts the feature is meant to reach: parse the URL, take its host, resolve it, and refuse the
connection unless the address is allowed. Refuse private, loopback, link-local and metadata addresses (127.0.0.0/8,
10/8, 172.16/12, 192.168/16, 169.254/16, ::1, fc00::/7), schemes other than http(s), and redirects to another host;
connect to the address you checked, do not resolve again. Otherwise answer like a rejected input does today. Do not
block strings such as `localhost` or `127.` by hand: `2130706433`, `0x7f000001`, `0177.0.0.1`, `[::1]` and DNS names
that resolve to an internal address all get past that.

## cmdi
## What a correct fix looks like (command injection)

The request value ends up on a command line. Do not build a command string: run the program with an argument list and
no shell (`subprocess.run([...], shell=False)`, `execFile`, `ProcessBuilder` with separate arguments), validate the
value against the exact format the feature takes (a host name, a number) with an allowlist, and pass user data after
`--` when the program has options. If the feature can be done with a library call, do that instead of spawning a
process. Do not escape or strip shell metacharacters by hand.

## ssti
## What a correct fix looks like (server-side template injection)

The request value is compiled or evaluated as part of a template. Treat it as data: pass it to the template as a
variable (`render(template, name=value)`), never concatenate it into the template source, keep autoescaping on, and use
the engine's sandboxed environment when it has one. A template the user is meant to author needs a logic-less engine
or a sandbox, not a filter. Do not strip `{{`, `${` or `<%` by hand.

## deser
## What a correct fix looks like (insecure deserialization)

The request value is deserialized with a format that can build arbitrary objects (pickle, Java ObjectInputStream,
PHP `unserialize`, `yaml.load`, node-serialize). Replace it with a data-only format parsed by the standard parser
(JSON), or the safe loader (`yaml.safe_load`), and validate the parsed structure against the fields you expect. Never
unpickle or unserialize untrusted input, and do not try to blocklist gadget classes.

## xxe
## What a correct fix looks like (XML external entity)

The XML parser resolves external entities or DTDs named in the request body. Turn that off in the parser: DTDs and
external entities disabled (`defusedxml` in Python; `disallow-doctype-decl` and secure processing in Java;
`LIBXML_NONET` without `LIBXML_NOENT` in PHP; `noent: false` in Node parsers), or reject any document that has a
DOCTYPE. Documents without a DOCTYPE must parse exactly as before.

## redirect
## What a correct fix looks like (open redirect)

The redirect target comes from the request. Redirect only to a path of this site: accept a relative target that starts
with a single `/` (not `//` and not `/\`), or compare the parsed host with an allowlist of your own hosts; otherwise
redirect to a fixed default page. Do not test with `startswith("http")` or a substring: `//evil.example`,
`/\evil.example` and `https://evil.example@your.host/` get past those.

## other
Find the root cause at the reported sink and fix it in the narrowest way that keeps every
legitimate request working the same.
