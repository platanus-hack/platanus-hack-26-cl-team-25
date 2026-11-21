## traversal

This is a path-traversal bug: a request-supplied value reached the filesystem and resolved to
a path OUTSIDE the directories the server is allowed to serve. A correct fix normalises and
resolves the request path so that `.`/`..` segments (in every form the server decodes them,
including percent-encoded ones such as `%2e`) can never climb above the configured roots,
BEFORE the path is used to open a file. Fix the normalisation/decoding routine itself so the
invariant holds for all inputs; do not blocklist particular sequences, and do not break
legitimate paths that merely contain dots.

## other

Fix the confirmed root cause in the listed files with the smallest change that makes the
reported class of attack impossible for every input, without changing legitimate behaviour.
