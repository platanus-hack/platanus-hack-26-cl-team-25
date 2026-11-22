## traversal

This is a path-traversal bug: a request-supplied value reached the filesystem and resolved to
a path OUTSIDE the directory the handler is allowed to serve. A correct fix constrains the
request-supplied path so it can never climb above that directory, BEFORE it is used to open
or serve a file: resolve the path to a canonical form and ensure the final path really is
contained in the intended base directory. Note that cleaning a *relative* path does not remove
leading parent references. Fix the path handling itself so the invariant holds for all inputs;
do not blocklist particular sequences, and do not break legitimate file names that contain dots.

## other

Fix the confirmed root cause in the listed files with the smallest change that makes the
reported class of attack impossible for every input, without changing legitimate behaviour.
