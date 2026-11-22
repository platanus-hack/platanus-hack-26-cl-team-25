## authz

This is a broken-access-control bug: a privileged operation was carried out for a caller whose
identity was never established or never checked. A correct fix authorises the operation itself
— at the point where the privileged action is performed — using the identity the connection or
request already carries, and refuses the action when that identity is missing or insufficient.
Establish the identity once where the connection/request is accepted, and gate every privileged
operation on it; do not rely on the client to say who it is, and do not only fix the one
operation named in the evidence if the same gap applies to its siblings.

## traversal

This is a path-traversal bug: a request-supplied value reached the filesystem and resolved to
a path OUTSIDE the directory the handler is allowed to serve. A correct fix constrains the
request-supplied path so it can never climb above that directory, BEFORE it is used, by
resolving to a canonical form and checking containment in the intended base directory.

## other

Fix the confirmed root cause in the listed files with the smallest change that makes the
reported class of attack impossible for every input, without changing legitimate behaviour.
