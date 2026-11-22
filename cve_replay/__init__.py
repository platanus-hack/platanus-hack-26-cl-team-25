"""CVE-replay: run the immune system's oracle + patcher against a real third-party
service pinned to the commit *before* an upstream security patch.

Demo target: Apache httpd 2.4.49, vulnerable to CVE-2021-41773 (path traversal). The
file oracle (out-of-process, strace) catches the exploit opening a file outside the
served roots; the generalised patcher proposes the root-cause fix; we rebuild httpd
with it and show the exploit blocked and legitimate traffic intact.
"""
