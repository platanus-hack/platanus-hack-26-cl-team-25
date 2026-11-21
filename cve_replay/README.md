# cve_replay — stand the product on a real pre-patch release

A demo mode that runs the whole immune loop against a **real service pinned to the commit
before its upstream security patch**, to show we would have caught and fixed the bug ahead of
time. First target: **Apache httpd 2.4.49 / CVE-2021-41773** (path traversal).

The point: this is the *product's own flow* end to end, not a hand-written analysis. The LLM
patcher only ever sees generic runtime evidence — it is never told the CVE, the project, or the
version (enforced by `tests/test_oracle.py::test_prompt_never_reveals_the_cve_or_project`).

## The loop

1. **Stand up the vulnerable release** — `httpd:2.4.49` with a vulnerable config, under
   `strace` (file oracle, see below). `Dockerfile.vuln` + `entrypoint-strace.sh`.
2. **Fire the public PoC** `GET /static/.%2e/.%2e/.%2e/.%2e/etc/passwd` → leaks `/etc/passwd`.
3. **Detect out of process** — the `FileEscapeOracle` reads the syscall trace and fires when a
   request opens a file **outside the roots the server may serve** that normal traffic never
   touched. Works for a C server because it watches `open`/`openat`, not Python internals.
4. **Incident → `patcher.propose`** — generic evidence (request, syscall, localised sink/stack,
   editable file `server/util.c`) goes to the real LLM patcher; it returns a diff.
5. **Rebuild the real binary** — `Dockerfile.build` compiles httpd 2.4.49 from source *with the
   diff applied* and re-probes: PoC blocked? legit `/` still 200? bypass blocked?
6. **Iterate like upstream did** — the first proposal blocks the direct traversal but the
   double-encoded bypass (`%%32%65`, the CVE-2021-42013 bypass of Apache's own 2.4.50 fix) still
   leaks. That observation is fed back as runtime evidence and the patcher produces a second,
   stronger diff that blocks both — mirroring upstream going 2.4.50 → 2.4.51.

## Verified result

| request | vulnerable 2.4.49 | our v1 patch | our v2 patch |
|---|---|---|---|
| PoC `/.%2e/…/etc/passwd` | 200, leaks | **400 blocked** | **400 blocked** |
| bypass `/.%%32%65/…/etc/passwd` | 200, leaks | 200, leaks | **400 blocked** |
| legit `/` | 200 | 200 | 200 |

Both diffs touch **only `server/util.c`**.

## Run it

```bash
python -m cve_replay.run prepare   # fetch httpd-2.4.49 source + build the vulnerable image
python -m cve_replay.run detect    # PoC + oracle -> runs/<target>.incident.json
python -m cve_replay.run patch     # real LLM -> runs/<target>.patch.diff   (needs ANTHROPIC_API_KEY)
python -m cve_replay.run verify    # rebuild httpd with the diff, prove PoC blocked / legit ok
python -m cve_replay.run iterate   # feed the bypass back -> stronger diff (v2)
python -m cve_replay.run demo      # detect -> patch -> compare -> verify in one shot
```

Set `BUS_URL` + `BUS_TOKEN` to publish `oracle.fired` / `incident.opened` / `patch.diff` /
`verify.result` to the existing dashboard bus (no-op otherwise).

The upstream source tree (`releases/`) and run artifacts (`runs/`) are git-ignored; `prepare`
downloads the source.
