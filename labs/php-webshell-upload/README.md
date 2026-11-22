# Lab: PHP webshell via unvalidated upload — what our system does, honestly

Replicates the real attacker entry (unrestricted file upload → webshell → RCE) in a contained
container and measures, with our own product code, what each layer catches. No claim is made that
is not reproduced by a command in this directory.

## The attacker entry (reproduced)

`app/upload.php` stores the uploaded file under the webroot with its original name and extension,
with no type or content check — the classic bug. Driven entirely inside the container
(`--network none`, so the box has no network and the webshell only ever runs a harmless `id`):

```
upload avatar.png (legit)                      -> stored:/uploads/avatar.png
upload shell.php as Content-Type: image/png    -> stored:/uploads/shell.php
GET /uploads/shell.php?cmd=id                  -> uid=33(www-data) gid=33(www-data)   # RCE
```

## What our system catches — three layers, honestly

**1. Recon → caught, shipped.** A webshell attacker's first move is scanning for panels and
secrets. Every such path hits the gateway's L0 decoy layer, which the product already ships:

```
/wp-login.php /xmlrpc.php /config.php /admin.php /phpmyadmin /.env /.git/config /server-status
   -> l0.is_scanner_path == True  -> SUSPECT "scanner" -> deterministic decoy, session diverted
```

So the honeypot genuinely engages the attacker during reconnaissance.

**2. The upload → NOT caught.** Stage-1 classification ignores uploaded file bodies:

```
classifier.parse_multipart_fields(<multipart with shell.php>)  -> []   # the .php body is invisible
classifier.traversal_in_path("/uploads/shell.php")             -> False
```

The malicious upload passes stage-1 unflagged. **Gap #1.**

**3. The RCE → not caught as shipped; caught with a small, demonstrated addition.**
The product already has the right idea for execution: `shadow/instrument.py` installs a
`sys.addaudithook` that records a `proc` event on `subprocess.Popen`/`os.system`/`os.exec*`/
`os.*spawn`/`os.fork`, and the gateway already diverts an untrusted session to a shadow-clone
honeypot once an oracle fires. But that oracle is a **Python in-process** audit hook and the shadow
clone runs the app as an in-process Python ASGI app. A PHP webshell runs in php/apache — a
different runtime — so the shipped oracle never sees it. **Gap #2.**

The fix is one syscall away from the oracle we already built for Apache (`cve_replay`, `openat`).
`cve_replay`'s `ProcessSpawnOracle` traces `execve` out of process (run.py now runs it for every target). A web server never spawns a process after
startup, so any request-time exec is the signal:

```
[execve-oracle] request-time process spawns after startup: 1
[execve-oracle]   FIRED: execve /usr/bin/id argv=["id"]
[execve-oracle] verdict=oracle class=exec
```

That `oracle.fired class=exec` plugs into the gateway's existing captive→shadow diversion — the
same honeypot path the recon layer uses.

## Verdict

| attack stage | shipped product | with the additions below |
|---|---|---|
| recon / scanning | **engaged by L0 decoy honeypot** | same |
| malicious upload stored | not flagged | flagged (upload-type check) |
| webshell RCE | not seen (Python-only oracle) | **oracle fires, session → honeypot** |

## Two improvements, both small

1. **Classifier upload-type check** — compare an uploaded part's content-type/magic against the
   field's declared schema. A `.php` body sent as `image/png` to an avatar field is an obvious
   mismatch → SUSPECT → diverted to a clone before it is ever stored on prod.
2. **Out-of-process execve oracle** — generalize the `openat` strace oracle to `execve`; catches a
   webshell's process spawn on any runtime (PHP, Node, …), feeding the existing honeypot diversion.

## Run it

```
docker build -t php-webshell-lab:vuln -f Dockerfile.vuln .
docker run -d --name php-lab --network none php-webshell-lab:vuln
# drive upload+exec via `docker exec php-lab curl 127.0.0.1 ...`, then:
docker cp php-lab:/tmp/trace.log /tmp/php-trace.log
python detect.py --trace /tmp/php-trace.log   # uses cve_replay.oracle.ProcessSpawnOracle
```
