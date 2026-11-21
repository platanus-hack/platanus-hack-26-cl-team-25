"""Unit tests for sidecar.strace (line parser + classification). Lines are verbatim strace 6.13 output
captured on this host (arm64, -f -y -qq), plus the -o file prefix variant."""
from sidecar import strace
from sidecar.observer import Observer


def obs_of(lines, cwd=None):
    p = strace.Parser(default_pid=1)
    out = []
    for l in lines:
        sc = p.feed(l)
        if sc is not None:
            o = strace.observe(sc, (lambda pid: cwd) if cwd else None)
            if o is not None:
                out.append(o)
    return out


def test_successful_open_uses_kernel_path_of_returned_fd():
    [o] = obs_of(['[pid     1] openat(AT_FDCWD</usr>, "lib/../../etc/hostname", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 17</etc/hostname>'])
    assert o.kind == "file" and o.pid == 1
    assert o.detail == {"path": "lib/../../etc/hostname", "realpath": "/etc/hostname"}


def test_o_file_prefix_variant():
    [o] = obs_of(['1     openat(AT_FDCWD</>, "/etc/hostname", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = 23</etc/hostname>'])
    assert o.pid == 1 and o.detail["realpath"] == "/etc/hostname"


def test_failed_open_does_not_count():
    assert obs_of(['[pid     1] openat(AT_FDCWD</usr>, "nope", O_RDONLY|O_LARGEFILE|O_CLOEXEC) = -1 ENOENT (No such file or directory)']) == []
    assert obs_of(['openat(AT_FDCWD</app>, "/etc/shadow", O_RDONLY) = -1 EACCES (Permission denied)']) == []


def test_relative_path_against_at_fdcwd_without_fd_decoration():
    # e.g. strace without -y: the base comes from AT_FDCWD</cwd> if present, else /proc/<pid>/cwd
    [o] = obs_of(['openat(AT_FDCWD</app/static>, "../../etc/passwd", O_RDONLY) = 3'])
    assert o.detail["realpath"] == "/etc/passwd"
    [o] = obs_of(['openat(AT_FDCWD, "sub/../x.txt", O_RDONLY) = 3'], cwd="/srv/www")
    assert o.detail["realpath"] == "/srv/www/x.txt"


def test_openat_relative_to_directory_fd():
    [o] = obs_of(['openat(5</app/static>, "manual.v1.txt", O_RDONLY) = 6</app/static/manual.v1.txt>'])
    assert o.detail["realpath"] == "/app/static/manual.v1.txt"
    [o] = obs_of(['openat(5</app/static>, "../secret", O_RDONLY) = 6'])
    assert o.detail["realpath"] == "/app/secret"


def test_unfinished_and_resumed_are_joined_per_pid():
    lines = ['[pid    14] openat(AT_FDCWD</usr>, "/etc/passwd", O_RDONLY|O_LARGEFILE|O_CLOEXEC <unfinished ...>',
             '[pid     1] openat(AT_FDCWD</usr>, "nope", O_RDONLY) = -1 ENOENT (No such file or directory)',
             '[pid    14] <... openat resumed>) = 17</etc/passwd>']
    [o] = obs_of(lines)
    assert o.pid == 14 and o.detail == {"path": "/etc/passwd", "realpath": "/etc/passwd"}


def test_resumed_failure_does_not_count_and_orphan_resumed_is_ignored():
    lines = ['[pid 7] openat(AT_FDCWD</>, "/x", O_RDONLY <unfinished ...>',
             '[pid 7] <... openat resumed>) = -1 ENOENT (No such file or directory)',
             '[pid 9] <... openat resumed>) = 3</y>']
    assert obs_of(lines) == []


def test_paths_with_escapes_commas_and_spaces():
    [o] = obs_of([r'openat(AT_FDCWD</a, b>, "we\"ird, name\n.txt", O_RDONLY) = 3</a, b/we"ird, name\n.txt>'])
    assert o.detail["path"] == 'we"ird, name\n.txt'
    assert strace.unquote(r'"\303\251t\x41"') == "étA"


def test_deleted_suffix_is_stripped():
    [o] = obs_of(['openat(AT_FDCWD</>, "/tmp/x", O_RDONLY) = 3</tmp/x (deleted)>'])
    assert o.detail["realpath"] == "/tmp/x"


def test_execve_success_with_argv_and_failure_ignored():
    lines = ['[pid    31] execve("/usr/local/sbin/sh", ["sh", "-c", "id"], 0xe85687ed4920 /* 7 vars */) = -1 ENOENT (No such file or directory)',
             '[pid    31] execve("/bin/sh", ["/bin/sh", "-c", "echo resolving x; id"], 0xe85687ed4920 /* 7 vars */) = 0']
    [o] = obs_of(lines)
    assert o.kind == "exec" and o.detail == {"path": "/bin/sh", "argv": ["/bin/sh", "-c", "echo resolving x; id"]}


def test_execve_unfinished_resumed():
    lines = ['[pid 40] execve("/bin/id", ["id"], 0xffff /* 3 vars */ <unfinished ...>',
             '[pid 40] <... execve resumed>) = 0']
    [o] = obs_of(lines)
    assert o.detail["argv"] == ["id"]


def test_clone_thread_is_not_a_process_but_fork_is():
    t = 'clone(child_stack=0xffff, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tid=[33], tls=0xffff, child_tidptr=0xffff) = 33'
    f = 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xffff) = 34'
    c3 = 'clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0xffff, stack_size=0x9000}, 88) = 35'
    out = obs_of([t, f, c3])
    assert [(o.kind, o.detail["child"]) for o in out] == [("fork", 34), ("fork", 35)]


def test_connect_inet_inet6_unix():
    [a, b, c] = obs_of([
        '[pid     1] connect(19<socket:[2246430]>, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("10.9.9.9")}, 16) = -1 EINPROGRESS (Operation now in progress)',
        'connect(20<TCP:[3]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = 0',
        'connect(21<UNIX:[9]>, {sa_family=AF_UNIX, sun_path="/var/run/docker.sock"}, 110) = 0'])
    assert (a.detail["family"], a.detail["address"], a.detail["port"]) == ("AF_INET", "10.9.9.9", 5432)
    assert (b.detail["address"], b.detail["port"]) == ("2001:db8::1", 443)
    assert c.detail["address"] == "/var/run/docker.sock"


def test_sendto_with_and_without_address():
    out = obs_of(['sendto(5<UDP:[1]>, "\\x12\\x34", 2, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 2',
                  'sendto(6<TCP:[2]>, "GET / HTTP/1.1", 14, MSG_NOSIGNAL, NULL, 0) = 14'])
    assert len(out) == 1 and out[0].detail["port"] == 53


def test_noise_lines_ignored():
    assert obs_of(['--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=31} ---', '+++ exited with 0 +++',
                   'strace: Process 7 attached', '', '[pid 3] exit_group(0) = ?']) == []


def test_observer_windows_learning_and_roots():
    ob = Observer(["/app/static"])
    mk = lambda p: strace.Observation("file", 1, {"path": p, "realpath": p})
    ob.learning = True
    ob.on_obs(mk("/etc/mime.types"))
    ob.learning = False
    ob.on_obs(mk("/etc/passwd"))          # between requests: dropped
    assert ob.outside == 1
    ob.begin()
    for p in ("/etc/mime.types", "/app/static/a.b.txt", "/app/staticx", "/etc/hostname"):
        ob.on_obs(mk(p))
    rec = ob.end()
    evs = ob.system_events(rec)
    assert [e["detail"]["realpath"] for e in evs] == ["/app/staticx", "/etc/hostname"]
    assert all(e["oracle"] == "file" and e["stack"] == [] for e in evs)


def test_observer_net_rules():
    ob = Observer([])
    n = lambda a, port, fam="AF_INET": strace.Observation("net", 1, {"syscall": "connect", "family": fam, "address": a, "port": port, "result": "0"})
    ob.begin()
    for o in (n("127.0.0.1", 5432), n("::1", 80, "AF_INET6"), n("10.0.0.5", 80), n("127.0.0.11", 53)):
        ob.on_obs(o)
    evs = ob.system_events(ob.end())
    assert [(e["detail"]["address"], e["detail"]["port"]) for e in evs] == [("10.0.0.5", 80), ("127.0.0.11", 53)]


def test_exec_after_fork_reported_once():
    ob = Observer([])
    ob.begin()
    ob.on_obs(strace.Observation("fork", 1, {"child": 50, "syscall": "clone3"}))
    ob.on_obs(strace.Observation("exec", 50, {"path": "/bin/sh", "argv": ["sh"]}))
    ob.on_obs(strace.Observation("fork", 1, {"child": 51, "syscall": "fork"}))
    evs = ob.system_events(ob.end())
    assert [e["detail"] for e in evs] == [{"path": "/bin/sh", "argv": ["sh"]}, {"syscall": "fork", "child": 51}]
