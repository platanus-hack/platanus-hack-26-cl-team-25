"""Native call stacks (strace -k) for file/proc/net evidence: parsing, filtering, file:line resolution.

The frame lines below are real output of strace 6.13 (`-f -y -qq -k`) on a C program built with -g:
handler() calls read_file() which open()s the path.
"""
import struct

from sidecar import nativestack, observer, strace, tracer

LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
REAL = f"""\
10    openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>
 > {LIBC}() [0x8f3a7]
 > {LIBC}(__open64+0x4d) [0x10353d]
 > /w/t(read_file+0x22) [0x1168]
 > /w/t(handler+0x18) [0x1198]
 > /w/t(main+0x22) [0x11bc]
 > {LIBC}(__libc_start_main+0x85) [0x29d65]
 > /w/t(_start+0x21) [0x1081]
11    execve("/bin/sh", ["sh", "-c", "--", "true"], 0x7fffb13dfb70 /* 12 vars */) = 0
 > {LIBC}(execve+0x7) [0xddb57]
 > /w/t(spawn+0x10) [0x11f0]
"""


def parse(text):
    p, out = strace.Parser(default_pid=1), []
    for line in text.splitlines():
        sc = p.feed(line)
        if sc is not None:
            out.append(strace.observe(sc))
    return out


# ------------------------------------------------------------------ parsing
def test_frames_attach_to_the_syscall_printed_before_them():
    file_obs, exec_obs = parse(REAL)
    assert file_obs.kind == "file" and exec_obs.kind == "exec"
    assert [f[1] for f in file_obs.frames] == ["", "__open64", "read_file", "handler", "main", "__libc_start_main", "_start"]
    assert file_obs.frames[2] == ("/w/t", "read_file", 0x22, 0x1168)
    assert [f[1] for f in exec_obs.frames] == ["execve", "spawn"]      # not mixed up with the open before it


def test_frames_arrive_after_the_observation_and_fill_it_in_place():
    p = strace.Parser(default_pid=1)
    obs = strace.observe(p.feed('10    openat(AT_FDCWD</w>, "/etc/hostname", O_RDONLY) = 3</etc/hostname>'))
    assert obs.frames == []                                            # the stack is printed on the next lines
    p.feed(" > /w/t(read_file+0x22) [0x1168]")
    assert obs.frames == [("/w/t", "read_file", 0x22, 0x1168)]         # shared list: events built later see it


def test_frame_line_variants():
    assert strace.parse_frame(" > /lib/x.so() [0x1d2c0]") == ("/lib/x.so", "", 0, 0x1d2c0)
    assert strace.parse_frame(" > /lib/x.so(+0x0) [0xf98e9]") == ("/lib/x.so", "", 0, 0xf98e9)
    assert strace.parse_frame(" > /a b/app(main+0x5) [0x401000]") == ("/a b/app", "main", 5, 0x401000)
    assert strace.parse_frame(" > [0xdeadbeef]") == ("", "", 0, 0xdeadbeef)
    assert strace.parse_frame(" > No DWARF information found") is None
    assert strace.parse_frame("openat(AT_FDCWD</w>, ...) = 3") is None


def test_a_frame_line_without_a_syscall_is_ignored():
    assert strace.Parser().feed(" > /w/t(main+0x1) [0x1000]") is None


# ------------------------------------------------------------------ ELF address mapping
def elf_with_load(segments):
    """A minimal ELF64 little-endian image with the given (offset, filesz, vaddr) PT_LOAD program headers."""
    ehdr = bytearray(64)
    ehdr[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", ehdr, 0x20, 64)                  # e_phoff
    struct.pack_into("<HH", ehdr, 0x36, 56, len(segments))  # e_phentsize, e_phnum
    ph = b"".join(struct.pack("<IIQQQQQQ", 1, 5, off, va, va, size, size, 0x1000) for off, size, va in segments)
    return bytes(ehdr) + ph


def test_load_segments_and_virtual_address(tmp_path):
    # non-PIE: file offset 0x1000 is loaded at 0x401000, so strace's offset 0x1168 is address 0x401168
    f = tmp_path / "bin"
    f.write_bytes(elf_with_load([(0, 0x570, 0x400000), (0x1000, 0x1dd, 0x401000)]))
    segs = nativestack.load_segments(str(f))
    assert segs == [(0, 0x570, 0x400000), (0x1000, 0x1dd, 0x401000)]
    assert nativestack.vaddr_of(segs, 0x1168) == 0x401168
    assert nativestack.vaddr_of(segs, 0x9999) is None
    pie = tmp_path / "pie"
    pie.write_bytes(elf_with_load([(0x1000, 0x1f1, 0x1000)]))      # PIE: virtual address == offset
    assert nativestack.vaddr_of(nativestack.load_segments(str(pie)), 0x1168) == 0x1168


def test_load_segments_of_something_that_is_not_an_elf(tmp_path):
    f = tmp_path / "script"
    f.write_text("#!/bin/sh\n")
    assert nativestack.load_segments(str(f)) == []
    assert nativestack.load_segments(str(tmp_path / "missing")) == []


# ------------------------------------------------------------------ the stack of an event
def fake_addr2line(table):
    calls = []

    def run(binary, path, vaddrs, timeout=5.0):
        calls.append((path, list(vaddrs)))
        return [table.get(v, ("", "", 0)) for v in vaddrs]
    run.calls = calls
    return run


def stacker_for(tmp_path, table, **kw):
    # the app binary the frames name, readable through the root the sidecar sees (non-PIE layout)
    (tmp_path / "w").mkdir(exist_ok=True)
    (tmp_path / "w" / "t").write_bytes(elf_with_load([(0, 0x570, 0x400000), (0x1000, 0x1000, 0x401000)]))
    return nativestack.Stacker(root=lambda: str(tmp_path), runner=fake_addr2line(table), **kw)


def test_stack_is_outermost_first_ends_at_the_sink_and_drops_libc(tmp_path):
    table = {0x401168: ("read_file", "/src/t.c", 5), 0x401198: ("handler", "/src/t.c", 6),
             0x4011bc: ("main", "/src/t.c", 7)}
    st = stacker_for(tmp_path, table)
    stack = st(parse(REAL)[0].frames)
    assert stack == [{"file": "/src/t.c", "line": 7, "func": "main"},
                     {"file": "/src/t.c", "line": 6, "func": "handler"},
                     {"file": "/src/t.c", "line": 5, "func": "read_file"}]        # stack[-1] is the sink
    assert stack[-1]["func"] == "read_file"


def test_path_map_turns_the_build_path_into_the_repo_path(tmp_path):
    st = stacker_for(tmp_path, {0x401168: ("read_file", "/src/app/t.c", 5)}, path_map=[("/src", "services/c")])
    assert st(parse(REAL)[0].frames)[-1] == {"file": "services/c/app/t.c", "line": 5, "func": "read_file"}


def test_binary_without_debug_info_keeps_named_frames_as_function_only(tmp_path):
    st = stacker_for(tmp_path, {})                                   # addr2line knows nothing
    stack = st(parse(REAL)[0].frames)
    assert [f["func"] for f in stack] == ["main", "handler", "read_file"]      # _start / libc dropped, order kept
    assert all(f["file"] == "/w/t" and f["line"] == 0 for f in stack)


def test_in_a_debug_binary_unresolved_frames_are_libc_linked_statically(tmp_path):
    frames = [("/w/t", "__internal_syscall_cancel", 0x67, 0x1500), ("/w/t", "handler", 0x18, 0x1198),
              ("/w/t", "main", 0x22, 0x11bc)]
    st = stacker_for(tmp_path, {0x401198: ("handler", "/src/t.c", 6), 0x4011bc: ("main", "/src/t.c", 7)})
    assert [f["func"] for f in st(frames)] == ["main", "handler"]


def test_interpreters_and_vms_are_not_the_apps_code(tmp_path):
    frames = [("/usr/bin/python3.12", "_PyEval_EvalFrameDefault", 9, 0x500), ("/usr/bin/node", "uv_fs_open", 1, 0x600),
              ("/opt/java/bin/java", "", 0, 0x700), ("/w/t", "handler", 0x18, 0x1198)]
    st = stacker_for(tmp_path, {})
    assert [f["func"] for f in st(frames)] == ["handler"]


def test_include_and_exclude_globs(tmp_path):
    frames = [("/w/t", "handler", 1, 0x1198), ("/w/vendor/libfoo.so", "foo", 1, 0x10)]
    assert [f["func"] for f in stacker_for(tmp_path, {}, exclude=["*/vendor/*"])(frames)] == ["handler"]
    assert [f["func"] for f in stacker_for(tmp_path, {}, include=["/w/vendor/*"])(frames)] == ["foo"]


def test_one_addr2line_call_per_binary_and_results_are_cached(tmp_path):
    st = stacker_for(tmp_path, {0x401168: ("read_file", "/src/t.c", 5), 0x401198: ("handler", "/src/t.c", 6)})
    frames = parse(REAL)[0].frames
    st(frames)
    st(frames)
    assert len(st.runner.calls) == 1                                  # one call for all the frames of the binary...
    assert sorted(st.runner.calls[0][1]) == [0x401081, 0x401168, 0x401198, 0x4011bc]   # ..._start included


def test_a_failing_addr2line_degrades_to_function_names(tmp_path):
    def boom(*a, **k):
        raise RuntimeError("addr2line exploded")
    st = stacker_for(tmp_path, {})
    st.runner = boom
    assert [f["func"] for f in st(parse(REAL)[0].frames)] == ["main", "handler", "read_file"]


def test_stack_never_fails_the_event(tmp_path):
    st = stacker_for(tmp_path, {})
    assert st(["not a frame", 7]) == []                                # malformed input: empty, not an exception
    assert st([]) == [] and st(None) == []


def test_from_config():
    assert nativestack.Stacker.from_config(None) is None
    assert nativestack.Stacker.from_config(False) is None
    assert nativestack.Stacker.from_config({"enabled": False}) is None
    st = nativestack.Stacker.from_config({"exclude": ["*/x"], "path_map": [["/a", "/b"]], "max_frames": 3})
    assert st.exclude == ["*/x"] and st.path_map == [("/a", "/b")] and st.max_frames == 3
    assert nativestack.Stacker.from_config(True) is not None


def test_max_frames_keeps_the_innermost(tmp_path):
    frames = [("/w/t", f"f{i}", 1, 0x1100 + i) for i in range(10)]            # f0 is the innermost
    st = stacker_for(tmp_path, {}, max_frames=3)
    assert [f["func"] for f in st(frames)] == ["f2", "f1", "f0"]


# ------------------------------------------------------------------ events
def make_observer(tmp_path, table):
    return observer.Observer(["/app/static"], stacker=stacker_for(tmp_path, table))


def test_file_event_carries_the_native_stack(tmp_path):
    obs = make_observer(tmp_path, {0x401168: ("read_file", "/src/t.c", 5), 0x401198: ("handler", "/src/t.c", 6)})
    rec = obs.begin()
    for o in parse(REAL):
        obs.on_obs(o)
    events = obs.system_events(rec)
    file_ev = next(e for e in events if e["oracle"] == "file")
    assert file_ev["stack"][-1] == {"file": "/src/t.c", "line": 5, "func": "read_file"}
    assert [e["oracle"] for e in events] == ["file", "proc"]
    assert events[1]["stack"][-1]["func"] == "spawn"                       # the exec has its own stack


def test_without_a_stacker_events_keep_an_empty_stack(tmp_path):
    obs = observer.Observer(["/app/static"])
    rec = obs.begin()
    for o in parse(REAL):
        obs.on_obs(o)
    assert [e["stack"] for e in obs.system_events(rec)] == [[], []]


def test_response_marker_event_keeps_the_stack_of_the_open_it_leaked(tmp_path):
    obs = make_observer(tmp_path, {0x401168: ("read_file", "/src/t.c", 5)})
    rec = obs.begin()
    for o in parse(REAL):
        obs.on_obs(o)
    markers = {"MKAAAAAAAAAA": {"path": "/etc/hostname"}}
    events = observer.marker_events(markers, {}, b"host MKAAAAAAAAAA", obs.system_events(rec))
    ev = next(e for e in events if e["oracle"] == "file")
    assert ev["detail"]["observed"] == "response+syscall"
    assert ev["stack"][-1]["func"] == "read_file"


# ------------------------------------------------------------------ strace arguments
def test_k_is_only_added_when_native_stacks_are_on():
    assert "-k" not in tracer.base_args(0)
    on = tracer.base_args(48)
    assert "-k" in on and "--stack-trace-frame-limit=48" in on
    assert "-k" not in tracer.docker_cmd("app", "immune-strace:1", "t")
    assert "-k" in tracer.docker_cmd("app", "immune-strace:1", "t", stack=32)


def test_glibc_internals_of_a_static_binary_are_not_the_apps_code(tmp_path):
    # real strace -k output for a static build: the unwinder sees only __internal_syscall_cancel
    frames = [("/w/t", "__internal_syscall_cancel", 0x67, 0x685c7)]
    assert stacker_for(tmp_path, {})(frames) == []
    # a symbol the app named itself is kept, even next to libc internals
    frames = [("/w/t", "__open64", 5, 0x1500), ("/w/t", "serve_file", 9, 0x1600), ("/w/t", "__libc_start_main", 1, 0x1700)]
    assert [f["func"] for f in stacker_for(tmp_path, {})(frames)] == ["serve_file"]
