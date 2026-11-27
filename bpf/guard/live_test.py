#!/usr/bin/env python3
"""Live-kernel test of the core pack's objects, one object at a time.

Usage (as root, on a throwaway VM or privileged container whose kernel has
the BPF LSM enabled; needs bpftool and a bpffs at /sys/fs/bpf):

    python3 live_test.py <dir with the *.bpf.o files>

It loads and attaches each object with bpftool, fills its maps the way
README.md says the rule compiler must, and checks the verdicts (EPERM or
not), the ring-buffer events, the hit counters, the kill switch, the
never-block units and the guard_tgid exemption. It creates cgroups named
gt-*.scope, system.slice/sshd.service etc. under /sys/fs/cgroup and files
under /tmp/gt and /etc/gtprot. Never-block depends on a cgroup's depth in
the real hierarchy, so a container must share the host's cgroup namespace
(docker run --cgroupns=host), and the cases that need a unit to be exempt
run only when /sys/fs/cgroup is the kernel's root cgroup: set
GUARD_LIVE_ROOT_CGROUP=1 then. (A Docker engine that itself runs in a
nested cgroup namespace, as OrbStack's does, cannot reach it: there every
cgroup sits deeper than its path says, so the exempt cases are skipped and
only the "still blocked" ones are checked.) Every object is detached when its test ends (unpinning the
links). The module object is only loaded: a module load needs real modules.
"""
import ctypes, json, mmap, os, socket, struct, subprocess, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "/out"
FS = "/sys/fs/bpf"
libc = ctypes.CDLL(None, use_errno=True)
SYS_BPF = 280 if os.uname().machine == "aarch64" else 321
FAILS = []
ROOT_CGROUP = os.environ.get("GUARD_LIVE_ROOT_CGROUP") == "1"

def exempt_check(name, cond, detail=""):
    """A never-block case: needs the kernel's root cgroup (see the docstring)."""
    if ROOT_CGROUP:
        check(name, cond, detail)
    else:
        print("SKIP " + name + "  [not the root cgroup namespace]")

def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
    if not cond:
        FAILS.append(name)

def sh(*a, check_=True):
    r = subprocess.run(a, capture_output=True, text=True)
    if check_ and r.returncode:
        raise SystemExit(f"{a}: {r.stderr}{r.stdout}")
    return r

def load(obj):
    sh("rm", "-rf", f"{FS}/{obj}", f"{FS}/{obj}_m")
    sh("bpftool", "prog", "loadall", f"{OUT}/{obj}.bpf.o", f"{FS}/{obj}", "autoattach",
       "pinmaps", f"{FS}/{obj}_m")

def unload(obj):
    sh("rm", "-rf", f"{FS}/{obj}", f"{FS}/{obj}_m")

def hx(b):
    return [f"0x{x:02x}" for x in b]

def upd(obj, m, k, v):
    sh("bpftool", "map", "update", "pinned", f"{FS}/{obj}_m/{m}", "key", *hx(k), "value", *hx(v))

def rs(*slots):
    w = [0] * 16
    for s in slots:
        w[s // 64] |= 1 << (s % 64)
    return struct.pack("<16Q", *w)

def pathkey(p, prefix=True):
    b = p.encode()
    if not prefix:
        b += b"\0"
    return struct.pack("<I", len(b) * 8) + b.ljust(256, b"\0")

ANYPATH = struct.pack("<I", 0) + b"\0" * 256
ANYUNIT = b"\0" * 64
PORT_ANY = struct.pack("<I", 0x10000)

def unit(n):
    return n.encode().ljust(64, b"\0")

def rule(obj, slot, hook, action, enabled=1):
    upd(obj, "rules_meta", struct.pack("<I", slot), struct.pack("<IBBBx", slot, hook, action, enabled))

def config(obj, kill=0, tgid=0):
    upd(obj, "config", struct.pack("<I", 0), struct.pack("<BxxxI", kill, tgid))

def hits(obj, slot):
    return sum_percpu(obj, "hits", slot)

def sum_percpu(obj, m, slot):
    r = sh("bpftool", "-j", "map", "lookup", "pinned", f"{FS}/{obj}_m/{m}", "key", *hx(struct.pack("<I", slot)))
    j = json.loads(r.stdout)
    vals = j.get("values") or j.get("formatted", {}).get("values")
    tot = 0
    for v in vals:
        val = v["value"]
        if isinstance(val, list):
            tot += int.from_bytes(bytes(int(x, 16) for x in val), "little")
        else:
            tot += int(val)
    return tot

class Ring:
    def __init__(self, obj):
        path = f"{FS}/{obj}_m/events".encode()
        buf = ctypes.create_string_buffer(path)
        attr = struct.pack("<QIIi4x", ctypes.addressof(buf), 0, 0, 0)
        a = ctypes.create_string_buffer(attr)
        fd = libc.syscall(SYS_BPF, 7, a, len(attr))
        if fd < 0:
            raise OSError(ctypes.get_errno(), "BPF_OBJ_GET")
        self.size = 1 << 20
        pg = mmap.PAGESIZE
        self.cons = mmap.mmap(fd, pg, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=0)
        self.prod = mmap.mmap(fd, pg + 2 * self.size, mmap.MAP_SHARED, mmap.PROT_READ, offset=pg)
        self.pg = pg

    def drain(self):
        evs = []
        c = struct.unpack_from("<Q", self.cons, 0)[0]
        p = struct.unpack_from("<Q", self.prod, 0)[0]
        while c < p:
            off = self.pg + (c & (self.size - 1))
            ln, _ = struct.unpack_from("<II", self.prod, off)
            if ln & (1 << 31):
                break
            if not ln & (1 << 30):
                evs.append(parse(bytes(self.prod[off + 8: off + 8 + (ln & 0x3fffffff)])))
            c += ((ln & 0x3fffffff) + 8 + 7) & ~7
        struct.pack_into("<Q", self.cons, 0, c)
        return evs

def cstr(b):
    return b.split(b"\0", 1)[0].decode(errors="replace")

def parse(b):
    assert len(b) == 624, len(b)
    (ts, pid, ppid, uid, rid, hook, action, blocked, exe, target, addr, st, port, fam, un) = \
        struct.unpack_from("<QIIIIBBB256s256s16sBHB64s", b)
    return dict(ts=ts, pid=pid, ppid=ppid, uid=uid, rule=rid, hook=hook, action=action,
                blocked=blocked, exe=cstr(exe), target=cstr(target), addr=addr, port=port,
                family=fam, unit=cstr(un), sock_type=st)

def cg(name):
    os.makedirs(f"/sys/fs/cgroup/{name}", exist_ok=True)
    return name

def in_cg(name, code):
    """Run python `code` in a child placed in cgroup `name`; returns (rc, stdout)."""
    cg(name)
    def pre():
        with open(f"/sys/fs/cgroup/{name}/cgroup.procs", "w") as f:
            f.write("0")
    r = subprocess.run([sys.executable, "-c", code], preexec_fn=pre, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).strip()

CONNECT = """
import socket, errno, sys
s = socket.socket(); s.setblocking(False)
try:
    s.connect(("{ip}", {port}))
except BlockingIOError:
    print("inprogress"); sys.exit(0)
except PermissionError:
    print("eperm"); sys.exit(0)
except OSError as e:
    print("err", e.errno); sys.exit(0)
print("connected")
"""

H_EXEC, H_CONNECT, H_LISTEN, H_FILE, H_SETUID, H_MODULE, H_BPF = range(7)
ALERT, BLOCK = 0, 1

def wildcards(obj, slots, exe=True, unit_=True):
    if exe:
        upd(obj, "exe_prefix_lpm", ANYPATH, rs(*slots))
    if unit_:
        upd(obj, "unit_rules", ANYUNIT, rs(*slots))

def t_connect():
    o = "connect"
    load(o)
    r = Ring(o)
    config(o)
    # slot 3: block 1.2.3.4 any port, only in unit "gt-a.scope" and "sshd.service"
    rule(o, 3, H_CONNECT, BLOCK)
    upd(o, "exe_prefix_lpm", ANYPATH, rs(3))
    upd(o, "unit_rules", unit("gt-a.scope"), rs(3))
    upd(o, "unit_rules", unit("sshd.service"), rs(3))
    upd(o, "unit_rules", unit("sensr-agentx.service"), rs(3))
    upd(o, "net4_lpm", struct.pack("<I", 32) + socket.inet_aton("1.2.3.4"), rs(3))
    upd(o, "port_rules", PORT_ANY, rs(3))
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=80))
    check("connect: block rule denies 1.2.3.4", out == "eperm", out)
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.5", port=80))
    check("connect: other address not denied", out != "eperm", out)
    rc, out = in_cg("gt-b.scope", CONNECT.format(ip="1.2.3.4", port=80))
    check("connect: other unit not denied", out != "eperm", out)
    rc, out = in_cg("system.slice/sshd.service", CONNECT.format(ip="1.2.3.4", port=80))
    exempt_check("connect: never-block unit system.slice/sshd.service not denied", out != "eperm", out)
    rc, out = in_cg("system.slice/sensr-agentx.service", CONNECT.format(ip="1.2.3.4", port=80))
    check("connect: sensr-agentx.service is denied", out == "eperm", out)
    evs = [e for e in r.drain() if e["hook"] == H_CONNECT]
    blocked = [e for e in evs if e["blocked"]]
    nb = [e for e in evs if e["unit"] == "sshd.service"]
    check("connect: events for each match (gt-a, sshd, agentx)", len(evs) == 3, str(len(evs)))
    if evs:
        e = evs[0]
        check("connect: event fields", e["rule"] == 3 and e["action"] == BLOCK and e["family"] == 2
              and e["addr"][:4] == socket.inet_aton("1.2.3.4") and e["port"] == 80
              and e["unit"] == "gt-a.scope" and e["exe"] == "" and e["pid"] > 0 and e["ppid"] > 0,
              str(e))
    exempt_check("connect: never-block event says not blocked, action block",
                 len(nb) == 1 and nb[0]["blocked"] == 0 and nb[0]["action"] == BLOCK)
    exempt_check("connect: two blocked events", len(blocked) == 2, str(len(blocked)))
    check("connect: hits counted", hits(o, 3) == 3, str(hits(o, 3)))
    # never-block is by place, not name alone: a delegated subtree (as a
    # user's user@UID.service) naming a cgroup sshd.service is still blocked
    for fake in ["gt-u.slice/sshd.service", "gt-u.slice/gt-v.service/sshd.service",
                 "system.slice/gt-w.service/sshd.service", "sshd.service"]:
        rc, out = in_cg(fake, CONNECT.format(ip="1.2.3.4", port=80))
        check(f"connect: {fake} (not directly under system.slice) is denied", out == "eperm", out)
    # the root cgroup (kernel threads, usermode helpers such as modprobe)
    if ROOT_CGROUP:
        upd(o, "unit_rules", unit(""), rs(3))
        rc, out = in_cg("", CONNECT.format(ip="1.2.3.4", port=80))
        check("connect: the root cgroup is never blocked", out != "eperm", out)
        upd(o, "unit_rules", unit(""), rs())
    else:
        exempt_check("connect: the root cgroup is never blocked", False)
    r.drain()
    # port-specific: 1.2.3.4:443 only
    upd(o, "port_rules", PORT_ANY, rs())
    upd(o, "port_rules", struct.pack("<I", 443), rs(3))
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=80))
    check("connect: port rule leaves port 80 alone", out != "eperm", out)
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=443))
    check("connect: port rule denies port 443", out == "eperm", out)
    # alert and block both match: block wins; alert only: no deny
    rule(o, 1, H_CONNECT, ALERT)
    upd(o, "exe_prefix_lpm", ANYPATH, rs(1, 3))
    upd(o, "unit_rules", unit("gt-a.scope"), rs(1, 3))
    upd(o, "net4_lpm", struct.pack("<I", 32) + socket.inet_aton("1.2.3.4"), rs(1, 3))
    upd(o, "port_rules", struct.pack("<I", 443), rs(1, 3))
    r.drain()
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=443))
    evs = r.drain()
    check("connect: block preferred over lower alert slot", out == "eperm" and evs and evs[0]["rule"] == 3,
          f"{out} {evs[:1]}")
    rule(o, 3, H_CONNECT, BLOCK, enabled=0)
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=443))
    evs = r.drain()
    check("connect: disabled block rule -> alert only", out != "eperm" and evs and evs[0]["rule"] == 1
          and evs[0]["blocked"] == 0, f"{out} {evs[:1]}")
    rule(o, 3, H_CONNECT, BLOCK)
    # wrong hook in meta: no match
    rule(o, 1, H_LISTEN, ALERT)
    rule(o, 3, H_LISTEN, BLOCK)
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=443))
    check("connect: rules of another hook do not apply", out != "eperm" and not r.drain(), out)
    rule(o, 3, H_CONNECT, BLOCK)
    # kill switch
    config(o, kill=1)
    rc, out = in_cg("gt-a.scope", CONNECT.format(ip="1.2.3.4", port=443))
    evs = r.drain()
    check("connect: kill switch -> not denied, event still emitted", out != "eperm" and len(evs) == 1
          and evs[0]["blocked"] == 0, f"{out} {evs}")
    config(o)
    # IPv6
    upd(o, "net6_lpm", struct.pack("<I", 128) + socket.inet_pton(socket.AF_INET6, "2001:db8::1"), rs(3))
    upd(o, "port_rules", PORT_ANY, rs(3))
    code6 = """
import socket, sys
s = socket.socket(socket.AF_INET6); s.setblocking(False)
try: s.connect(("2001:db8::1", 80))
except PermissionError: print("eperm"); sys.exit()
except OSError as e: print("err", e.errno); sys.exit()
print("ok")
"""
    rc, out = in_cg("gt-a.scope", code6)
    check("connect: IPv6 block", out == "eperm", out)
    # IPv4-mapped IPv6 is the IPv4 address: net4_lpm, reported as AF_INET
    upd(o, "net4_lpm", struct.pack("<I", 32) + socket.inet_aton("1.2.3.4"), rs(3))
    r.drain()
    rc, out = in_cg("gt-a.scope", code6.replace("2001:db8::1", "::ffff:1.2.3.4"))
    evs = r.drain()
    check("connect: ::ffff:1.2.3.4 from an AF_INET6 socket hits the 1.2.3.4/32 block",
          out == "eperm" and len(evs) == 1 and evs[0]["family"] == 2
          and evs[0]["addr"] == socket.inet_aton("1.2.3.4") + b"\0" * 12, f"{out} {evs}")
    rc, out = in_cg("gt-a.scope", code6.replace("2001:db8::1", "::ffff:1.2.3.5"))
    check("connect: ::ffff:1.2.3.5 not denied", out != "eperm", out)
    # ring buffer overflow is counted in ringbuf_dropped
    r.drain()
    rc, out = in_cg("gt-a.scope", """
import socket
n = 0
for i in range(3000):
    s = socket.socket(); s.setblocking(False)
    try: s.connect(("1.2.3.4", 443))
    except PermissionError: n += 1
    except OSError: pass
    s.close()
print(n)
""")
    dropped = sum_percpu(o, "ringbuf_dropped", 0)
    evs = r.drain()
    check("connect: ring buffer overflow counted in ringbuf_dropped",
          out == "3000" and dropped > 0 and len(evs) + dropped == 3000, f"{out} events={len(evs)} dropped={dropped}")
    unload(o)

def t_exec():
    o = "exec"
    os.makedirs("/tmp/gt", exist_ok=True)
    sh("cp", "/bin/true", "/tmp/gt/true")
    # a process that predates the load: it waits for a line, then runs /tmp/gt/true
    cg("gt-a.scope")
    def pre():
        open("/sys/fs/cgroup/gt-a.scope/cgroup.procs", "w").write("0")
    old = subprocess.Popen([sys.executable, "-c",
                            "import subprocess; input(); subprocess.run(['/tmp/gt/true'])"],
                           preexec_fn=pre, stdin=subprocess.PIPE, text=True)
    load(o)
    r = Ring(o)
    config(o)
    rule(o, 5, H_EXEC, ALERT)
    wildcards(o, [5])
    upd(o, "path_prefix_lpm", pathkey("/tmp/gt/"), rs(5))
    r.drain()
    # the loader reads the seeding iterator once (bpftool pinned its link)
    seeded = sh("cat", f"{FS}/{o}/guard_seed_exe", check_=False)
    old.communicate("\n")
    evs = [e for e in r.drain() if e["hook"] == H_EXEC]
    check("exec: the seeding iterator gives a task that predates the load its exe",
          seeded.returncode == 0 and len(evs) == 1 and evs[0]["exe"].startswith("/usr/bin/python"),
          f"{seeded.returncode} {seeded.stderr} {evs}")
    rc, out = in_cg("gt-a.scope", "import subprocess; print(subprocess.run(['/tmp/gt/true']).returncode)")
    evs = [e for e in r.drain() if e["hook"] == H_EXEC]
    check("exec: alert on /tmp/gt/true", out == "0" and len(evs) == 1 and evs[0]["target"] == "/tmp/gt/true"
          and evs[0]["blocked"] == 0, f"{out} {evs}")
    if evs:
        check("exec: event exe is the caller (cached at its exec)", evs[0]["exe"].startswith("/usr/bin/python"),
              evs[0]["exe"])
    rc, out = in_cg("gt-a.scope", "import subprocess; print(subprocess.run(['/bin/true']).returncode)")
    check("exec: /bin/true does not match", not [e for e in r.drain() if e["hook"] == H_EXEC], out)
    # an exec that fails after the check (ENOEXEC: not a binary) keeps the old exe
    open("/tmp/gt/junk", "wb").write(b"\0" * 64)
    os.chmod("/tmp/gt/junk", 0o755)
    rc, out = in_cg("gt-a.scope", """
import os, subprocess
try: os.execv('/tmp/gt/junk', ['junk'])
except OSError as e: print(e.errno, end=' ')
print(subprocess.run(['/tmp/gt/true']).returncode)
""")
    evs = [e for e in r.drain() if e["hook"] == H_EXEC]
    late = [e for e in evs if e["target"] == "/tmp/gt/true"]
    check("exec: a failed exec does not replace the cached exe", out == "8 0" and len(late) == 1
          and late[0]["exe"].startswith("/usr/bin/python"), f"{out} {evs}")
    rule(o, 5, H_EXEC, BLOCK)
    rc, out = in_cg("gt-a.scope", """
import subprocess
try: subprocess.run(['/tmp/gt/true']); print('ran')
except PermissionError: print('eperm')
""")
    check("exec: block denies /tmp/gt/true", out == "eperm", out)
    # a denied exec keeps the old exe too
    rule(o, 6, H_EXEC, ALERT)
    upd(o, "exe_prefix_lpm", ANYPATH, rs(5, 6))
    upd(o, "unit_rules", ANYUNIT, rs(5, 6))
    upd(o, "path_prefix_lpm", pathkey("/bin/"), rs(6))
    upd(o, "path_prefix_lpm", pathkey("/usr/bin/"), rs(6))
    r.drain()
    rc, out = in_cg("gt-a.scope", """
import os, subprocess
try: os.execv('/tmp/gt/true', ['true'])
except PermissionError: print('eperm', end=' ')
print(subprocess.run(['/bin/true']).returncode)
""")
    evs = [e for e in r.drain() if e["hook"] == H_EXEC and e["target"] == "/usr/bin/true"]
    check("exec: a denied exec does not replace the cached exe", out == "eperm 0" and len(evs) == 1
          and evs[0]["exe"].startswith("/usr/bin/python"), f"{out} {evs}")
    rule(o, 6, H_EXEC, ALERT, enabled=0)
    rc, out = in_cg("init.scope", "import subprocess; print(subprocess.run(['/tmp/gt/true']).returncode)")
    exempt_check("exec: init.scope never blocked", out == "0", out)
    r.drain()
    # process exe constraint: only when the caller's exe is under /usr/bin/ (python is)
    upd(o, "exe_prefix_lpm", ANYPATH, rs())
    upd(o, "exe_prefix_lpm", pathkey("/usr/bin/"), rs(5))
    rc, out = in_cg("gt-a.scope", """
import subprocess
try: subprocess.run(['/tmp/gt/true']); print('ran')
except PermissionError: print('eperm')
""")
    check("exec: exe prefix /usr/bin/ matches python caller", out == "eperm", out)
    rc, out = in_cg("gt-a.scope", "import os; os.execv('/bin/sh', ['sh', '-c', '/tmp/gt/true && echo ran || echo denied'])")
    check("exec: dash (/usr/bin/dash) as caller matches /usr/bin/", "denied" in out, out)
    upd(o, "exe_prefix_lpm", pathkey("/usr/bin/"), rs())
    upd(o, "exe_prefix_lpm", pathkey("/usr/bin/dash", prefix=False), rs(5))
    rc, out = in_cg("gt-a.scope", """
import subprocess
try: subprocess.run(['/tmp/gt/true']); print('ran')
except PermissionError: print('eperm')
""")
    check("exec: exact exe /usr/bin/dash does not match python", out == "ran", out)
    rc, out = in_cg("gt-a.scope", "import os; os.execv('/usr/bin/dash', ['sh', '-c', '/tmp/gt/true && echo ran || echo denied'])")
    check("exec: exact exe /usr/bin/dash matches dash (fork inherits exe)", "denied" in out, out)
    # a program under a path longer than 255 bytes: cut to 255, still a /tmp/gt/ prefix match
    rule(o, 5, H_EXEC, ALERT)
    upd(o, "exe_prefix_lpm", pathkey("/usr/bin/dash", prefix=False), rs())
    upd(o, "exe_prefix_lpm", ANYPATH, rs(5))
    upd(o, "exe_prefix_lpm", pathkey("/usr/bin/"), rs(5))  # cumulative: still covers python
    longdir = "/tmp/gt/" + "/".join(["d" * 60] * 5)
    os.makedirs(longdir, exist_ok=True)
    sh("cp", "/usr/bin/dash", longdir + "/dash")
    r.drain()
    rc, out = in_cg("gt-a.scope", f"import os; os.execv('{longdir}/dash', ['sh', '-c', '/tmp/gt/true && echo ran'])")
    evs = [e for e in r.drain() if e["hook"] == H_EXEC]
    check("exec: a >255-byte /tmp path triggers the /tmp/gt/ exec rule (target cut to 255)",
          out == "ran" and len(evs) == 2 and evs[0]["target"] == (longdir + "/dash")[:255], f"{out} {evs[:1]}")
    if len(evs) == 2:
        check("exec: the long exe is cached (cut to 255) for the next exec",
              evs[1]["exe"] == (longdir + "/dash")[:255] and evs[1]["target"] == "/tmp/gt/true", str(evs[1]))
    unload(o)

def t_file():
    o = "file"
    load(o)
    r = Ring(o)
    config(o)
    os.makedirs("/etc/gtprot", exist_ok=True)
    open("/etc/gtprot/f", "w").write("x")
    rule(o, 7, H_FILE, BLOCK)
    wildcards(o, [7])
    upd(o, "path_prefix_lpm", pathkey("/etc/gtprot/"), rs(7))
    upd(o, "path_prefix_lpm", pathkey("/etc/gtprot", prefix=False), rs(7))
    r.drain()
    code = """
import os
def t(f):
    try: f(); return 'ok'
    except PermissionError: return 'eperm'
    except OSError as e: return 'err%d' % e.errno
print(t(lambda: open('/etc/gtprot/f').read()),
      t(lambda: open('/etc/gtprot/f', 'a').write('y')),
      t(lambda: os.unlink('/etc/gtprot/f')),
      t(lambda: os.rename('/etc/gtprot/f', '/tmp/gtf')),
      t(lambda: os.rename('/tmp/gtsrc', '/etc/gtprot/new')),
      t(lambda: open('/etc/gtprotx', 'w').write('y')),
      t(lambda: os.rmdir('/etc/gtprot/nonexist')))
"""
    open("/tmp/gtsrc", "w").write("s")
    rc, out = in_cg("gt-a.scope", code)
    check("file: read ok; write, unlink, rename out, rename in denied; sibling ok",
          out == "ok eperm eperm eperm eperm ok err2", out)
    evs = [e for e in r.drain() if e["hook"] == H_FILE]
    tg = sorted(set(e["target"] for e in evs))
    check("file: event targets", tg == ["/etc/gtprot/f", "/etc/gtprot/new"], str(tg))
    rc, out = in_cg("system.slice/sensr-update-check.service", code)
    exempt_check("file: sensr-update* prefix never blocked", out.split()[1] == "ok", out)
    # a write under a >255-byte path below the blocked prefix
    longdir = "/etc/gtprot/" + "/".join(["d" * 60] * 5)
    os.makedirs(longdir, exist_ok=True)  # mkdir is not hooked
    rc, out = in_cg("gt-a.scope", f"""
try: open('{longdir}/f', 'w').write('y'); print('ok')
except PermissionError: print('eperm')
""")
    check("file: write under a >255-byte path below a blocked prefix is denied", out == "eperm", out)
    # rename: alert on the source side, block on the destination -> blocked
    rule(o, 8, H_FILE, ALERT)
    wildcards(o, [7, 8])
    upd(o, "path_prefix_lpm", pathkey("/tmp/"), rs(8))
    open("/tmp/gtsrc2", "w").write("s")
    r.drain()
    rc, out = in_cg("gt-a.scope", """
import os
try: os.rename('/tmp/gtsrc2', '/etc/gtprot/new2'); print('ok')
except PermissionError: print('eperm')
""")
    evs = r.drain()
    check("file: rename from an alert dir into a blocked dir is denied (one event, the block)",
          out == "eperm" and len(evs) == 1 and evs[0]["rule"] == 7 and evs[0]["blocked"]
          and evs[0]["target"] == "/etc/gtprot/new2", f"{out} {evs}")
    rc, out = in_cg("gt-a.scope", """
import os
os.rename('/tmp/gtsrc2', '/tmp/gtsrc3'); print('ok')
""")
    evs = r.drain()
    check("file: rename within the alert dir: allowed, alert event for the old path",
          out == "ok" and len(evs) == 1 and evs[0]["rule"] == 8 and evs[0]["target"] == "/tmp/gtsrc2", f"{out} {evs}")
    unload(o)
    sh("rm", "-rf", "/etc/gtprot", "/etc/gtprotx")

def t_creds():
    o = "creds"
    load(o)
    r = Ring(o)
    config(o)
    rule(o, 9, H_SETUID, BLOCK)
    wildcards(o, [9])
    upd(o, "uid_rules", struct.pack("<I", 1234), rs(9))
    code = """
import os
try: os.setuid({u}); print('ok')
except PermissionError: print('eperm')
"""
    rc, out = in_cg("gt-a.scope", code.format(u=1234))
    check("setuid: block to uid 1234", out == "eperm", out)
    rc, out = in_cg("gt-a.scope", code.format(u=1235))
    check("setuid: uid 1235 allowed", out == "ok", out)
    evs = r.drain()
    check("setuid: event target is the uid", len(evs) == 1 and evs[0]["target"] == "1234", str(evs))
    rule(o, 9, H_SETUID, ALERT)
    upd(o, "uid_rules", struct.pack("<I", 1234), rs())
    upd(o, "uid_rules", struct.pack("<I", 0xffffffff), rs(9))
    rc, out = in_cg("gt-a.scope", code.format(u=4000000))
    evs = r.drain()
    check("setuid: any-uid alert", out == "ok" and len(evs) == 1 and evs[0]["target"] == "4000000", f"{out} {evs}")
    unload(o)

def t_listen():
    o = "listen"
    load(o)
    r = Ring(o)
    config(o)
    rule(o, 2, H_LISTEN, BLOCK)
    wildcards(o, [2])
    upd(o, "net4_lpm", struct.pack("<I", 0) + b"\0" * 4, rs(2))
    upd(o, "net6_lpm", struct.pack("<I", 0) + b"\0" * 16, rs(2))
    upd(o, "port_rules", struct.pack("<I", 8081), rs(2))
    upd(o, "port_rules", struct.pack("<I", 8082), rs(2))
    code = """
import socket
def t(f):
    try: f(); return 'ok'
    except PermissionError: return 'eperm'
def tcp(p):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', p)); s.listen()
def udp(p):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('0.0.0.0', p))
print(t(lambda: tcp(8081)), t(lambda: tcp(8083)), t(lambda: udp(8082)), t(lambda: udp(8084)), t(lambda: udp(0)))
"""
    rc, out = in_cg("gt-a.scope", code)
    check("listen: tcp 8081 & udp 8082 denied, others ok", out == "eperm ok eperm ok ok", out)
    evs = r.drain()
    ports = sorted(e["port"] for e in evs)
    check("listen: events for 8081, 8082", ports == [8081, 8082], str(ports))
    if evs:
        e = [e for e in evs if e["port"] == 8081][0]
        check("listen: tcp event carries bound address", e["addr"][:4] == socket.inet_aton("127.0.0.1") and e["family"] == 2, str(e))
    # v4-mapped: only the IPv4 any-address rule is left
    upd(o, "net6_lpm", struct.pack("<I", 0) + b"\0" * 16, rs())
    rc, out = in_cg("gt-a.scope", """
import socket
def t(a):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try: s.bind((a, 8082)); return 'ok'
    except PermissionError: return 'eperm'
print(t('::ffff:127.0.0.1'), t('::1'))
""")
    evs = r.drain()
    check("listen: bind to ::ffff:127.0.0.1 hits the IPv4 rule, ::1 does not",
          out == "eperm ok" and len(evs) == 1 and evs[0]["family"] == 2, f"{out} {evs}")
    # dual-stack [::] takes IPv4 too: the IPv4 any-address rule applies,
    # unless the socket is v6only
    rc, out = in_cg("gt-a.scope", """
import socket
def t(kind, v6only, p):
    s = socket.socket(socket.AF_INET6, kind)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, v6only)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('::', p))
        if kind == socket.SOCK_STREAM: s.listen()
        return 'ok'
    except PermissionError: return 'eperm'
print(t(socket.SOCK_DGRAM, 0, 8082), t(socket.SOCK_DGRAM, 1, 8082),
      t(socket.SOCK_STREAM, 0, 8081), t(socket.SOCK_STREAM, 1, 8081))
""")
    evs = r.drain()
    check("listen: dual-stack [::] binds and listens hit the IPv4 rule, v6only ones do not",
          out == "eperm ok eperm ok" and len(evs) == 2 and all(e["family"] == 10 for e in evs),
          f"{out} {evs}")
    check("listen: events carry the socket type (UDP bind 2, TCP listen 1)",
          sorted(e["sock_type"] for e in evs) == [1, 2], str([e["sock_type"] for e in evs]))
    unload(o)

def t_bpf():
    o = "bpf"
    load(o)
    r = Ring(o)
    rule(o, 4, H_BPF, BLOCK)
    wildcards(o, [4], unit_=False)
    upd(o, "unit_rules", unit("gt-a.scope"), rs(4))
    code = r"""
import ctypes, struct, os, sys
libc = ctypes.CDLL(None, use_errno=True)
insns = struct.pack('<BBhi', 0xb7, 0, 0, 0) + struct.pack('<BBhi', 0x95, 0, 0, 0)
ib = ctypes.create_string_buffer(insns); lic = ctypes.create_string_buffer(b'GPL')
attr = struct.pack('<IIQQIIQ', 1, 2, ctypes.addressof(ib), ctypes.addressof(lic), 0, 0, 0).ljust(144, b'\0')
a = ctypes.create_string_buffer(attr)
SYS = 280 if os.uname().machine == 'aarch64' else 321
fd = libc.syscall(SYS, 5, a, len(attr))
print('ok' if fd >= 0 else 'err%d' % ctypes.get_errno())
"""
    config(o)
    rc, out = in_cg("gt-a.scope", code)
    check("bpf: prog load by other process denied", out == "err1", out)
    evs = r.drain()
    check("bpf: event target prog_load", len(evs) == 1 and evs[0]["target"] == "prog_load" and evs[0]["blocked"], str(evs))
    # guard_tgid exemption. Pids in this container are not the kernel's
    # root-namespace tgid the program sees, so learn it from a first event.
    code2 = code.replace("fd = libc.syscall(SYS, 5, a, len(attr))",
        "fd = libc.syscall(SYS, 5, a, len(attr)); print('first', fd >= 0, flush=True); input(); fd = libc.syscall(SYS, 5, a, len(attr))")
    cg("gt-a.scope")
    def pre():
        open("/sys/fs/cgroup/gt-a.scope/cgroup.procs", "w").write("0")
    p = subprocess.Popen([sys.executable, "-c", code2], preexec_fn=pre, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    first = p.stdout.readline().strip()
    evs = r.drain()
    tgid = evs[0]["pid"] if evs else 0
    config(o, tgid=tgid)
    out, _ = p.communicate("\n")
    evs2 = r.drain()
    check("bpf: guard_tgid not blocked, not reported", first == "first False" and tgid
          and out.strip() == "ok" and not evs2, f"{first} {tgid} {out} {evs2}")
    config(o)
    unload(o)

def t_module():
    o = "module"
    load(o)
    unload(o)
    check("module: loads and attaches", True)

for t in [t_connect, t_exec, t_file, t_creds, t_listen, t_bpf, t_module]:
    try:
        t()
    except SystemExit as e:
        check(t.__name__, False, str(e))
print("FAILURES:", FAILS)
sys.exit(1 if FAILS else 0)
