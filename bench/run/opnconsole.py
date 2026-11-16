#!/usr/bin/env python3
"""Drive the OPNsense serial console: log in as root, open a shell (menu 8)
and run commands. Used only for bootstrap (injecting config.xml, enabling
SSH); all measurements go over SSH/HTTPS afterwards.

usage: opnconsole.py PORT 'cmd1' ['cmd2' ...]      run commands, print output
       opnconsole.py PORT --put LOCAL REMOTE       copy a file (base64 chunks)
"""
import base64
import re
import sys
import time
import uuid

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from console import Console

PROMPT = r"root@[^:]*:~ # $|^# $|root@\S+ # $"


def quiet_tail(c, quiet=2.0, timeout=300):
    """Wait until the console has been silent for `quiet` seconds; return the tail."""
    deadline = time.time() + timeout
    last = -1
    while time.time() < deadline:
        n = len(c.buf)
        if n == last:
            break
        last = n
        time.sleep(quiet)
    return c.buf[-300:].replace("\r", "")


def shell(c, password="opnsense"):
    """Reach a root /bin/sh from whatever state the console is in. Decide on
    the *last* prompt once output has settled: a previous session's menu can
    redraw and then die (getty respawns login), which is slow under TCG."""
    c.send("\x03")
    time.sleep(0.3)
    c.sendline("")
    for _ in range(10):
        tail = quiet_tail(c)
        if tail.rstrip().endswith("login:"):
            c.sendline("root")
        elif tail.rstrip().endswith("Password:"):
            c.sendline(password)
        elif tail.rstrip().endswith("Enter an option:"):
            c.sendline("8")
        elif re.search(r"(root@[^\n]*[#%]|^#) *$", tail.rstrip() + " ", re.M) and not tail.rstrip().endswith(":"):
            break
        else:
            c.sendline("")
    else:
        raise TimeoutError("could not reach a root shell: " + repr(c.buf[-300:]))
    # plain sh keeps the console simple (no csh history expansion quirks)
    c.sendline("exec /bin/sh")
    time.sleep(0.5)
    c.sendline("PS1='# '; stty -echo")
    time.sleep(1.0)
    c.drain()


def run(c, cmd, timeout=600):
    tag = uuid.uuid4().hex[:8]
    c.sendline(f"{cmd}; echo __END_{tag}_$?__")
    m = c.expect(rf"__END_{tag}_(\d+)__", timeout)
    out = c.buf[: m.start()]
    out = out[out.rfind(f"__END_{tag}") if False else 0 :]
    return m, int(m.group(1))


def run_capture(c, cmd, timeout=600):
    start = len(c.buf)
    c.pos = start
    m, rc = run(c, cmd, timeout)
    text = c.buf[start : m.start()]
    lines = [l for l in text.replace("\r", "").split("\n") if "__END_" not in l]
    return "\n".join(lines).strip(), rc


def put(c, local, remote):
    data = base64.b64encode(open(local, "rb").read()).decode()
    run_capture(c, f": > {remote}.b64")
    for i in range(0, len(data), 200):
        run_capture(c, f"printf '%s' '{data[i:i+200]}' >> {remote}.b64")
    out, rc = run_capture(c, f"b64decode -r {remote}.b64 > {remote} && rm {remote}.b64 && sha256 -q {remote}")
    import hashlib
    want = hashlib.sha256(open(local, "rb").read()).hexdigest()
    if want not in out:
        raise SystemExit(f"checksum mismatch for {remote}: {out}")


if __name__ == "__main__":
    port = int(sys.argv[1])
    c = Console(port, f"/mnt/vms/sensr/bench/work/console-{port}.log")
    shell(c)
    if sys.argv[2] == "--put":
        put(c, sys.argv[3], sys.argv[4])
        print("ok")
    else:
        for cmd in sys.argv[2:]:
            out, rc = run_capture(c, cmd)
            print(out)
            if rc:
                print(f"[rc={rc}]", file=sys.stderr)
    c.sendline("exit")
    c.close()
