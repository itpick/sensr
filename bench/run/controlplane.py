#!/usr/bin/env python3
"""Control-plane benchmarks (router must be running with the given policy).

usage: controlplane.py KIND [--reps 5] [--parts apply,table,api,gui,proto]
  apply  one-rule change end-to-end, until the rule is active in the kernel
         OPNsense: API add_rule + filter/apply (configd -> rc.filter_configure ->
                   pfctl -f), verified by the rule UUID label in `pfctl -sr`
         OpenBSD:  append rule to pf.conf + `pfctl -f` (no management layer)
         VyOS:     configure; set rule; commit (vyos-1x -> nft), verified in nft
         NixOS:    Rust prototype POST /api/rules -> render all -> `nft -j -f`
  table  blocklist replacement with 1k/10k/100k entries
         raw kernel tool (pfctl -T replace / nft flush+add set) and, where a
         management layer exists, its own path (OPNsense alias API+reconfigure,
         VyOS network-group commit, Rust prototype render+nft -j -f)
  api    read-request latency (rule search) x 50
  gui    OPNsense page weight/latency (dashboard, firewall rules)
Results: results/controlplane.jsonl
"""
import argparse
import base64
import json
import os
import re
import ssl
import statistics
import time
import urllib.parse
import urllib.request
import uuid as uuidlib
from http.cookiejar import CookieJar

import lab

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
OUT = f"{lab.BENCH}/results/controlplane.jsonl"
TABLES = {"1k": "blk-1k.txt", "10k": "blk-10k.txt", "100k": "blk-100k.txt"}
if os.environ.get("TABLE_SIZES"):
    TABLES = {k: v for k, v in TABLES.items() if k in os.environ["TABLE_SIZES"].split(",")}


def rec(kind, part, **kw):
    r = {"router": kind, "part": part, "ts": time.time(), "host_loadavg1": lab.host_load()["loadavg"][0], **kw}
    lab.append_jsonl(OUT, r)
    print(json.dumps(r), flush=True)


def timed_ssh(host, cmd):
    """Time a command inside the guest (guest clock, excludes ssh overhead)."""
    out = lab.ssh(host, f"t0=$(date +%s.%N 2>/dev/null); {cmd} >/dev/null; t1=$(date +%s.%N); echo $t0 $t1", timeout=1800)
    a, b = out.split()[-2:]
    return float(b) - float(a)


def bsd_timed(host, cmd):
    """Time cmd inside a BSD guest with a sub-ms clock (perl on OpenBSD,
    python3 on OPNsense; BSD date has no %N and time -p only 10 ms)."""
    clk = ("perl -MTime::HiRes=time -e 'printf(\"%.6f\\n\", time)' 2>/dev/null || "
           "python3 -c 'import time; print(\"%.6f\" % time.time())'")
    out = lab.ssh(host, f"a=$({clk}); {cmd} >/dev/null 2>/tmp/bsd_timed.err; rc=$?; b=$({clk}); echo $a $b $rc", timeout=1800)
    a, b, rc = out.split()[-3:]
    if rc != "0":
        raise RuntimeError(f"{cmd!r} rc={rc}: " + lab.ssh(host, "cat /tmp/bsd_timed.err", check=False)[-300:])
    return float(b) - float(a)


PROTO = os.environ.get("PROTO_BIN", "sensr-proto")


# ------------------------------------------------------------------ OPNsense
def opn_auth():
    k = json.load(open(os.environ.get("OPN_KEYFILE", f"{lab.BENCH}/keys/opn-apikey.json")))
    return "Basic " + base64.b64encode(f"{k['key']}:{k['secret']}".encode()).decode()


def opn(path, body=None, timeout=1800):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"https://192.168.1.1/api/{path}", data=data)
    req.add_header("Authorization", opn_auth())
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def opn_apply(kind, reps):
    for rep in range(reps):
        t0 = time.time()
        r = opn("firewall/filter/add_rule", {"rule": {
            "enabled": "1", "sequence": "1", "action": "block", "quick": "1", "interface": "lan",
            "direction": "in", "ipprotocol": "inet", "protocol": "TCP", "source_net": "192.168.1.77",
            "destination_net": "any", "destination_port": str(31000 + rep), "description": f"bench {rep}"}})
        u = r["uuid"]
        t1 = time.time()
        opn("firewall/filter/apply", {})
        t2 = time.time()
        n = lab.ssh("router", f"pfctl -sr | grep -c {u} || true").strip()
        rec(kind, "apply", rep=rep, add_s=t1 - t0, apply_s=t2 - t1, total_s=t2 - t0, active_after=n != "0")
        opn(f"firewall/filter/del_rule/{u}", {})
        opn("firewall/filter/apply", {})


def opn_table(kind, reps, raw=True, mgmt=True):
    for label, f in TABLES.items():
        path = f"{lab.SRC}/generated/tables/{f}"
        lab.sh(f"scp -F {lab.SSHCFG} -q {path} router:/tmp/{f}")
        n = len(open(path).read().split())
        for rep in range(reps if raw else 0):
            t = bsd_timed("router", f"pfctl -t blocklist_v4 -T replace -f /tmp/{f}")
            rec(kind, "table_raw", size=label, entries=n, rep=rep, seconds=t)
        if not mgmt:
            continue
        # management path: set alias content through the API, then reconfigure
        # search_item returns a truncated (broken chunked) body once the alias holds
        # ~10k entries, so look the UUID up by name instead
        u = opn("firewall/alias/getAliasUUID/blocklist_v4")["uuid"]
        content = open(path).read().strip()
        for rep in range(reps):
            t0 = time.time()
            r = opn(f"firewall/alias/set_item/{u}", {"alias": {"content": content}})
            t1 = time.time()
            opn("firewall/alias/reconfigure", {})
            t2 = time.time()
            # wait until pf holds the new content (reconfigure may hand off to a background job)
            got = 0
            while time.time() - t2 < 900:
                got = int(lab.ssh("router", "pfctl -t blocklist_v4 -T show | wc -l").strip())
                if got == n:
                    break
                time.sleep(0.2)
            t3 = time.time()
            rec(kind, "table_mgmt", size=label, entries=n, rep=rep, set_item_s=t1 - t0,
                reconfigure_s=t2 - t1, total_s=t3 - t0, loaded=got, result=r.get("result"))


def opn_api(kind, n=50):
    for q, label in (("bulk", "search"), ("", "list_all")):
        lat = []
        for _ in range(n):
            t0 = time.time()
            r = opn("firewall/filter/search_rule", {"current": 1, "rowCount": 25, "searchPhrase": q})
            lat.append(1000 * (time.time() - t0))
        rec(kind, "api", query=label, n=n, p50_ms=statistics.median(lat), p95_ms=sorted(lat)[int(0.95 * n) - 1],
            total_rows=r.get("total"))


def opn_gui(kind, reps):
    for rep in range(reps):
        cj = CookieJar()
        op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(cj))
        html = op.open("https://192.168.1.1/").read().decode()
        name, val = re.search(r'name="([^"]+)" value="([^"]+)" autocomplete="new-password"', html).groups() \
            if re.search(r'autocomplete="new-password"', html) else re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', html).groups()
        data = urllib.parse.urlencode({name: val, "usernamefld": "root", "passwordfld": "opnsense", "login": "1"}).encode()
        op.open("https://192.168.1.1/", data).read()
        for page in ("/index.php", "/ui/firewall/filter"):
            t0 = time.time()
            body = op.open("https://192.168.1.1" + page).read()
            t_html = time.time() - t0
            assets = set(re.findall(rb'(?:src|href)="(/[^"]+\.(?:js|css)[^"]*)"', body))
            total = len(body)
            for a in assets:
                try:
                    total += len(op.open("https://192.168.1.1" + a.decode()).read())
                except Exception:
                    pass
            t_all = time.time() - t0
            rec(kind, "gui", page=page, rep=rep, html_bytes=len(body), assets=len(assets),
                total_bytes=total, html_s=t_html, html_plus_assets_s=t_all)


# ------------------------------------------------------------------ OpenBSD
def obsd_apply(kind, reps):
    lab.ssh("router", "cp /etc/pf.conf /tmp/pf.conf.orig")
    for rep in range(reps):
        line = f"block in quick on vio0 inet proto tcp from 192.168.1.77 to any port {31000 + rep}"
        lab.ssh("router", f"cp /tmp/pf.conf.orig /etc/pf.conf && echo '{line}' >> /etc/pf.conf")
        t = bsd_timed("router", "pfctl -f /etc/pf.conf")
        ok = lab.ssh("router", f"pfctl -sr | grep -c 'port = {31000 + rep}' || true").strip() != "0"
        rec(kind, "apply", rep=rep, total_s=t, active_after=ok, method="pfctl -f (whole ruleset)")
    lab.ssh("router", "cp /tmp/pf.conf.orig /etc/pf.conf && pfctl -f /etc/pf.conf")


def obsd_table(kind, reps):
    for label, f in TABLES.items():
        path = f"{lab.SRC}/generated/tables/{f}"
        lab.sh(f"scp -F {lab.SSHCFG} -q {path} router:/tmp/{f}")
        n = len(open(path).read().split())
        for rep in range(reps):
            t = bsd_timed("router", f"pfctl -t blocklist_v4 -T replace -f /tmp/{f}")
            rec(kind, "table_raw", size=label, entries=n, rep=rep, seconds=t)


# ------------------------------------------------------------------ NixOS + Rust prototype
def nix_table(kind, reps):
    for label, f in TABLES.items():
        path = f"{lab.SRC}/generated/tables/{f}"
        n = len(open(path).read().split())
        elems = ", ".join(open(path).read().split())
        script = f"flush set inet filter blocklist_v4\nadd element inet filter blocklist_v4 {{ {elems} }}\n"
        p = f"{lab.BENCH}/work/nft-{label}.nft"
        open(p, "w").write(script)
        lab.sh(f"scp -F {lab.SSHCFG} -q {p} router:/tmp/set-{label}.nft")
        lab.sh(f"scp -F {lab.SSHCFG} -q {path} router:/tmp/{f}")
        for rep in range(reps):
            t = timed_ssh("router", f"nft -f /tmp/set-{label}.nft")
            rec(kind, "table_raw", size=label, entries=n, rep=rep, seconds=t, method="nft -f flush+add (text)")
        out = lab.ssh("router", f"{PROTO} bench --policy /etc/sensrbench/opn/small.json --reps {reps} --set-files /tmp/{f}")
        for line in out.splitlines():
            j = json.loads(line)
            if j["what"] == "set_replace":
                rec(kind, "table_mgmt", size=label, entries=n, proto=PROTO, render_s=j["render_ms"] / 1000,
                    apply_s=j["nft_apply_ms"] / 1000, total_s=(j["render_ms"] + j["nft_apply_ms"]) / 1000,
                    method="rust prototype: render JSON + nft -j -f")
    lab.ssh("router", "nft -f /etc/sensrbench/nft/small.nft")


def proto_full(kind, reps):
    """Full-ruleset render + apply in the prototype at 50 / 1k / 10k rules."""
    for pol, extra, label in (("small", 0, "50"), ("large", 0, "1000"), ("large", 9000, "10000")):
        out = lab.ssh("router", f"{PROTO} bench --policy /etc/sensrbench/opn/{pol}.json --extra {extra} --reps {reps}")
        for line in out.splitlines():
            j = json.loads(line)
            rec(kind, "proto_full", proto=PROTO, renderer=j.get("renderer", "dom"), rules=j["rules"], set_entries=j["set_entries"], json_bytes=j["json_bytes"],
                render_s=j["render_ms"] / 1000, apply_s=j["nft_apply_ms"] / 1000, rss_mib=j["rss_kib"] / 1024)
        # compare: same ruleset through nft's own text parser
        if extra == 0:
            for rep in range(reps):
                t = timed_ssh("router", f"nft -f /etc/sensrbench/nft/{pol}.nft")
                rec(kind, "nft_text_full", rules=label, rep=rep, seconds=t)
    lab.ssh("router", "nft -f /etc/sensrbench/nft/small.nft")


def proto_api(kind, reps, n=50):
    """Prototype as a running service: search latency + one-rule apply end-to-end."""
    for pol, extra, label in (("small", 0, "50"), ("large", 0, "1000"), ("large", 9000, "10000")):
        lab.ssh("router", "systemctl stop sensr-proto; pkill -f 'sensr-proto.* serve' || true", check=False)
        lab.ssh("router", f"nohup {PROTO} serve --policy /etc/sensrbench/opn/{pol}.json --extra {extra} --port 8080 --apply-on-start yes >/dev/null 2>&1 &")
        for _ in range(100):
            try:
                urllib.request.urlopen("http://192.168.1.1:8080/api/health", timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        rss = json.loads(urllib.request.urlopen("http://192.168.1.1:8080/api/stats").read())["rss_kib"] / 1024
        for q, ql in (("bulk", "search"), ("", "list_all")):
            lat = []
            for _ in range(n):
                t0 = time.time()
                urllib.request.urlopen(f"http://192.168.1.1:8080/api/rules/search?q={q}&limit=25").read()
                lat.append(1000 * (time.time() - t0))
            rec(kind, "api", proto=PROTO, rules=label, query=ql, n=n, p50_ms=statistics.median(lat),
                p95_ms=sorted(lat)[int(0.95 * n) - 1], rss_mib=rss)
        for rep in range(reps):
            body = json.dumps({"description": f"bench {rep}", "source": "192.168.1.77", "port": 31000 + rep}).encode()
            t0 = time.time()
            r = json.loads(urllib.request.urlopen(urllib.request.Request(
                "http://192.168.1.1:8080/api/rules", data=body, headers={"Content-Type": "application/json"})).read())
            t1 = time.time()
            ok = lab.ssh("router", f"nft list chain inet filter forward | grep -c 'bench {rep}' || true").strip() != "0"
            rec(kind, "apply", proto=PROTO, rules=label, rep=rep, total_s=t1 - t0, render_s=r["render_ms"] / 1000,
                apply_s=r["nft_apply_ms"] / 1000, active_after=ok, method="rust prototype POST /api/rules")
        rss2 = json.loads(urllib.request.urlopen("http://192.168.1.1:8080/api/stats").read())["rss_kib"] / 1024
        rec(kind, "proto_rss", proto=PROTO, rules=label, rss_mib_start=rss, rss_mib_after_applies=rss2)
    lab.ssh("router", "pkill -f 'sensr-proto.* serve'; nft -f /etc/sensrbench/nft/small.nft; systemctl start sensr-proto", check=False)


# ------------------------------------------------------------------ VyOS
def vyos_cfg(cmds, timeout=1800):
    script = "source /opt/vyatta/etc/functions/script-template\nconfigure\n" + "\n".join(cmds) + \
        "\nT0=$(date +%s.%N)\ncommit\nT1=$(date +%s.%N)\necho \"COMMIT_S $T0 $T1\"\nexit discard\n"
    p = f"{lab.BENCH}/work/vyos-cp.sh"
    open(p, "w").write(script)
    t0 = time.time()
    out = lab.sh(f"ssh -F {lab.SSHCFG} vyos 'vbash -s' < {p}", timeout=timeout, check=False)
    wall = time.time() - t0
    m = re.search(r"COMMIT_S ([\d.]+) ([\d.]+)", out)
    return (float(m.group(2)) - float(m.group(1)) if m else None), wall, out


def vyos_apply(kind, reps):
    for rep in range(reps):
        b = "set firewall ipv4 forward filter rule 5"
        cmds = [f"{b} action drop", f"{b} protocol tcp", f"{b} source address 192.168.1.77",
                f"{b} destination port {31000 + rep}", f"{b} inbound-interface name eth0"]
        c, wall, out = vyos_cfg(cmds)
        ok = lab.ssh("vyos", f"sudo nft list ruleset | grep -c 'dport {31000 + rep}' || true").strip() != "0"
        rec(kind, "apply", rep=rep, commit_s=c, total_s=wall, active_after=ok, method="vbash configure/set/commit",
            error=None if c else out[-400:])
        vyos_cfg(["delete firewall ipv4 forward filter rule 5"])


def vyos_table(kind, reps, timeout=600):
    for label, f in TABLES.items():
        entries = open(f"{lab.SRC}/generated/tables/{f}").read().split()
        cmds = ["delete firewall group network-group blocklist_v4"] + \
            [f"set firewall group network-group blocklist_v4 network {e if '/' in e else e + '/32'}" for e in entries]
        for rep in range({1000: reps, 10000: 3}.get(len(entries), 1)):
            try:
                tmo = 2400 if len(entries) <= 10000 else timeout  # 100k: give up after ~10 min
                c, wall, out = vyos_cfg(cmds, timeout=tmo)
            except Exception as e:  # subprocess timeout: report it as the result
                c, wall, out = None, float(tmo), f"timeout after {tmo}s: {e}"
                lab.ssh("vyos", "sudo pkill -f 'vbash -s' || true", check=False)
                time.sleep(30)
            got = lab.ssh("vyos", "sudo nft list set ip vyos_filter N_blocklist_v4 2>/dev/null | grep -o ',' | wc -l", check=False).strip()
            rec(kind, "table_mgmt", size=label, entries=len(entries), rep=rep, commit_s=c, total_s=wall,
                timed_out=c is None, method="vbash delete+set network-group + commit", nft_commas=got,
                error=None if c else out[-300:])
            if c is None:
                break


def vyos_api(kind, n=50):
    k = json.load(open(f"{lab.BENCH}/keys/vyos-apikey.json"))["key"]
    for path, label in ((["firewall", "ipv4", "forward", "filter", "rule", "10"], "get_one_rule"),
                        (["firewall", "ipv4", "forward", "filter"], "get_all_rules")):
        lat = []
        for _ in range(n):
            data = urllib.parse.urlencode({"data": json.dumps({"op": "showConfig", "path": path}), "key": k}).encode()
            t0 = time.time()
            urllib.request.urlopen(urllib.request.Request("https://192.168.1.1/retrieve", data=data), context=CTX, timeout=60).read()
            lat.append(1000 * (time.time() - t0))
        rec(kind, "api", query=label, n=n, p50_ms=statistics.median(lat), p95_ms=sorted(lat)[int(0.95 * n) - 1])
    # one-rule change through the HTTP API (set + commit in one request)
    for rep in range(3):
        b = ["firewall", "ipv4", "forward", "filter", "rule", "6"]
        ops = [{"op": "set", "path": b + ["action", "drop"]}, {"op": "set", "path": b + ["protocol", "tcp"]},
               {"op": "set", "path": b + ["destination", "port", str(32000 + rep)]}]
        data = urllib.parse.urlencode({"data": json.dumps(ops), "key": k}).encode()
        t0 = time.time()
        r = urllib.request.urlopen(urllib.request.Request("https://192.168.1.1/configure", data=data), context=CTX, timeout=600).read()
        t1 = time.time()
        rec(kind, "apply_api", rep=rep, total_s=t1 - t0, response=r[:200].decode(errors="replace"))
        data = urllib.parse.urlencode({"data": json.dumps({"op": "delete", "path": b}), "key": k}).encode()
        urllib.request.urlopen(urllib.request.Request("https://192.168.1.1/configure", data=data), context=CTX, timeout=600).read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--parts", default="apply,table,api,gui,proto")
    a = ap.parse_args()
    parts = a.parts.split(",")
    k = a.kind
    fam = k.rstrip("L")
    if fam == "opn":
        "apply" in parts and opn_apply(k, a.reps)
        "table" in parts and opn_table(k, a.reps)
        "tablemgmt" in parts and opn_table(k, a.reps, raw=False)
        "tableraw" in parts and opn_table(k, a.reps, mgmt=False)
        "api" in parts and opn_api(k)
        "gui" in parts and opn_gui(k, a.reps)
    elif fam == "obsd":
        "apply" in parts and obsd_apply(k, a.reps)
        "table" in parts and obsd_table(k, a.reps)
    elif fam == "nixr":
        "table" in parts and nix_table(k, a.reps)
        "proto" in parts and proto_full(k, a.reps)
        ("apply" in parts or "api" in parts) and proto_api(k, a.reps)
    elif fam == "vyos":
        "apply" in parts and vyos_apply(k, a.reps)
        "api" in parts and vyos_api(k)
        "table" in parts and vyos_table(k, a.reps)


if __name__ == "__main__":
    main()
