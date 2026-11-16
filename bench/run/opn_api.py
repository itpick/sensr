#!/usr/bin/env python3
"""Minimal OPNsense API client (stdlib only) used to load the synthetic policy
and to time API round-trips.

usage: opn_api.py load small|large      replace user rules/aliases with payload
       opn_api.py get PATH | post PATH JSON
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.request

BENCH = os.environ.get("BENCH", "/mnt/vms/sensr/bench")
HOST = os.environ.get("OPN_HOST", "192.168.1.1")
_key = json.load(open(os.environ.get("OPN_KEYFILE", f"{BENCH}/keys/opn-apikey.json")))
_auth = "Basic " + base64.b64encode(f"{_key['key']}:{_key['secret']}".encode()).decode()
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def call(path, body=None, timeout=900):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"https://{HOST}/api/{path}", data=data, method="POST" if data is not None else "GET")
    req.add_header("Authorization", _auth)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=_ctx, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def user_rules():
    rows = call("firewall/filter/search_rule", {"current": 1, "rowCount": -1})["rows"]
    # MVC (user) rules have dashed UUIDs; generated/internal rules do not
    return [r["uuid"] for r in rows if "-" in r.get("uuid", "")]


def user_aliases():
    rows = call("firewall/alias/search_item", {"current": 1, "rowCount": -1})["rows"]
    return [r["uuid"] for r in rows if r.get("name", "") in NAMES]


NAMES = set()


def load(size):
    p = json.load(open(os.path.join(BENCH, "src/generated/opn", f"{size}.json")))
    NAMES.update(a["alias"]["name"] for a in p["aliases"])
    t0 = time.time()
    for u in user_rules():
        call(f"firewall/filter/del_rule/{u}", {})
    for u in user_aliases():
        call(f"firewall/alias/del_item/{u}", {})
    t1 = time.time()
    for a in p["aliases"]:
        r = call("firewall/alias/add_item", a)
        assert r.get("result") == "saved", r
    t2 = time.time()
    for rule in p["rules"]:
        r = call("firewall/filter/add_rule", rule)
        assert r.get("result") == "saved", (rule, r)
    t3 = time.time()
    call("firewall/alias/reconfigure", {})
    t4 = time.time()
    st = call("firewall/filter/apply", {})
    t5 = time.time()
    print(json.dumps({"size": size, "rules": len(p["rules"]), "delete_s": t1 - t0,
                      "add_aliases_s": t2 - t1, "add_rules_s": t3 - t2,
                      "per_rule_add_ms": 1000 * (t3 - t2) / len(p["rules"]),
                      "alias_reconfigure_s": t4 - t3, "filter_apply_s": t5 - t4, "apply_status": st}))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "load":
        load(sys.argv[2])
    elif cmd == "get":
        print(json.dumps(call(sys.argv[2])))
    elif cmd == "post":
        print(json.dumps(call(sys.argv[2], json.loads(sys.argv[3]))))
