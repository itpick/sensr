#!/usr/bin/env python3
"""One synthetic home-router policy, rendered for every router under test.

The same rule list (order, match fields, actions) is emitted as:
  nft/{small,large}{,-ft}.nft   Linux nftables (-ft: software flowtable fast path)
  pf/{small,large}.conf         OpenBSD pf.conf
  opn/{small,large}.json        OPNsense MVC API payloads (aliases + filter rules)
  tables/blk-{1k,10k,100k}.txt  table/set contents for the reload benchmark

Shape (small): ~6 aliases, 50 filter rules on LAN-in / WAN-in, outbound NAT on
WAN, default deny. Large: the same plus 950 per-host rules (1,000 total) and a
10k-entry blocklist table. The benchmark flow (192.168.1.100 -> 10.99.0.10,
tcp/udp 5201, nginx :80) matches none of the specific rules and is accepted by
the final "LAN to any" rule, so a new connection walks the whole list.
Deterministic (fixed seed) so every target gets identical content.
"""
import ipaddress
import json
import os
import random
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "generated"
LAN_NET = "192.168.1.0/24"
LAN_IP = "192.168.1.1"


def blocklist(n, seed):
    """n non-overlapping public IPv4 entries, ~30% /24 networks, rest /32."""
    rnd = random.Random(seed)
    seen, out = set(), []
    while len(out) < n:
        a = rnd.randint(1, 223)
        if a in (10, 100, 127, 169, 172, 192, 198, 203):
            continue  # keep clear of private / lab / special ranges
        b, c = rnd.randint(0, 255), rnd.randint(0, 255)
        if (a, b, c) in seen:
            continue
        seen.add((a, b, c))
        if rnd.random() < 0.3:
            out.append(f"{a}.{b}.{c}.0/24")
        else:
            out.append(f"{a}.{b}.{c}.{rnd.randint(1, 254)}")
    return out


def aliases(large):
    return {
        "iot_devices": {"type": "host", "content": [f"192.168.1.{i}" for i in range(20, 28)]},
        "kids_devices": {"type": "host", "content": [f"192.168.1.{i}" for i in range(40, 44)]},
        "admin_hosts": {"type": "host", "content": ["192.168.1.10", "192.168.1.11"]},
        "work_vpn_nets": {"type": "network", "content": ["203.0.113.0/24", "198.51.100.0/24"]},
        "blocklist_v4": {"type": "network", "content": blocklist(10000 if large else 200, 7)},
        "web_ports": {"type": "port", "content": ["80", "443", "8080", "8443"]},
        "mail_ports": {"type": "port", "content": ["25", "465", "587", "993", "995"]},
    }


def R(action, iface, proto, src, dst, dport=None, descr=""):
    return dict(action=action, iface=iface, proto=proto, src=src, dst=dst, dport=dport, descr=descr)


def rules(large):
    rs = [
        R("pass", "lan", "udp", "lan", "self", "53", "DNS to router"),
        R("pass", "lan", "tcp", "lan", "self", "53", "DNS/TCP to router"),
        R("pass", "lan", "udp", "lan", "self", "123", "NTP to router"),
        R("pass", "lan", "udp", "lan", "self", "67", "DHCP"),
        R("pass", "lan", "tcp", "admin_hosts", "self", "22", "admin SSH"),
        R("pass", "lan", "tcp", "admin_hosts", "self", "443", "admin GUI"),
        R("pass", "lan", "icmp", "lan", "self", None, "ping router"),
        R("block", "lan", "any", "lan", "blocklist_v4", None, "blocklist"),
        R("block", "lan", "tcp", "iot_devices", "any", "mail_ports", "IoT no mail"),
        R("block", "lan", "any", "iot_devices", "work_vpn_nets", None, "IoT not to work"),
        R("pass", "lan", "tcp", "iot_devices", "any", "web_ports", "IoT web"),
        R("pass", "lan", "udp", "iot_devices", "any", "123", "IoT NTP"),
        R("block", "lan", "any", "iot_devices", "any", None, "IoT default deny"),
        R("block", "lan", "tcp", "kids_devices", "any", "6881:6889", "kids no bittorrent"),
        R("block", "lan", "udp", "kids_devices", "any", "3478:3480", "kids no STUN"),
        R("pass", "lan", "tcp", "kids_devices", "any", "web_ports", "kids web"),
        R("block", "lan", "any", "kids_devices", "any", None, "kids default deny"),
        R("block", "lan", "tcp", "lan", "any", "445", "no SMB out"),
        R("block", "lan", "tcp", "lan", "any", "135:139", "no NetBIOS out"),
        R("block", "lan", "udp", "lan", "any", "137:138", "no NetBIOS/udp out"),
        R("block", "lan", "udp", "lan", "any", "1900", "no SSDP out"),
        R("block", "lan", "tcp", "lan", "any", "23", "no telnet out"),
    ]
    # filler: per-host exceptions typical of a family network
    i = 0
    while len(rs) < 45:
        host = f"192.168.1.{60 + i}"
        rs.append(R("block" if i % 2 else "pass", "lan", "tcp" if i % 3 else "udp", host,
                    f"198.18.{i}.0/24", str(7000 + i), f"host exception {i}"))
        i += 1
    rs += [
        R("pass", "lan", "any", "lan", "any", None, "LAN to any"),
        R("block", "wan", "any", "blocklist_v4", "any", None, "WAN blocklist"),
        R("pass", "wan", "icmp", "any", "self", None, "WAN ping"),
        R("block", "wan", "tcp", "any", "self", "22", "WAN SSH"),
        R("block", "wan", "tcp", "any", "self", "443", "WAN GUI"),
    ]
    assert len(rs) == 50
    if large:
        # 950 more specific rules placed before "LAN to any" so new flows walk them
        extra = []
        for j in range(950):
            host = f"192.168.1.{2 + (j % 9)}" if j % 5 == 0 else f"192.168.1.{150 + (j % 100)}"
            dst = f"100.{64 + j // 250}.{j % 250}.0/24"
            extra.append(R("block" if j % 3 == 0 else "pass", "lan", "tcp" if j % 2 else "udp",
                           host, dst, str(10000 + j), f"bulk rule {j}"))
        k = next(n for n, r in enumerate(rs) if r["descr"] == "LAN to any")
        rs = rs[:k] + extra + rs[k:]
        assert len(rs) == 1000
    return rs


# ---------------------------------------------------------------- nftables
def nft_addr(x, al):
    if x == "lan":
        return LAN_NET
    if x in al:
        return "@" + x
    return x


def nft_port(p, al):
    if p in al:
        return "@" + p
    return p.replace(":", "-")


def nft_rule(r, al):
    parts = []
    if r["src"] != "any":
        parts.append(f"ip saddr {nft_addr(r['src'], al)}")
    if r["dst"] not in ("any", "self"):
        parts.append(f"ip daddr {nft_addr(r['dst'], al)}")
    if r["proto"] in ("tcp", "udp"):
        parts.append(r["proto"] + (f" dport {nft_port(r['dport'], al)}" if r["dport"] else ""))
    elif r["proto"] == "icmp":
        parts.append("ip protocol icmp")
    verdict = "accept" if r["action"] == "pass" else "drop"
    return " ".join(parts + [f'counter {verdict} comment "{r["descr"]}"'])


def render_nft(large, flowtable):
    al = aliases(large)
    rs = rules(large)
    out = ["flush ruleset", "", "table inet filter {"]
    for name, a in al.items():
        if a["type"] == "port":
            out.append(f"  set {name} {{ type inet_service; elements = {{ {', '.join(a['content'])} }} }}")
        else:
            flags = " flags interval;" if a["type"] == "network" else ""
            out.append(f"  set {name} {{ type ipv4_addr;{flags} elements = {{ {', '.join(a['content'])} }} }}")
    if flowtable:
        out.append("  flowtable ft { hook ingress priority 0; devices = { lan0, wan0 }; }")
    out.append("  chain input {\n    type filter hook input priority filter; policy drop;")
    out.append("    iif lo accept\n    ct state established,related accept\n    ct state invalid drop")
    # equivalent of OPNsense's built-in anti-lockout rule (LAN -> self 22/80/443)
    out.append('    iifname "lan0" tcp dport { 22, 80, 443, 8080 } accept comment "anti-lockout"')
    for r in rs:
        if r["dst"] == "self":
            out.append(f"    iifname \"{r['iface']}0\" " + nft_rule(r, al))
    out.append("  }")
    out.append("  chain forward {\n    type filter hook forward priority filter; policy drop;")
    if flowtable:
        out.append("    meta l4proto { tcp, udp } flow add @ft")
    out.append("    ct state established,related accept\n    ct state invalid drop")
    for r in rs:
        if r["dst"] != "self":
            out.append(f"    iifname \"{r['iface']}0\" " + nft_rule(r, al))
    out.append("  }")
    out.append("  chain output { type filter hook output priority filter; policy accept; }")
    out.append("}")
    out.append("table ip nat {\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;")
    out.append(f"    oifname \"wan0\" ip saddr {LAN_NET} masquerade\n  }}\n}}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- OpenBSD pf
def pf_addr(x, al):
    if x == "lan":
        return "$lan_net"
    if x == "self":
        return "self"
    if x in al:
        return f"<{x}>"
    return x


def pf_port(p, al):
    if p in al:
        return "{ " + " ".join(al[p]["content"]) + " }"
    return p


def render_pf(large):
    al = aliases(large)
    rs = rules(large)
    out = ['lan = "vio0"', 'wan = "vio1"', f'lan_net = "{LAN_NET}"', ""]
    for name, a in al.items():
        if a["type"] == "port":
            continue
        out.append(f"table <{name}> persist file \"/etc/pf/{name}.txt\"")
    out += ["", "set skip on lo", "", "match out on $wan inet from $lan_net nat-to ($wan)",
            "block log all", "pass out quick inet",
            "pass in quick on $lan inet proto tcp to self port { 22 80 443 }  # anti-lockout", ""]
    for r in rs:
        proto = "" if r["proto"] == "any" else f" proto {r['proto']}"
        src = "" if r["src"] == "any" else pf_addr(r["src"], al)
        dst = "any" if r["dst"] == "any" else pf_addr(r["dst"], al)
        port = f" port {pf_port(r['dport'], al)}" if r["dport"] else ""
        frm = f" from {src}" if src else " from any"
        out.append(f"{r['action']} in quick on ${r['iface']} inet{proto}{frm} to {dst}{port}  # {r['descr']}")
    return "\n".join(out) + "\n", {n: a["content"] for n, a in al.items() if a["type"] != "port"}


# ---------------------------------------------------------------- VyOS
def render_vyos(large):
    """VyOS 'set' commands (rolling syntax). eth0 = LAN, eth1 = WAN."""
    al = aliases(large)
    rs = rules(large)
    out = []
    for n, a in al.items():
        if a["type"] == "port":
            out += [f"set firewall group port-group {n} port {p}" for p in a["content"]]
        elif a["type"] == "host":
            out += [f"set firewall group address-group {n} address {x}" for x in a["content"]]
        else:
            out += [f"set firewall group network-group {n} network {x if '/' in x else x + '/32'}" for x in a["content"]]
    for chain in ("input", "forward"):
        base = f"set firewall ipv4 {chain} filter"
        out += [f"{base} default-action drop",
                f"{base} rule 1 action accept", f"{base} rule 1 state established", f"{base} rule 1 state related",
                f"{base} rule 2 action drop", f"{base} rule 2 state invalid"]
    out += ["set firewall ipv4 input filter rule 3 action accept",
            "set firewall ipv4 input filter rule 3 inbound-interface name lo",
            "set firewall ipv4 input filter rule 4 action accept",
            "set firewall ipv4 input filter rule 4 inbound-interface name eth0",
            "set firewall ipv4 input filter rule 4 protocol tcp",
            "set firewall ipv4 input filter rule 4 destination port 22,80,443,8080",
            "set firewall ipv4 input filter rule 4 description anti-lockout"]
    n = {"input": 10, "forward": 10}
    for r in rs:
        chain = "input" if r["dst"] == "self" else "forward"
        b = f"set firewall ipv4 {chain} filter rule {n[chain]}"
        n[chain] += 1
        out.append(f"{b} action {'accept' if r['action'] == 'pass' else 'drop'}")
        out.append(f"{b} inbound-interface name {'eth0' if r['iface'] == 'lan' else 'eth1'}")
        out.append(f"{b} description '{r['descr']}'")
        if r["proto"] != "any":
            out.append(f"{b} protocol {r['proto']}")
        for side, key in (("source", "src"), ("destination", "dst")):
            x = r[key]
            if x in ("any", "self"):
                continue
            if x == "lan":
                out.append(f"{b} {side} address {LAN_NET}")
            elif x in al:
                kind = {"host": "address-group", "network": "network-group"}[al[x]["type"]]
                out.append(f"{b} {side} group {kind} {x}")
            else:
                out.append(f"{b} {side} address {x}")
        if r["dport"]:
            if r["dport"] in al:
                out.append(f"{b} destination group port-group {r['dport']}")
            else:
                out.append(f"{b} destination port {r['dport'].replace(':', '-')}")
    out += ["set nat source rule 100 outbound-interface name eth1",
            f"set nat source rule 100 source address {LAN_NET}",
            "set nat source rule 100 translation address masquerade"]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- OPNsense
def opn_payload(large):
    al = aliases(large)
    rs = rules(large)
    A = [{"alias": {"enabled": "1", "name": n, "type": a["type"],
                    "content": "\n".join(a["content"]), "description": n}}
         for n, a in al.items()]
    def net(x):
        return {"lan": "lan", "self": "(self)", "any": "any"}.get(x, x)
    F = []
    for seq, r in enumerate(rs, start=1):
        F.append({"rule": {
            "enabled": "1", "sequence": str(seq * 10), "action": r["action"], "quick": "1",
            "interface": r["iface"], "direction": "in", "ipprotocol": "inet",
            "protocol": {"any": "any", "tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}[r["proto"]],
            "source_net": net(r["src"]), "destination_net": net(r["dst"]),
            "destination_port": (r["dport"] or "").replace(":", "-"),
            "description": r["descr"], "log": "0",
        }})
    return {"aliases": A, "rules": F}


def main():
    for d in ("nft", "pf", "opn", "tables", "vyos"):
        os.makedirs(os.path.join(OUT, d), exist_ok=True)
    for size in ("small", "large"):
        large = size == "large"
        for ft in (False, True):
            p = os.path.join(OUT, "nft", f"{size}{'-ft' if ft else ''}.nft")
            open(p, "w").write(render_nft(large, ft))
        conf, tables = render_pf(large)
        open(os.path.join(OUT, "pf", f"{size}.conf"), "w").write(conf)
        os.makedirs(os.path.join(OUT, "pf", f"{size}-tables"), exist_ok=True)
        for n, content in tables.items():
            open(os.path.join(OUT, "pf", f"{size}-tables", f"{n}.txt"), "w").write("\n".join(content) + "\n")
        open(os.path.join(OUT, "vyos", f"{size}.cmds"), "w").write(render_vyos(large))
        json.dump(opn_payload(large), open(os.path.join(OUT, "opn", f"{size}.json"), "w"), indent=1)
    for n, label in ((1000, "1k"), (10000, "10k"), (100000, "100k")):
        open(os.path.join(OUT, "tables", f"blk-{label}.txt"), "w").write("\n".join(blocklist(n, 11)) + "\n")
    # sanity: the benchmark endpoints must not be caught by any table entry
    for e in blocklist(100000, 11) + blocklist(10000, 7):
        assert ipaddress.ip_address("10.99.0.10") not in ipaddress.ip_network(e, strict=False)


if __name__ == "__main__":
    main()
