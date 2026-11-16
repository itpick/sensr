#!/usr/bin/env python3
"""Patch the factory OPNsense config.xml into the benchmark baseline.

Only what the topology needs is changed; everything else stays "as shipped"
(including the default hardware-offload-disabled settings):
  - WAN static 10.99.0.1/24 with gateway WAN_GW=10.99.0.254 (automatic
    outbound NAT only applies to interfaces that have a gateway)
  - block private/bogon networks on WAN off (the lab "internet" is 10.99/24)
  - IPv6 off on WAN/LAN (the NixOS router is IPv4-only too)
  - SSH on, root login with the bench key only; initial wizard skipped
usage: opn_bootstrap.py IN.xml OUT.xml PUBKEY_FILE
"""
import base64
import sys
import uuid
import xml.etree.ElementTree as ET

src, dst, pubkey = sys.argv[1:4]
tree = ET.parse(src)
root = tree.getroot()


def sub(parent, tag, text=None):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    if text is not None:
        el.text = text
    return el


wiz = root.find("trigger_initial_wizard")
if wiz is not None:
    root.remove(wiz)

system = root.find("system")
ssh = sub(system, "ssh")
sub(ssh, "enabled", "enabled")
sub(ssh, "permitrootlogin", "1")
sub(ssh, "group", "admins")
for user in system.findall("user"):
    if user.findtext("name") == "root":
        sub(user, "authorizedkeys", base64.b64encode(open(pubkey).read().encode()).decode())

wan = root.find("interfaces/wan")
sub(wan, "ipaddr", "10.99.0.1")
sub(wan, "subnet", "24")
sub(wan, "gateway", "WAN_GW")
for tag in ("blockpriv", "blockbogons", "ipaddrv6", "dhcp6-ia-pd-len"):
    el = wan.find(tag)
    if el is not None:
        wan.remove(el)
lan = root.find("interfaces/lan")
for tag in ("ipaddrv6", "subnetv6", "track6-interface", "track6-prefix-id"):
    el = lan.find(tag)
    if el is not None:
        lan.remove(el)

opn = sub(root, "OPNsense")
gws = sub(opn, "Gateways")
gw = ET.SubElement(gws, "gateway_item", {"uuid": str(uuid.uuid4())})
for k, v in {
    "disabled": "0", "name": "WAN_GW", "descr": "bench upstream", "interface": "wan",
    "ipprotocol": "inet", "gateway": "10.99.0.254", "defaultgw": "1",
    "fargw": "0", "monitor_disable": "0", "monitor_noroute": "0", "force_down": "0",
    "priority": "255", "weight": "1",
}.items():
    sub(gw, k, v)

tree.write(dst, xml_declaration=True, encoding="utf-8")
