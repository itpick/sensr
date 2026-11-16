# sensr-net test fixtures

All files here are **synthetic**: hand-written to the shape iproute2 prints
for `ip -j -6 route show table all` and `ip -j -6 addr show`, using only the
documentation prefix `2001:db8::/32` (RFC 3849) and made-up link names. None
was captured from a real router and none is copied from OPNsense.

| File | Situation |
|---|---|
| `routes-pd56.json` | WAN `wan0` holds a /56 from networkd's DHCPv6 client: `unreachable … proto dhcp` route with `expires`, plus the usual RA default, link and kernel routes. |
| `addrs-pd56.json` | Addresses for the same router: WAN IA_NA address, `lan0` (subnet 0) and `lan1` (subnet 0x10) PD addresses with finite lifetimes, a static ULA, link-locals. |
| `routes-pd64.json` | A /64 delegation: networkd installs no unreachable route. |
| `addrs-pd64.json` | `lan0` holding the single delegated /64. |
| `routes-two-uplinks.json` | Two uplinks each with a delegated prefix (`2001:db8:a::/56`, `2001:db8:b::/60`); the unreachable routes both sit on `lo`. |
| `addrs-two-uplinks.json` | `lan0` inside the first, `lan9` inside the second. |
| `routes-expires-text.json` | Older iproute2 style where `expires` is a string such as `"3539sec"`. |
