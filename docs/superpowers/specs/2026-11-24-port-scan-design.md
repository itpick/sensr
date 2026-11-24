# Daily open-port scan of LAN hosts: design

Status: approved by the owner, 2026-11-24 ("go ahead and build the port scanner").

## Why

The owner wants to know which ports each device on the network has open, for example a camera exposing RTSP
or telnet, or an Echo serving its admin UI on 8080/8443. The router discovers these once a day and shows
them on each device's page.

## Goals

- **What is scanned**
  - Every host on an internal interface that has an IPv4 address and was seen in the last 24 h.
  - Skipped: Quarantine hosts and the router's own addresses.
- **Ports**
  - TCP 1–1024, plus this extra list: 554, 1883, 1900, 3000, 3389, 5000, 5001, 5353, 5555, 5900, 8000, 8008,
    8009, 8080, 8123, 8443, 8554, 8883, 8888, 9000, 32400, 49152.
  - Owner-extendable via config `hosts.portscan.extra_ports`.
- **Method**
  - Plain TCP connect: open = connection accepted, closed = refused, filtered = timeout.
  - Only open ports are stored.
  - No raw sockets and no UDP.
- **Rate**
  - At most 200 connection attempts per second overall and at most 8 in flight per host.
  - 1.5 s connect timeout.
  - One host at a time per interface.
  - A full LAN of about 70 hosts finishes in roughly 7 minutes or less.
- **Schedule**
  - Daily at 03:30 local time (config `hosts.portscan.time`).
  - Plus "Scan now" for one host from the UI or API.
  - It can be turned off with `hosts.portscan.enabled` (default true).
- **Results**
  - Per host: the open ports with first seen, last seen and service name. The name comes from a small
    built-in table (22 ssh, 23 telnet, 53 dns, 80 http, 443 https, 554 rtsp, 8080 http-alt, …) or is empty.
  - A port is **new** if first seen within the last 24 h.
  - A port that was open but is now closed is kept as `closed_at` for 90 days.
  - Results are stored in the agent's state directory.
- **Where it shows**
  - The host page (`/ui/hosts/<mac>`) gets an **Open ports** card: port, service, first seen, a new pill,
    "last scanned …", and a "Scan now" button.
  - Each Hosts card row shows "N open" next to its smart label.
  - Global search matches `port 23` or `23/tcp` to hosts with that port open.
- **API**
  - `GET /api/v1/hosts/<mac>/ports`.
  - `POST /api/v1/hosts/<mac>/scan`. It returns 202, and the scan runs in the background.
  - Both use the existing hosts privilege. Scan now also needs the user not to be read-only.

## Non-goals

- Firewall changes or blocking based on results.
- Vulnerability scanning.
- OS detection.
- Scanning WAN or remote hosts.
- UDP.

## Anti-goals

- Upsetting cheap IoT devices, which is why the rate is low.
- Tripping the router's own IDS. Suricata listens on the WAN only, so LAN scans don't cross it; this is
  noted in the docs.
- Leaving connections half open.

## Approach

A `portscan` module in sensr-agent: tokio TCP connects, bounded by a semaphore and a governor-style rate
limit, with no new crates. It is driven by the agent's existing timers. It reads targets from the host
inventory and stores `ports.json` in the state directory. The hosts view gains a count, and the host page
gains the card.

## Left to the builder

- The exact service-name table.
- How the Hosts card count is styled.
