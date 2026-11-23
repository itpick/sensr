# Per-host DNS activity ("what is this device doing"): design

Status: draft for owner approval, 2026-11-23.

## Why

The owner wants to see what each device on the network is doing, mainly their kids' devices, and also to
spot odd or chatty devices. For a kid's tablet that means "45 min YouTube, 20 min Roblox today" plus the
categories (video, social, games) over the week. For an IoT gadget it means which domains it talks to, and
when a new one shows up.

This is item 6 of the owner's queue, moved ahead of allowlist mode (item 3). It also builds the DNS-answer
feed that allowlist mode needs.

## Goals

- **Host page.** Clicking a device's name on the dashboard Hosts card opens `/ui/hosts/<mac>`.
  - The page header shows the host's name, smart label, IPs, mode and last seen.
  - **Today / 7 days** toggle.
  - **Services:** minutes per service (YouTube, Netflix, TikTok, Roblox, Minecraft, Discord, …), largest
    first, each with its category and a bar.
  - **Categories:** total minutes per category (Video, Social, Games, Messaging, Music, Education,
    Shopping, Apple/Google/Microsoft system, Ads & tracking, Smart home, Other).
  - **Timeline:** a 24 × 7 heat strip of active minutes per hour, showing when the device is used.
  - **Domains:** every domain the device asked for, with query count, service, first seen and last seen.
    - Badges: **new** (first seen in the last 24 h) and **blocked** (answered by a DNS blocklist).
    - The list is searchable and sortable.
- **Hosts card.** Each row gets a small "today" figure (e.g. `1 h 12 m`) for devices that have activity.
- **Retention.**
  - Per-minute detail: 7 days.
  - Daily service minutes: 90 days.
  - Both are kept on the router, in the existing insight SQLite store, with no SD-card thrash. SQLite is
    already used for traffic buckets.
- **Privacy.** Nothing leaves the router. The page needs the hosts privilege plus the insight privilege.

## Non-goals (this piece)

- Blocking or time limits per device. That comes later through allowlist mode and schedules.
- Forcing devices to use the router's DNS (DNS intercept / DoH blocking). This is a separate gap item.
- Per-device notifications. These come later through the notifications item.

## Anti-goals

- **Wildly wrong minutes.** DNS queries alone undercount streaming, because one lookup can be followed by
  an hour of video. Counting every background ping as "use" overcounts. The rules below address both.
- Packet capture or deep inspection on the Pi: the CPU cost, and the privacy.
- A service catalogue the owner cannot correct.

## Approaches considered

1. **Re-read Unbound's query log** (exists today). It has client and name only. It has no answers, so
   flows cannot be tied to services, and minutes would be DNS-only.
2. **Unbound dnstap + insight's kernel flow counters (chosen).** Unbound streams every client query and
   response, answers included, to a local socket. That gives, per client, name → answer IPs with TTLs.
   Insight already counts traffic in the kernel. It gains a host-by-remote-address counter, so each
   minute's bytes per (device, remote IP) can be attributed to the domain and service that resolved to
   that IP. This makes streaming minutes accurate, and the same answer feed is what allowlist mode
   needs.
3. **Make sensr-dns a DNS proxy in front of Unbound.** Full control, but it adds a hop and a failure
   point on the DNS path.

## Design

### Capture

- **Unbound build.** Unbound is built `withDNSTAP = true`, via a package override in the sensr NixOS
  module.
- **Unbound config.** The rendered config enables dnstap to the unix socket
  `/run/sensr-insight/dnstap.sock` with `dnstap-log-client-query-messages: yes` and
  `dnstap-log-client-response-messages: yes`. It is enabled only when insight is enabled.
- **Collector.** `sensr-insight` (the daemon that already owns the flow store) listens on the socket and
  reads the Frame Streams protocol.
  - It decodes the dnstap protobuf with a small hand-written decoder for the few fields used, with no new
    crate.
  - It parses the DNS response with the existing DNS wire parser (crates/sensr-fingerprint mdns/dns code,
    shared).
- **Each response yields:** client IP, qname, qtype, rcode, answer A/AAAA records with TTLs, whether the
  answer came from a blocklist local-zone (0.0.0.0, or NXDOMAIN from a blocklisted zone), and the time.

### Attribution

- **Client to device.** Client IP maps to MAC through the host inventory (the neighbour table and leases;
  insight reads the agent's hosts view).
- **IP map.** Per device, a short-lived map from remote IP to (qname, expiry). Expiry is answer TTL
  + 10 min of grace, bounded at 4096 entries per device.
- **Flow counters.** The kernel accounting table gains a set keyed by (local host . remote address) with
  counters, named `p…` like the other sets, with the same timeout and a max-entries bound.
  - Every sample, insight attributes each (device, remote IP) delta to the mapped qname.
  - If there is no mapping, the delta goes to the PTR-less bucket "Other (by address)".

### Catalogue

- A built-in table maps domain suffixes to service and category, e.g.
  `googlevideo.com, youtube.com, ytimg.com → YouTube / Video` and
  `roblox.com, rbxcdn.com → Roblox / Games`.
- It covers about 150 services, chosen for what kids use plus the big platforms and trackers. It is our
  own data file, with tests.
- **Owner corrections.** Config `insight.dns.service_overrides` maps a domain suffix to a service name and
  a category, and wins over the built-in table. Part B adds a small editor on the host page ("This is
  YouTube Kids → Video").

### Minutes

- **Active minute.** A device is active on a service in a given minute if either:
  - it moved at least **32 KB**, summed across the minute, to or from IPs attributed to that service; or
  - it queried a domain of that service in that minute and moved at least **4 KB** to it.
- **Background traffic.** Pure background pings never count, because they stay below the threshold.
- **Category minutes.** Category minutes are the union of their services' minutes, so two services active
  in the same minute count as one minute for the category.
- **System and tracking.** "Apple/Google/Microsoft system" and "Ads & tracking" are shown, but are not
  counted in the headline "screen time" total.

### Storage

New tables in the insight SQLite, retention-pruned like `traffic`:

- `dns_queries(host, minute, qname, count, blocked)`, kept 7 days.
- `service_minutes(host, minute, service)`, kept 7 days.
- `service_days(host, day, service, minutes)`, kept 90 days.
- `domains_seen(host, qname, first_seen, last_seen, count)`, kept 90 days.

### API and UI

- **API.** `GET /api/v1/hosts/<mac>/activity?range=today|7d` returns header, services, categories,
  timeline and domains (paged). It is covered by the hosts plus insight privileges.
- **Host page.** A new server-rendered page with small islands for the range toggle and the domain table
  search, reusing the existing grid/table styles. Charts are simple bars and a heat strip made of CSS
  grid cells: no chart library, minimal wasm.
- **Hosts card link.** The Hosts card name becomes a link to the host page, and the "today" figure comes
  from `service_days`.

## Constraints

- **Dependencies.** Latest dependencies and no new crates. The protobuf and Frame Streams decoders are
  hand-written and fuzz-tested, like the DHCP/mDNS parsers.
- **Code safety.** `unsafe` is forbidden. Linux-only socket code is cfg-gated.
- **Pi budget.** At most 2 % of one core at typical home load, and bounded memory: about 4096 IP-map
  entries per device and a global cap of 64k.
- **Degradation.** If dnstap is not available, the page shows DNS-only data from the query log path that
  exists today.
- **Housekeeping.** No AI attribution. The island bundle stays within its budget.
- **Tests.** Unit tests for the decoders, catalogue, attribution and minute rules; an end-to-end VM check
  in `slice.nix` that a client's lookup plus a download produces service minutes; e2e for the page.

## Left to the builder

- The exact service list, beyond the kid-relevant core (YouTube, YouTube Kids, Netflix, Disney+, Prime
  Video, Twitch, TikTok, Instagram, Snapchat, Facebook, Messenger, WhatsApp, Discord, Roblox, Minecraft,
  Fortnite/Epic, Steam, Xbox, PlayStation, Nintendo, Spotify, Apple Music, Khan Academy, Google
  Classroom, Duolingo, ChatGPT, Amazon shopping).
- The page layout details, within the existing design language.
