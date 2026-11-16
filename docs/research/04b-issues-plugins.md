# 04b — opnsense/plugins issue tracker: what 3,230 issues tell sensr

Source: all 3,230 issues (no PRs) of <https://github.com/opnsense/plugins>, snapshot 2026-11-15. Every issue was classified to a plugin programmatically (title prefixes such as `net/frr:` / `os-haproxy`, then keyword fallbacks on title and body); the 165 open issues and the ~730 declined ones were then read individually. Issue type (bug / feature / support / other) comes from labels where present and from title heuristics otherwise, so counts are approximate (±10%). "Engagement" = reactions + comments.

Companion documents: 04a covers opnsense/core. Stable IDs for the 30 most impactful plugin findings are `ISS-P-001`…`ISS-P-030` (section 7) and are referenced throughout.

## 1. Statistics

### 1.1 By state and close reason

| State / reason | Count | Share |
|---|---:|---:|
| closed / completed | 2286 | 70.8% |
| closed / not_planned | 764 | 23.7% |
| open / None | 160 | 5.0% |
| closed / duplicate | 15 | 0.5% |
| open / reopened | 5 | 0.2% |
| **total** | **3230** | 100% |

Reading: 71% of all issues were closed as completed, 24% as not_planned. Of the 764 not_planned closes, **709 carried the `help wanted` label** — OPNsense's way of saying "we would merge a PR but will not write it". That pile (section 3) is the clearest list of features users wanted and nobody delivered.

### 1.2 By label

| Label | Count | closed completed | closed not_planned | open |
|---|---:|---:|---:|---:|
| help wanted | 1115 | 403 | 709 | 3 |
| support | 537 | 366 | 139 | 29 |
| feature | 505 | 474 | 15 | 16 |
| incomplete | 417 | 236 | 152 | 21 |
| bug | 269 | 258 | 7 | 4 |
| cleanup | 131 | 125 | 4 | 2 |
| upstream | 94 | 70 | 17 | 7 |
| dependencies | 1 | 1 | 0 | 0 |
| (no label) | 641 | | | 88 |

### 1.3 By derived type

| Type | Count | completed | not_planned | open |
|---|---:|---:|---:|---:|
| bug | 1043 | 732 | 255 | 48 |
| feature | 977 | 740 | 181 | 54 |
| other | 717 | 477 | 197 | 41 |
| support | 493 | 337 | 131 | 22 |

### 1.4 By year opened

| Year | Issues | bug | feature | support | other | still open |
|---|---:|---:|---:|---:|---:|---:|
| 2015 | 7 | 0 | 7 | 0 | 0 | 0 |
| 2016 | 25 | 5 | 15 | 0 | 5 | 0 |
| 2017 | 181 | 45 | 87 | 18 | 31 | 0 |
| 2018 | 272 | 62 | 132 | 36 | 42 | 0 |
| 2019 | 266 | 82 | 90 | 45 | 49 | 0 |
| 2020 | 295 | 66 | 96 | 48 | 85 | 0 |
| 2021 | 326 | 115 | 85 | 45 | 81 | 1 |
| 2022 | 307 | 107 | 86 | 53 | 61 | 3 |
| 2023 | 316 | 123 | 62 | 54 | 77 | 1 |
| 2024 | 404 | 154 | 99 | 61 | 90 | 9 |
| 2025 | 356 | 98 | 101 | 73 | 84 | 4 |
| 2026 | 475 | 186 | 117 | 60 | 112 | 147 |

Volume is still growing (475 issues in the first 10.5 months of 2026, the highest ever) and the tracker is kept nearly empty: 147 of the 165 open issues are from 2026. Older items are closed aggressively (stale bot + `help wanted` → not_planned), so "open" is not a backlog — it is the last ~6 months of inflow.

### 1.5 Issues per plugin (all plugins, sorted)

Includes historic plugins that no longer exist in the tree (wireguard → core, dyndns, quagga, unbound-plus, monit, arp-scan, firewall-api) and non-plugin buckets (new-plugin-request, core-misfiled, OPNWAF which is a third-party repo).

| Plugin | Total | bug | feature | support | other | open | completed | not_planned | help wanted | upstream | first | last | engagement | sensr tier |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|---|---:|---|
| acme-client | 397 | 128 | 125 | 99 | 45 | 18 | 332 | 45 | 64 | 40 | 2015 | 2026 | 1782 | core |
| frr | 224 | 54 | 75 | 31 | 64 | 7 | 163 | 54 | 78 | 4 | 2017 | 2026 | 1159 | core |
| haproxy | 219 | 68 | 80 | 51 | 20 | 11 | 197 | 11 | 29 | 6 | 2016 | 2026 | 1104 | first-party |
| nginx | 197 | 75 | 67 | 15 | 40 | 12 | 141 | 42 | 76 | 0 | 2018 | 2026 | 715 | community |
| ddclient | 155 | 55 | 43 | 26 | 31 | 10 | 67 | 78 | 77 | 3 | 2018 | 2026 | 817 | core |
| caddy | 125 | 31 | 41 | 18 | 35 | 2 | 97 | 26 | 12 | 4 | 2018 | 2026 | 643 | first-party |
| wireguard | 120 | 33 | 20 | 35 | 32 | 1 | 83 | 36 | 51 | 1 | 2018 | 2026 | 800 | core |
| freeradius | 102 | 39 | 27 | 7 | 29 | 5 | 69 | 28 | 40 | 1 | 2017 | 2026 | 492 | first-party |
| bind | 101 | 31 | 36 | 12 | 22 | 8 | 52 | 41 | 51 | 1 | 2018 | 2026 | 406 | first-party |
| dyndns | 94 | 39 | 18 | 7 | 30 | 0 | 87 | 7 | 48 | 4 | 2017 | 2026 | 451 | core |
| core-misfiled/other | 79 | 22 | 10 | 15 | 32 | 1 | 64 | 13 | 27 | 0 | 2015 | 2026 | 252 | n/a |
| new-plugin-request | 68 | 2 | 61 | 5 | 0 | 11 | 42 | 14 | 27 | 0 | 2015 | 2026 | 534 | n/a |
| telegraf | 66 | 20 | 21 | 2 | 23 | 1 | 44 | 21 | 31 | 0 | 2017 | 2026 | 265 | first-party |
| nut | 60 | 27 | 13 | 2 | 18 | 0 | 35 | 22 | 30 | 1 | 2017 | 2026 | 337 | first-party |
| postfix | 54 | 16 | 25 | 7 | 6 | 4 | 40 | 10 | 17 | 0 | 2017 | 2026 | 192 | community |
| git-backup | 41 | 19 | 2 | 17 | 3 | 6 | 21 | 14 | 15 | 0 | 2020 | 2026 | 156 | core |
| upnp | 41 | 10 | 9 | 8 | 14 | 3 | 28 | 10 | 20 | 3 | 2017 | 2026 | 165 | core |
| crowdsec | 39 | 17 | 8 | 3 | 11 | 5 | 21 | 12 | 12 | 4 | 2022 | 2026 | 177 | first-party |
| dnscrypt-proxy | 37 | 11 | 8 | 4 | 14 | 3 | 24 | 10 | 16 | 0 | 2018 | 2026 | 217 | first-party |
| squid | 36 | 14 | 3 | 9 | 10 | 2 | 17 | 16 | 22 | 3 | 2017 | 2026 | 197 | community |
| OPNWAF (3rd-party) | 35 | 5 | 21 | 5 | 4 | 0 | 31 | 4 | 4 | 0 | 2024 | 2026 | 88 | n/a |
| zabbix-agent | 35 | 7 | 17 | 6 | 5 | 2 | 29 | 3 | 3 | 1 | 2017 | 2026 | 202 | first-party |
| tor | 34 | 9 | 14 | 2 | 9 | 2 | 18 | 14 | 21 | 0 | 2017 | 2026 | 95 | community |
| firewall-api | 31 | 6 | 11 | 8 | 6 | 2 | 18 | 10 | 11 | 0 | 2018 | 2026 | 125 | core |
| tailscale | 29 | 5 | 7 | 5 | 12 | 8 | 8 | 13 | 13 | 0 | 2023 | 2026 | 173 | first-party |
| zabbix-proxy | 29 | 8 | 12 | 3 | 6 | 1 | 22 | 6 | 13 | 0 | 2018 | 2026 | 115 | first-party |
| quagga | 29 | 8 | 12 | 2 | 7 | 0 | 29 | 0 | 4 | 0 | 2017 | 2025 | 207 | core |
| zerotier | 27 | 6 | 9 | 5 | 7 | 0 | 22 | 5 | 13 | 1 | 2017 | 2025 | 129 | first-party |
| nextcloud-backup | 26 | 12 | 6 | 3 | 5 | 3 | 12 | 11 | 12 | 0 | 2018 | 2026 | 142 | core |
| openconnect | 25 | 9 | 4 | 3 | 9 | 0 | 16 | 9 | 13 | 0 | 2018 | 2025 | 101 | first-party |
| unbound-plus | 24 | 6 | 9 | 2 | 7 | 0 | 17 | 7 | 15 | 0 | 2018 | 2026 | 115 | core |
| intrusion-detection-content | 22 | 9 | 4 | 4 | 5 | 1 | 16 | 5 | 5 | 0 | 2017 | 2026 | 93 | first-party |
| net-snmp | 20 | 6 | 4 | 3 | 7 | 1 | 14 | 5 | 8 | 2 | 2017 | 2026 | 107 | core |
| tinc | 20 | 11 | 1 | 1 | 7 | 0 | 20 | 0 | 4 | 0 | 2016 | 2026 | 104 | community |
| rspamd | 20 | 8 | 7 | 1 | 4 | 0 | 15 | 5 | 9 | 0 | 2017 | 2023 | 162 | community |
| mdns-repeater | 19 | 6 | 7 | 3 | 3 | 1 | 6 | 12 | 13 | 0 | 2017 | 2026 | 73 | first-party |
| monit | 19 | 5 | 10 | 2 | 2 | 1 | 17 | 1 | 4 | 0 | 2017 | 2026 | 103 | core |
| ntopng | 18 | 7 | 4 | 0 | 7 | 2 | 11 | 5 | 10 | 1 | 2018 | 2026 | 75 | community |
| relayd | 18 | 9 | 3 | 0 | 6 | 0 | 15 | 3 | 4 | 0 | 2017 | 2025 | 51 | drop |
| vnstat | 16 | 4 | 7 | 1 | 4 | 1 | 10 | 5 | 7 | 0 | 2015 | 2026 | 65 | core |
| etpro-telemetry | 16 | 7 | 1 | 4 | 4 | 0 | 12 | 4 | 3 | 0 | 2019 | 2026 | 64 | community |
| q-feeds-connector | 15 | 7 | 4 | 0 | 4 | 2 | 12 | 1 | 1 | 0 | 2026 | 2026 | 34 | community |
| wol | 15 | 6 | 2 | 3 | 4 | 1 | 11 | 3 | 5 | 0 | 2018 | 2026 | 59 | core |
| smart | 15 | 3 | 5 | 3 | 4 | 1 | 12 | 2 | 6 | 0 | 2018 | 2026 | 74 | core |
| c-icap | 15 | 9 | 4 | 1 | 1 | 0 | 14 | 1 | 1 | 1 | 2017 | 2026 | 160 | community |
| theme-cicada | 14 | 8 | 0 | 1 | 5 | 1 | 8 | 5 | 7 | 0 | 2019 | 2026 | 64 | drop |
| chrony | 14 | 7 | 6 | 1 | 0 | 0 | 8 | 6 | 8 | 0 | 2020 | 2026 | 46 | core |
| netdata | 14 | 6 | 2 | 3 | 3 | 0 | 10 | 4 | 9 | 0 | 2019 | 2025 | 98 | community |
| netbird | 13 | 7 | 1 | 2 | 3 | 1 | 9 | 3 | 3 | 0 | 2025 | 2026 | 75 | first-party |
| rfc2136 | 13 | 8 | 2 | 0 | 3 | 0 | 5 | 8 | 11 | 0 | 2020 | 2026 | 37 | core |
| igmp-proxy | 12 | 5 | 2 | 3 | 2 | 2 | 7 | 3 | 2 | 2 | 2017 | 2026 | 41 | core |
| maltrail | 12 | 5 | 2 | 2 | 3 | 2 | 9 | 1 | 2 | 1 | 2019 | 2026 | 47 | drop |
| udpbroadcastrelay | 12 | 4 | 1 | 1 | 6 | 0 | 3 | 9 | 12 | 0 | 2020 | 2026 | 72 | first-party |
| theme-rebellion | 12 | 5 | 3 | 0 | 4 | 0 | 6 | 6 | 6 | 0 | 2018 | 2026 | 63 | drop |
| openvpn-legacy | 11 | 5 | 1 | 1 | 4 | 1 | 8 | 2 | 4 | 0 | 2017 | 2026 | 70 | n/a |
| iperf | 11 | 5 | 3 | 1 | 2 | 0 | 7 | 4 | 7 | 0 | 2018 | 2026 | 49 | core |
| themes | 10 | 4 | 1 | 0 | 5 | 2 | 5 | 3 | 4 | 0 | 2017 | 2026 | 24 | drop |
| wazuh-agent | 10 | 6 | 2 | 1 | 1 | 2 | 5 | 3 | 2 | 0 | 2023 | 2026 | 36 | community |
| node_exporter | 10 | 2 | 4 | 1 | 3 | 0 | 5 | 5 | 7 | 2 | 2017 | 2026 | 38 | core |
| clamav | 10 | 3 | 3 | 2 | 2 | 0 | 10 | 0 | 3 | 0 | 2017 | 2025 | 104 | community |
| tayga | 9 | 4 | 3 | 1 | 1 | 2 | 4 | 3 | 3 | 1 | 2016 | 2026 | 31 | first-party |
| OPNProxy | 9 | 5 | 1 | 2 | 1 | 1 | 3 | 5 | 5 | 0 | 2024 | 2026 | 28 | drop |
| nrpe | 9 | 3 | 3 | 1 | 2 | 2 | 3 | 4 | 6 | 1 | 2019 | 2026 | 32 | community |
| stunnel | 9 | 4 | 3 | 0 | 2 | 0 | 6 | 3 | 5 | 0 | 2020 | 2026 | 24 | community |
| lldpd | 9 | 2 | 6 | 0 | 1 | 0 | 5 | 4 | 5 | 0 | 2017 | 2026 | 41 | core |
| shadowsocks | 9 | 2 | 1 | 2 | 4 | 0 | 6 | 3 | 4 | 0 | 2018 | 2026 | 97 | community |
| isc-dhcp | 8 | 3 | 2 | 2 | 1 | 1 | 6 | 1 | 3 | 1 | 2016 | 2026 | 56 | n/a |
| sftp-backup | 8 | 5 | 1 | 1 | 1 | 0 | 5 | 2 | 2 | 0 | 2025 | 2026 | 43 | core |
| core-misfiled | 8 | 3 | 1 | 2 | 2 | 0 | 8 | 0 | 0 | 0 | 2018 | 2026 | 15 | n/a |
| redis | 7 | 4 | 1 | 1 | 1 | 0 | 4 | 3 | 3 | 0 | 2017 | 2026 | 30 | drop |
| tftp | 7 | 4 | 1 | 0 | 2 | 1 | 2 | 3 | 4 | 0 | 2021 | 2026 | 19 | first-party |
| qemu-guest-agent | 7 | 3 | 2 | 0 | 2 | 1 | 6 | 0 | 0 | 3 | 2019 | 2024 | 53 | core |
| xen | 7 | 5 | 1 | 1 | 0 | 0 | 5 | 2 | 2 | 1 | 2015 | 2024 | 25 | core |
| collectd | 7 | 1 | 5 | 0 | 1 | 0 | 7 | 0 | 1 | 0 | 2016 | 2021 | 40 | community |
| turnserver | 6 | 1 | 3 | 1 | 1 | 0 | 5 | 1 | 1 | 0 | 2025 | 2026 | 18 | community |
| framework | 6 | 1 | 3 | 0 | 2 | 0 | 6 | 0 | 0 | 0 | 2016 | 2026 | 15 | n/a |
| siproxd | 6 | 2 | 4 | 0 | 0 | 0 | 4 | 2 | 2 | 0 | 2017 | 2026 | 61 | community |
| arp-scan | 6 | 1 | 2 | 1 | 2 | 0 | 6 | 0 | 2 | 0 | 2017 | 2019 | 24 | core |
| theme-vicuna | 5 | 1 | 0 | 0 | 4 | 2 | 1 | 2 | 3 | 0 | 2020 | 2026 | 14 | drop |
| sunnyvalley | 5 | 0 | 1 | 3 | 1 | 1 | 2 | 2 | 3 | 0 | 2019 | 2026 | 17 | n/a |
| cloudflared | 4 | 3 | 1 | 0 | 0 | 1 | 3 | 0 | 0 | 0 | 2025 | 2026 | 12 | community |
| strongswan-legacy | 4 | 0 | 1 | 3 | 0 | 1 | 2 | 1 | 1 | 0 | 2024 | 2026 | 12 | n/a |
| apcupsd | 4 | 2 | 1 | 0 | 1 | 0 | 2 | 2 | 2 | 0 | 2022 | 2026 | 7 | community |
| dmidecode | 4 | 1 | 2 | 1 | 0 | 0 | 4 | 0 | 1 | 0 | 2018 | 2024 | 25 | core |
| ftp-proxy | 4 | 1 | 1 | 2 | 0 | 0 | 4 | 0 | 0 | 0 | 2016 | 2024 | 7 | drop |
| sslh | 4 | 0 | 1 | 0 | 3 | 0 | 1 | 3 | 3 | 0 | 2015 | 2024 | 22 | community |
| web-proxy-useracl | 4 | 2 | 0 | 2 | 0 | 0 | 4 | 0 | 2 | 0 | 2017 | 2019 | 24 | drop |
| web-proxy-sso | 4 | 1 | 2 | 0 | 1 | 0 | 3 | 1 | 1 | 0 | 2016 | 2018 | 36 | community |
| cpu-microcode | 3 | 0 | 2 | 0 | 1 | 0 | 3 | 0 | 1 | 0 | 2019 | 2025 | 12 | core |
| cache | 3 | 0 | 1 | 0 | 2 | 0 | 3 | 0 | 0 | 0 | 2017 | 2024 | 2 | drop |
| vmware | 3 | 0 | 1 | 2 | 0 | 0 | 2 | 1 | 2 | 0 | 2015 | 2023 | 18 | core |
| softether | 3 | 0 | 1 | 1 | 1 | 0 | 3 | 0 | 1 | 0 | 2018 | 2021 | 9 | drop |
| intrusion-detection-content-et-open | 2 | 1 | 0 | 0 | 1 | 0 | 2 | 0 | 0 | 0 | 2021 | 2026 | 21 | first-party |
| intrusion-detection-content-at-antiphishing | 2 | 0 | 0 | 0 | 2 | 1 | 1 | 0 | 0 | 0 | 2026 | 2026 | 6 | first-party |
| realtek-re | 2 | 0 | 0 | 1 | 1 | 1 | 0 | 1 | 1 | 1 | 2025 | 2026 | 3 | n/a |
| dec-hw | 2 | 1 | 0 | 0 | 1 | 0 | 2 | 0 | 0 | 0 | 2024 | 2026 | 2 | n/a |
| lcdproc-sdeclcd | 2 | 0 | 1 | 0 | 1 | 0 | 0 | 2 | 2 | 0 | 2022 | 2026 | 12 | community |
| theme-tukan | 2 | 0 | 0 | 0 | 2 | 0 | 1 | 1 | 2 | 0 | 2021 | 2025 | 9 | drop |
| intrusion-detection-content-et-pro | 2 | 1 | 0 | 0 | 1 | 0 | 1 | 1 | 1 | 0 | 2023 | 2023 | 3 | first-party |
| radsecproxy | 2 | 0 | 1 | 0 | 1 | 0 | 2 | 0 | 1 | 0 | 2020 | 2023 | 10 | community |
| mail-backup | 2 | 2 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 2019 | 2019 | 5 | core |
| l2tp | 2 | 0 | 2 | 0 | 0 | 0 | 2 | 0 | 1 | 0 | 2017 | 2019 | 21 | drop |
| debug | 2 | 0 | 2 | 0 | 0 | 0 | 2 | 0 | 1 | 0 | 2017 | 2018 | 5 | n/a |
| theme-flexcolor | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2026 | 2026 | 2 | drop |
| google-cloud-sdk | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2025 | 2025 | 1 | drop |
| puppet-agent | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2025 | 2025 | 3 | community |
| gdrive-backup | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 2025 | 2025 | 1 | core |
| theme-advanced | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2024 | 2024 | 10 | drop |
| maxit (3rd-party) | 1 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 2024 | 2024 | 1 | n/a |
| ndp-proxy-go | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 2023 | 2023 | 8 | core |
| intrusion-detection-content-snort-vrt | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 2022 | 2022 | 17 | first-party |
| fetchmail | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 2021 | 2021 | 4 | drop |
| apuled | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 2021 | 2021 | 2 | drop |
| helloworld | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 2016 | 2016 | 12 | n/a |
| virtualbox | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 2016 | 2016 | 30 | core |

The ten busiest plugins account for 1734 issues (54%). acme-client alone is 12% of the whole tracker; acme-client + frr + haproxy + nginx + ddclient/dyndns/rfc2136 (dynamic DNS) + caddy + wireguard + bind + freeradius are 55%.

## 2. Every currently open issue (165)

Grouped by plugin. Type is the derived type; "sensr disposition" is one of **adopt** (build it / fix it by design), **design avoids** (the sensr architecture makes the bug class impossible), **n/a on Linux / n/a**, **out of scope**, or **community module** (would live in a community-maintained module, not sensr proper). ISS-P-nnn references point to section 7.


### acme-client (18 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5899](https://github.com/opnsense/plugins/issues/5899) | os-acme-client: Add support for hosttech.ch DNS-01 challenge | feature | adopt: DNS-01 providers are data-driven; hosttech.ch joins the provider table |
| [#5852](https://github.com/opnsense/plugins/issues/5852) | security/acme-client: needsRenewal() ignores a renewed certificate that was never imported into the trust store | bug | adopt (ISS-P-001): renewal decision must look at the cert actually in the trust store, not the file acme.sh wrote |
| [#5835](https://github.com/opnsense/plugins/issues/5835) | security/acme-client: Add Redfish BMC deployment automation | feature | adopt: Redfish BMC deploy hook in the deploy-hook catalogue |
| [#5770](https://github.com/opnsense/plugins/issues/5770) | security/acme-client: missing accounts directory causes DNS-01 validation failure | bug | design avoids: account directories created transactionally before any challenge; no acme.sh shell plumbing |
| [#5746](https://github.com/opnsense/plugins/issues/5746) | security/acme-client: needsRenewal() only checks on-disk cert, never detects renewal that was not imported/deployed | bug | adopt (ISS-P-001): same root cause as #5852 |
| [#5730](https://github.com/opnsense/plugins/issues/5730) | security/os-acme-client: HTTP-01 "OPNsense Web Service" port forward is ineffective — rdr to 127.0.0.1 is dropped by the kernel, and the anchor is referenced with a /* wildcard | bug | design avoids (ISS-P-003): HTTP-01 answered by the sensr HTTP listener directly; no rdr to 127.0.0.1 and no wildcard anchor |
| [#5713](https://github.com/opnsense/plugins/issues/5713) | security/acme-client: DNS Sleep time reset to 0 | bug | adopt: form state must not silently reset numeric fields after failed runs |
| [#5667](https://github.com/opnsense/plugins/issues/5667) | security/acme-client: Support importing certificate signing requests generated elsewhere | feature | adopt: import external CSR into the cert store and let ACME sign it |
| [#5524](https://github.com/opnsense/plugins/issues/5524) | security/acme-client: no account/challenge for ACME with EAB | bug | adopt: EAB-only CAs (acme2certifier, Sectigo, HARICA) need "no challenge" mode |
| [#5497](https://github.com/opnsense/plugins/issues/5497) | ACME - Cert renewal fails after 180 to 360 days | bug | adopt (ISS-P-001): periodic renewal must never depend on account state going stale |
| [#5242](https://github.com/opnsense/plugins/issues/5242) | security/acme-client: Support for DNS-PERSIST-01 challenge | feature | adopt: DNS-PERSIST-01 challenge once the ACME library supports it |
| [#4665](https://github.com/opnsense/plugins/issues/4665) | security/acme-client: logging not initialised correctly on new installations | bug | design avoids (ISS-P-030): modules get structured journald logging by default, nothing to "initialise" |
| [#4415](https://github.com/opnsense/plugins/issues/4415) | security/acme-client: add NSUPDATE_SERVER_PORT configuration | feature | adopt: nsupdate server port field |
| [#4058](https://github.com/opnsense/plugins/issues/4058) | security/acme-client: add button to update SFTP/SSH host keys | feature | adopt: known_hosts refresh button for SFTP/SSH deploy targets |
| [#3997](https://github.com/opnsense/plugins/issues/3997) | ACME Client - Add a hint where to find the SSH certificate for ACME SSH/SFTP automations. | feature | adopt: show the SSH public key used by deploy automations inline |
| [#3799](https://github.com/opnsense/plugins/issues/3799) | security/acme-client: DNS-01 nsupdate: Help for secret key should mention format | feature | adopt: help text / validation for TSIG key format |
| [#3407](https://github.com/opnsense/plugins/issues/3407) | security/acme-client SFTP Upload of wildcard Certs | bug | adopt: wildcard cert file naming in SFTP deploy |
| [#3023](https://github.com/opnsense/plugins/issues/3023) | security/acme-client: Feature Request - IPv6 Option for CG-NAT-Firewalls | feature | adopt: IPv6-only HTTP-01 / "listen on v6" for CG-NAT users (#1967 related) |

### bind (8 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5931](https://github.com/opnsense/plugins/issues/5931) | os-bind: Apply silently loses newly added static records on dynamic zones (allowrndcupdate) | bug | design avoids (ISS-P-019): static records in dynamic zones are pushed via RFC2136/rndc, zone files never regenerated under a running named |
| [#5916](https://github.com/opnsense/plugins/issues/5916) | os-bind: BIND is restarted on every interface link-up, including interfaces it does not listen on | bug | design avoids (ISS-P-020): services subscribe only to events for interfaces they listen on |
| [#5816](https://github.com/opnsense/plugins/issues/5816) | os-bind: deleting a record does not update the zone serial | bug | adopt (ISS-P-019): serial bump on every zone mutation, including deletes |
| [#5720](https://github.com/opnsense/plugins/issues/5720) | DNS/bind os-bind, allow to use a self-provided dnsbl file | feature | adopt: user-supplied RPZ/DNSBL file sources |
| [#5701](https://github.com/opnsense/plugins/issues/5701) | BIND : Add an option to bind to set max-ncache-ttl | feature | adopt: max-ncache-ttl option |
| [#5626](https://github.com/opnsense/plugins/issues/5626) | os-bind: Validate configuration before saving and display errors | feature | design avoids: every module runs `named-checkconf`-style validation before commit and surfaces errors in the form |
| [#5549](https://github.com/opnsense/plugins/issues/5549) | dns/bind: add validate-except config option for split dns on forward zones | feature | adopt: validate-except for forward zones (split DNS) |
| [#4225](https://github.com/opnsense/plugins/issues/4225) | Feature Request: : Add allow-update-forwarding option for DDNS Updates with TSIG Key in BIND Web UI in os-bind | feature | adopt: allow-update-forwarding on secondary zones |

### caddy (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5896](https://github.com/opnsense/plugins/issues/5896) | [os-caddy] Feature Request: Add manual drag-and-drop reordering to GUI tables | feature | adopt: drag-and-drop ordering is a core grid capability |
| [#5729](https://github.com/opnsense/plugins/issues/5729) | www/caddy: Change basic_auth hashing to argon2id | feature | adopt: argon2id for basic_auth hashes |

### cloudflared (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5818](https://github.com/opnsense/plugins/issues/5818) | net/cloudflared: token/edge IP validation issues, logs not reaching syslog, no tunnel status | bug | adopt: token validation, syslog integration and tunnel status for the Cloudflare tunnel module (community module) |

### core-misfiled/other (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5875](https://github.com/opnsense/plugins/issues/5875) | EDGE 610 BIOS | other | n/a: BIOS request for Deciso hardware |

### crowdsec (5 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5848](https://github.com/opnsense/plugins/issues/5848) | security/crowdsec: blocklist aliases are silently not created when another (unrelated) alias fails model validation | bug | design avoids: alias model validation is per-object; one invalid alias cannot block creation of another |
| [#5753](https://github.com/opnsense/plugins/issues/5753) | security/crowdsec: UI support for remote LAPI in remediation component | feature | adopt: remote LAPI mode for the bouncer |
| [#5587](https://github.com/opnsense/plugins/issues/5587) | [os-crowdsec] Crowdsec does not start with multi-server setup (26.7) | bug | adopt: LAPI listen on 0.0.0.0 must keep a working local client URL |
| [#5483](https://github.com/opnsense/plugins/issues/5483) | os-crowdsec (1.10.12): opnsense-gui-logs and sshd-logs parsers do not match OPNsense 26.1.9 audit log format | bug | adopt: ship and test parsers for sensr's own audit log format |
| [#4262](https://github.com/opnsense/plugins/issues/4262) | Reboot held up by Crowdsec refusing to stop | bug | design avoids (ISS-P-018): systemd TimeoutStopSec bounded for every module; a service can never hold a reboot |

### ddclient (10 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5879](https://github.com/opnsense/plugins/issues/5879) | dns/ddclient dashboard widget false positives | bug | adopt: widget status derives from the last update result, not from "service running" |
| [#5863](https://github.com/opnsense/plugins/issues/5863) | dns/ddclient: DuckDNS token is written to syslog in clear text when the update request fails (native backend) | bug | adopt: redact credentials from HTTP error logs (generic secret-redaction helper) |
| [#5805](https://github.com/opnsense/plugins/issues/5805) | os-ddclient: support certificate-based AWS Route 53 authentication | feature | adopt: Route53 via IAM role / certificate-based auth |
| [#5718](https://github.com/opnsense/plugins/issues/5718) | os-ddclient: native backend skips update after CARP failback when the node gets its previous IP back | bug | adopt (ISS-P-005): CARP failback resets the DDNS cache; compare against provider state, not local cache |
| [#5608](https://github.com/opnsense/plugins/issues/5608) | dns/ddclient: add native bunny.net Dynamic DNS provider | feature | adopt: bunny.net provider |
| [#5578](https://github.com/opnsense/plugins/issues/5578) | os-ddclient submits wrong interface IP when using Porkbun provider, GUI missing IP and update time | bug | adopt (ISS-P-005): per-entry interface selection in multi-WAN and status display |
| [#5501](https://github.com/opnsense/plugins/issues/5501) | os-ddclient generates empty ddclient.conf although account exists in config.xml/json | bug | design avoids: single native engine; no second ddclient.conf renderer to drift |
| [#5499](https://github.com/opnsense/plugins/issues/5499) | os-ddclient generates empty ddclient.conf although account exists in config.xml/json | bug | design avoids: same as #5501 |
| [#5488](https://github.com/opnsense/plugins/issues/5488) | dns/ddclient: add button for manual push and live log to debug | feature | adopt: "update now" button and live log |
| [#5478](https://github.com/opnsense/plugins/issues/5478) | DDClient - IF DHCP IP as a DDNS-IP | feature | adopt: "use interface address as-is" option |

### dnscrypt-proxy (3 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5581](https://github.com/opnsense/plugins/issues/5581) | DNSCrypt-Proxy keeps stopping every day | bug | adopt: systemd Restart=on-failure + watchdog for all modules |
| [#5486](https://github.com/opnsense/plugins/issues/5486) | dns/dnscrypt-proxy: listen_addresses CSVListField does not support IPv6 bracket notation, preventing [::]:53 from being saved correctly | bug | adopt: IPv6 bracket notation in listen fields (shared validator) |
| [#5162](https://github.com/opnsense/plugins/issues/5162) | os-dnscrypt-proxy: bootstrap_resolvers template incorrectly formats multiple comma-separated resolvers | bug | adopt: list fields render as TOML arrays (typed templating, ISS-P-026) |

### firewall-api (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5926](https://github.com/opnsense/plugins/issues/5926) | security/policyanalyzer: new plugin, read-only firewall policy analysis with optional local AI | feature | adopt later: read-only policy analysis (shadowed/unused rules) as a core firewall report; no AI dependency |
| [#5922](https://github.com/opnsense/plugins/issues/5922) | misc/sonar: new plugin, dashboard widget that visualises the live firewall log | feature | adopt: live firewall log visualisation widget in core |

### freeradius (5 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5919](https://github.com/opnsense/plugins/issues/5919) | net/freeradius: VLAN fallback no longer accepts unknown MACs from UniFi access points since 1.10.3 | bug | adopt: MAB fallback must accept unknown MACs when configured; regression test |
| [#5914](https://github.com/opnsense/plugins/issues/5914) | net/freeradius: Saving MAB fallback settings in GUI omits Auth-Type := Accept in users file | bug | adopt: Auth-Type := Accept rendered for MAB fallback users |
| [#5864](https://github.com/opnsense/plugins/issues/5864) | net/freeradius: configurable outer EAP method restrictions | feature | adopt: configurable outer EAP method restrictions |
| [#5696](https://github.com/opnsense/plugins/issues/5696) | freeradius: shared secrets and the SQL password are rendered without safe quoting, and proxy.conf leaves the secret unquoted entirely | bug | design avoids (ISS-P-026): all secrets quoted/escaped by the typed config renderer |
| [#5678](https://github.com/opnsense/plugins/issues/5678) | net/freeradius: Some Cleartext-Password values containing % fail PAP authentication | bug | design avoids (ISS-P-026): `%` escaping in users file |

### frr (7 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5918](https://github.com/opnsense/plugins/issues/5918) | os-frr: BGP neighbor "update-source" is ignored for IPv6 neighbors | bug | adopt: update-source honoured for IPv6 neighbours |
| [#5897](https://github.com/opnsense/plugins/issues/5897) | os-frr: Static routes not applied after reboot | bug | adopt (ISS-P-008): staticd owns static routes; boot ordering verified |
| [#5652](https://github.com/opnsense/plugins/issues/5652) | os-frr: OSPF MD5 fails after FRR 10.6.1 with ExtremeXOS — upstream fix is FRR #22744 | bug | design avoids (ISS-P-028): routing daemon version pinned per release, upstream fixes cherry-picked via NixOS overlay |
| [#5624](https://github.com/opnsense/plugins/issues/5624) | os-frr : OSPF routes reported as installed in the Zebra RIB (O>*) but missing from the kernel FIB after a reboot; temporarily fixed by restarting the frr daemon. | bug | adopt (ISS-P-008): FIB/RIB consistency check after boot; zebra restarts only itself |
| [#5607](https://github.com/opnsense/plugins/issues/5607) | FRR redistribute bgp route-map xxx at RIP | feature | adopt: route-map on RIP redistribute |
| [#5515](https://github.com/opnsense/plugins/issues/5515) | OPNsense bug report — FRR 10.6.1 BGP regression | bug | design avoids (ISS-P-028): pinned FRR, regression suite for eBGP peering |
| [#5496](https://github.com/opnsense/plugins/issues/5496) | net/frr: carp demote does not chnage the metric of a default route | bug | adopt (ISS-P-009): CARP demotion drives routing metrics (route-map weight on backup node) |

### git-backup (6 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5833](https://github.com/opnsense/plugins/issues/5833) | os-git-backup: optional encryption of the pushed configuration | feature | adopt (ISS-P-021): encryption option for every backup target |
| [#5629](https://github.com/opnsense/plugins/issues/5629) | os-git-backup: SCP-style SSH URLs corrupted by credential injection | bug | design avoids: SSH URLs handled by a URL parser, credentials via helper/askpass, never string-injected |
| [#5606](https://github.com/opnsense/plugins/issues/5606) | Git backup plugin has multiple issues when configured for GitHub over SSH. | bug | adopt (ISS-P-021): SSH known_hosts handling, key auth, GitHub-specific tests |
| [#5605](https://github.com/opnsense/plugins/issues/5605) | Git backup always pushes local master branch and cannot synchronize multiple OPNsense nodes to the same repository | bug | adopt (ISS-P-021): per-node branch/path so multiple nodes can share a repo |
| [#5500](https://github.com/opnsense/plugins/issues/5500) | os-git-backup: add a way to avoid some conf changes that don't need backup | feature | adopt: ignore-list of volatile config paths (e.g. lease timestamps) for backup triggers |
| [#5480](https://github.com/opnsense/plugins/issues/5480) | git-backup crash | bug | adopt: backup failures are surfaced as alerts, not crashes |

### haproxy (11 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5709](https://github.com/opnsense/plugins/issues/5709) | net/haproxy: Rules were reordered after adding a certificate | bug | adopt (ISS-P-012): rules have explicit stable ordering independent of other objects |
| [#5690](https://github.com/opnsense/plugins/issues/5690) | net/haproxy: Template generation fails when model serializes list fields as dict instead of string | bug | design avoids (ISS-P-026): typed model -> typed template; no stringly list fields |
| [#5649](https://github.com/opnsense/plugins/issues/5649) | net/haproxy: Bulk Change Server Statet Buttons do not get rendered anymore | bug | adopt: bulk server state controls as a tested UI feature |
| [#5576](https://github.com/opnsense/plugins/issues/5576) | net/haproxy: boot path skips volatile runtime export; HAProxy starts manually after reboot | bug | adopt (ISS-P-010): boot path and apply path share one code path (runtime export included) |
| [#5505](https://github.com/opnsense/plugins/issues/5505) | net/haproxy: scrollbars missing in drop down menues | bug | adopt: core select widget fixes dropdown scrolling |
| [#5376](https://github.com/opnsense/plugins/issues/5376) | net/haproxy: Add timeout tunnel field to backend pool configuration | feature | adopt: timeout tunnel per backend |
| [#5150](https://github.com/opnsense/plugins/issues/5150) | net/haproxy: replace legacy mailer with Lua mailers | other | adopt: Lua mailers (legacy mailers removed in HAProxy 3.3) |
| [#4923](https://github.com/opnsense/plugins/issues/4923) | net/haproxy: integration with crowdsec plugin | feature | adopt (ISS-P-018): CrowdSec SPOA bouncer for HAProxy |
| [#4159](https://github.com/opnsense/plugins/issues/4159) | net/haproxy: Allow to have no DNS servers defined in SYSTEM: SETTINGS: GENERAL -> Networking | feature | adopt: no hard dependency on system DNS servers for the resolver section |
| [#2853](https://github.com/opnsense/plugins/issues/2853) | net/haproxy: Backend Server unable to use IPV6 Address. Syntax Checking fails. | bug | adopt: IPv6 backend addresses validated with brackets |
| [#2584](https://github.com/opnsense/plugins/issues/2584) | net/haproxy: Rules: allow more complex evaluation of conditions | feature | adopt (ISS-P-012): condition expressions with AND/OR/NOT groups |

### igmp-proxy (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5760](https://github.com/opnsense/plugins/issues/5760) | os-igmp-proxy: make quickleave optional (currently hardcoded, causes periodic IPTV dropouts) | bug | adopt: quickleave toggle (igmpproxy) |
| [#5755](https://github.com/opnsense/plugins/issues/5755) | net/igmp-proxy: expose per-interface multicast whitelist in the GUI | feature | adopt: per-interface multicast whitelist |

### intrusion-detection-content (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5794](https://github.com/opnsense/plugins/issues/5794) | [New Plugin] security/dynamic-homenet - keep Suricata HOME_NET in sync with the delegated IPv6 prefix and WAN address | feature | adopt: HOME_NET tracks delegated prefix/WAN address automatically in core IDS |

### intrusion-detection-content-at-antiphishing (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5675](https://github.com/opnsense/plugins/issues/5675) | os-intrusion-detection-content-at-antiphishing: support external Suricata dataset files | bug | adopt: rule sources can ship dataset files |

### isc-dhcp (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5824](https://github.com/opnsense/plugins/issues/5824) | net/isc-dhcp: prefixes.php re-adds released DHCPv6-PD routes from historical active lease records | bug | adopt: PD routes derived from active leases only (Kea lease hooks) |

### maltrail (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5490](https://github.com/opnsense/plugins/issues/5490) | os-maltrail: FAIL2BAN_REGEX editable by UI | feature | out of scope: maltrail dropped |
| [#5489](https://github.com/opnsense/plugins/issues/5489) | os-maltrail: CHECK_HOST_DOMAINS appears twice | bug | out of scope: maltrail dropped |

### mdns-repeater (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5904](https://github.com/opnsense/plugins/issues/5904) | New os-mdns-bridge plugin - Create a new plugin to implement the mDNS-Bridge by Denny Page | feature | adopt (ISS-P-029): Avahi/mdns-bridge style reflector with IPv6 and filtering |

### monit (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5634](https://github.com/opnsense/plugins/issues/5634) | Monit Syntax error with Polling Time Integer value | bug | adopt: integer polling interval validation (core health monitor) |

### net-snmp (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5479](https://github.com/opnsense/plugins/issues/5479) | Config sync transfers the listen IP of net-snmp yield into not running service on the backup node | bug | adopt (ISS-P-025): HA sync with per-node overrides for listen addresses |

### netbird (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5551](https://github.com/opnsense/plugins/issues/5551) | Netbird: Unbound does not restart | bug | adopt: overlay interfaces publish link-up events so Unbound rebinds |

### new-plugin-request (11 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5928](https://github.com/opnsense/plugins/issues/5928) | New plugin: net-mgmt/checkmk-agent (Checkmk monitoring agent) | feature | community module: checkmk agent |
| [#5880](https://github.com/opnsense/plugins/issues/5880) | Proposing security/tang plugin | feature | community module: tang (NBDE) server |
| [#5872](https://github.com/opnsense/plugins/issues/5872) | Plugin proposal: S3-compatible configuration backups with native encryption | feature | adopt (ISS-P-021): S3 backend with client-side encryption in the backup-targets engine |
| [#5836](https://github.com/opnsense/plugins/issues/5836) | Official Xray-core / sing-box Integration for Censorship-Resistant Remote Access (Server & Client) | feature | community module: xray/sing-box |
| [#5828](https://github.com/opnsense/plugins/issues/5828) | New plugin proposal: os-ont, status page and widget for the optical network terminal | feature | community module: ONT status widget |
| [#5804](https://github.com/opnsense/plugins/issues/5804) | www/gatus: proposal for a Gatus plugin | feature | community module: Gatus |
| [#5802](https://github.com/opnsense/plugins/issues/5802) | net/newt: proposal for Pangolin Newt connector integration | feature | community module: Pangolin Newt |
| [#5658](https://github.com/opnsense/plugins/issues/5658) | Create OPNsense plugin to export to Splunk using HTTP Event Collector | feature | adopt: Splunk HEC as a core log-shipping target (alongside syslog/Loki) |
| [#5642](https://github.com/opnsense/plugins/issues/5642) | [os-wanquota] Dual-WAN billing-cycle quota and consumer reporting | feature | adopt: WAN quota/billing-cycle accounting in core traffic reporting |
| [#5615](https://github.com/opnsense/plugins/issues/5615) | [os-usque] New plugin request: native Cloudflare WARP/MASQUE tunnel integration | feature | community module: Cloudflare WARP/MASQUE client |
| [#5556](https://github.com/opnsense/plugins/issues/5556) | [New Plugin] sysutil/vep1400-hw - add rc.syshook scripts, a GUI page and backend code to support Dell EMC VEP1400 platforms | feature | community module: Dell VEP1400 hardware support (NixOS hardware profile) |

### nextcloud-backup (3 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5744](https://github.com/opnsense/plugins/issues/5744) | [os-nextcloud-backup] Add API endpoint for remote backup status / last successful upload | feature | adopt (ISS-P-021): backup-target status API |
| [#5574](https://github.com/opnsense/plugins/issues/5574) | NextCloud Backup plugin throws exception on save/setup/apply | bug | adopt: path validation with clear error instead of exception |
| [#5181](https://github.com/opnsense/plugins/issues/5181) | os-nextcloud-backup 1.1 changes modus operandi and causes problems for existing backup schemes | feature | adopt (ISS-P-021): retention and naming behaviour must be configurable and migration-safe |

### nginx (12 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5845](https://github.com/opnsense/plugins/issues/5845) | os-nginx: possibility to dis-/enable brotli within the template per server | feature | community module (nginx): per-server brotli toggle |
| [#5826](https://github.com/opnsense/plugins/issues/5826) | www/nginx: per-server option to reject requests whose Host differs from the TLS SNI (421) | feature | community module (nginx): Host/SNI mismatch 421; core Caddy module gets it via strict_sni_host |
| [#5821](https://github.com/opnsense/plugins/issues/5821) | www/nginx: add trusted source networks for User-Agent bot protection | feature | community module (nginx): trusted networks for bot protection |
| [#5782](https://github.com/opnsense/plugins/issues/5782) | os-nginx: Expand Trusted Proxies network aliases when generating nginx configuration | bug | design avoids: alias expansion resolves nested URL-table aliases everywhere (core alias resolver) |
| [#5684](https://github.com/opnsense/plugins/issues/5684) | www/nginx: make upstream client-address headers configurable and sanitizable | feature | adopt in Caddy/HAProxy modules: configurable client-address headers |
| [#5662](https://github.com/opnsense/plugins/issues/5662) | [os-nginx] Add native Layer-7 enforcement of the autoblock/banned IP list behind trusted reverse proxies/CDNs | feature | adopt in Caddy module: ban list enforced at L7 behind trusted proxies |
| [#5656](https://github.com/opnsense/plugins/issues/5656) | [os-nginx] NAXSI blocked requests return HTTP 200 instead of 403 | bug | community module (nginx)/NAXSI; sensr WAF via Coraza returns proper 403 |
| [#5650](https://github.com/opnsense/plugins/issues/5650) | [os-nginx] orphaned sni_hostname_upstream_map_item / ip_acl_item entries on edit, blocking upstream deletion | bug | design avoids: child objects are owned by parent; edits cannot orphan rows |
| [#5596](https://github.com/opnsense/plugins/issues/5596) | [os-nginx] Add hostnames; to SNI Upstream Maps and proxy_protocol on; to Stream Servers | feature | adopt in Caddy layer4: hostnames in SNI maps, proxy_protocol |
| [#5534](https://github.com/opnsense/plugins/issues/5534) | www/nginx site access log rotation | feature | design avoids (ISS-P-030): journald + size-bounded log files for all modules |
| [#5532](https://github.com/opnsense/plugins/issues/5532) | os-nginx: Keepalive=0 is not rendered, but nginx >=1.29.7 enables upstream keepalive by default | bug | adopt: render explicit defaults when upstream changes defaults (pin + test) |
| [#4577](https://github.com/opnsense/plugins/issues/4577) | www/nginx add a default value > 0 to ban_ttl to prevent UI slow down over time | feature | design avoids (ISS-P-013): ban state in a runtime store with TTL, never in config.xml |

### nrpe (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5681](https://github.com/opnsense/plugins/issues/5681) | os-nrpe adding new Commands will only be available after disable and re-enable NRPE | bug | adopt: adding a command triggers reload |
| [#5059](https://github.com/opnsense/plugins/issues/5059) | Nagios check_procs plugin is failing using NRPE or check_by_ssh | bug | n/a on Linux: FreeBSD procfs change; monitoring-plugins on Linux unaffected |

### ntopng (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5898](https://github.com/opnsense/plugins/issues/5898) | os-ntopng: ntopng 7.0.d20260922 floods InfluxDB 1.8 with DROP/CREATE CONTINUOUS QUERY (~150/s), ~16 MB/s disk writes | bug | community module (ntopng) — upstream regression |
| [#5582](https://github.com/opnsense/plugins/issues/5582) | [os-ntopng] Sustained disk writes observed with local RRD timeseries on ZFS | bug | community module (ntopng); core time series are write-coalesced |

### openvpn-legacy (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5889](https://github.com/opnsense/plugins/issues/5889) | security/openvpn-legacy: non-admin page user can execute OpenVPN directives | bug | design avoids: enum-validated protocol field; privilege model prevents directive injection (also n/a: legacy pages) |

### OPNProxy (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5710](https://github.com/opnsense/plugins/issues/5710) | os-opnproxy 1.0.5_5 | bug | adopt: service actions must be declared per-service (reload vs restart) and validated at build time, never shelled to a missing rc verb |

### postfix (4 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5907](https://github.com/opnsense/plugins/issues/5907) | mail/postfix: add options to disable VRFY and restrict ETRN | feature | community module (postfix): disable VRFY / restrict ETRN |
| [#5570](https://github.com/opnsense/plugins/issues/5570) | service postfix restart can't handle postmap executable | bug | community module (postfix): PATH in service unit |
| [#5535](https://github.com/opnsense/plugins/issues/5535) | [os-postfix] Make smtpd_recipient_restrictions order configurable to protect trusted internal mail flow | feature | community module (postfix): restriction order |
| [#5493](https://github.com/opnsense/plugins/issues/5493) | Postfix - outdated configuration | bug | community module (postfix): drop deprecated params |

### q-feeds-connector (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5923](https://github.com/opnsense/plugins/issues/5923) | q-feeds-connector: "error in configd communication" every update when the Unbound DNSBL rebuild takes longer than 120s | bug | design avoids: long rebuilds run as jobs, API calls never block on configd-style 120 s socket timeouts |
| [#5474](https://github.com/opnsense/plugins/issues/5474) | [os-qfeeds-connector] - Events nothing shown | bug | community module (vendor connector) |

### qemu-guest-agent (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#4148](https://github.com/opnsense/plugins/issues/4148) | emulators/qemu-guest-agent: qemu-ga will not launch thaw operation | bug | adopt: fsfreeze hooks supported in the guest-agent toggle (Linux qemu-ga supports them) |

### realtek-re (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5495](https://github.com/opnsense/plugins/issues/5495) | os-realtek-re: if_re.ko unconditionally enables flow control (pause) on RTL8125, ignores ifconfig mediaopt | bug | n/a on Linux: FreeBSD vendor driver |

### smart (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5756](https://github.com/opnsense/plugins/issues/5756) | sysutils/smart: Graph below Reporting/Health | feature | adopt: SMART attribute graphs in core health reporting |

### squid (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5868](https://github.com/opnsense/plugins/issues/5868) | www/squid: remote ACL downloads are not length-checked, so a short HTTP body silently installs a truncated blocklist | bug | adopt: remote list downloads are length-checked and atomically swapped (core URL-table fetcher shares this) |
| [#5811](https://github.com/opnsense/plugins/issues/5811) | Squid is not applying changes made through the web interface | bug | community module (squid): reload must run `squid -k reconfigure` |

### strongswan-legacy (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5610](https://github.com/opnsense/plugins/issues/5610) | IPSEC OSPF opnsense 26.7 | other | adopt: OSPF over IPsec (VTI) documented and tested in core routing |

### sunnyvalley (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5471](https://github.com/opnsense/plugins/issues/5471) | [Plugin Proposal] os-automatisierung — Multi-instance OPNsense automation, backup & Zenarmor management | feature | out of scope: multi-instance fleet management is a separate product; sensr exposes a complete API for it |

### tailscale (8 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5903](https://github.com/opnsense/plugins/issues/5903) | os-tailscale: pre-auth key is not used when tailscaled.state is missing or holds a stale profile | bug | adopt (ISS-P-017): pre-auth key applied whenever state is absent or stale |
| [#5878](https://github.com/opnsense/plugins/issues/5878) | [os-tailscale] "Disable SNAT" opts into the kernel PF path but neither disables SNAT nor registers the anchor it requires | bug | adopt (ISS-P-017): SNAT/netfilter mode is a real firewall object, not a flag |
| [#5857](https://github.com/opnsense/plugins/issues/5857) | security/tailscale: add description to restart service | feature | adopt: service action descriptions |
| [#5711](https://github.com/opnsense/plugins/issues/5711) | [os-tailscale] WebUI Support for Tailscale Peer Relay Server functionality | feature | adopt: peer relay settings |
| [#5631](https://github.com/opnsense/plugins/issues/5631) | [os-tailscale] Settings are applied with the frozen `tailscale up`, silently resetting every preference the plugin does not manage | bug | adopt (ISS-P-017): drive tailscaled through its API/`tailscale set`, never `tailscale up --reset`-style clobbering |
| [#5613](https://github.com/opnsense/plugins/issues/5613) | Tailscale clients behind NAT lose control-plane connectivity every few hours after 26.7 upgrade (map long-poll timeout, UDP blocked; recovers only on daemon restart) | other | adopt: watchdog restarts on control-plane loss; investigate UDP state handling |
| [#5593](https://github.com/opnsense/plugins/issues/5593) | os-tailscale: ICMP traffic bypasses firewall rules on tailscale0 interface | bug | adopt (ISS-P-017): overlay interfaces are ordinary firewall interfaces; ICMP cannot bypass rules |
| [#5122](https://github.com/opnsense/plugins/issues/5122) | Tailscale - add peer relay function | feature | adopt: peer relay toggle + port |

### tayga (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5594](https://github.com/opnsense/plugins/issues/5594) | os-tayga: IPv6 Interface Address field breaks when CIDR suffix entered (double /128 appended) | bug | adopt: CIDR validation in address field (shared validator) |
| [#5503](https://github.com/opnsense/plugins/issues/5503) | os-tayga: no configuration synchronization | bug | adopt (ISS-P-025): module-level HA sync opt-in |

### telegraf (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5577](https://github.com/opnsense/plugins/issues/5577) | os-telegraf: PF input fails when Telegraf runs as telegraf user on OPNsense 26.7.1 (works immediately as root) | bug | adopt: least-privilege metrics access (nftables counters readable by the telegraf user via sensr metrics socket) |

### tftp (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5510](https://github.com/opnsense/plugins/issues/5510) | [os-tftp] Serve directory is incorrect or symlink to /tftpboot is broken out of the box | bug | adopt: tftp root directory must work out of the box |

### theme-cicada (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5564](https://github.com/opnsense/plugins/issues/5564) | 26.7 cicada plugin legibility of services panel on dashboard | bug | design avoids (ISS-P-027): design tokens with contrast checks; no theme plugins |

### theme-vicuna (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5600](https://github.com/opnsense/plugins/issues/5600) | vicuna plugin - services panel in dashboard is washed out and hard to read | bug | design avoids (ISS-P-027) |
| [#5572](https://github.com/opnsense/plugins/issues/5572) | 26.7.1 vicuna plugin legibility of services panel in dashboard | bug | design avoids (ISS-P-027) |

### themes (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5921](https://github.com/opnsense/plugins/issues/5921) | misc/theme-forja: new theme (dark brushed steel, CSS only) | feature | design avoids (ISS-P-027): user themes are token overrides, not plugins |
| [#5912](https://github.com/opnsense/plugins/issues/5912) | misc/theme-magikh0e: new theme (dark terminal look) | feature | design avoids (ISS-P-027) |

### tor (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5722](https://github.com/opnsense/plugins/issues/5722) | security/tor: Advanced mode / help toggles are broken | bug | community module (tor): advanced/help toggles are core form features |
| [#5703](https://github.com/opnsense/plugins/issues/5703) | [os-tor] Unable to start after upgrading to 26.7.x | bug | community module (tor): upstream crash after 26.7 |

### upnp (3 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5769](https://github.com/opnsense/plugins/issues/5769) | UPNP Not working without static port or EIM | bug | adopt: UPnP works with the default NAT mode (static-port not required) |
| [#5691](https://github.com/opnsense/plugins/issues/5691) | net/natpmp-client: NAT-PMP client plugin for provider assigned inbound ports | feature | adopt: NAT-PMP client for provider-assigned inbound ports (VPN providers) |
| [#5674](https://github.com/opnsense/plugins/issues/5674) | [os-upnp] Migrate legacy static PHP pages to MVC/API framework | other | design avoids: everything is MVC/API from day one |

### vnstat (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5699](https://github.com/opnsense/plugins/issues/5699) | net/vnstat: use OPNsense interface names in dashboard widget | bug | design avoids: core reporting uses logical interface names everywhere |

### wazuh-agent (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5900](https://github.com/opnsense/plugins/issues/5900) | os-wazuh-agent: active response fails to extract source IP from non-standard decoders (Caddy JSON, custom JSON) — silent no-op | bug | community module (wazuh): decoder-aware IP extraction |
| [#5849](https://github.com/opnsense/plugins/issues/5849) | security/wazuh-agent: active response silently fails when /var/ossec/logs/active-responses.log becomes a symlink loop | bug | community module (wazuh): safe log writes |

### wireguard (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#3094](https://github.com/opnsense/plugins/issues/3094) | Request: Netmaker Plugin | feature | adopt (ISS-P-024): Netmaker/Headscale/Netbird self-hosted overlay family as first-party modules |

### wol (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5467](https://github.com/opnsense/plugins/issues/5467) | Wake on LAN: Support IPv6-only interfaces | feature | adopt: WOL on IPv6-only interfaces |

### zabbix-agent (2 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5665](https://github.com/opnsense/plugins/issues/5665) | [os-zabbix] Zabbix 8.0 has been released | feature | design avoids (ISS-P-028): version variants pinned via NixOS; agent2 by default |
| [#4284](https://github.com/opnsense/plugins/issues/4284) | net-mgmt/zabbix-agent: Can't make use of HA in Zabbix agent | feature | adopt: multiple ServerActive entries (agent HA) |

### zabbix-proxy (1 open)

| # | Title | Type | sensr disposition |
|---|---|---|---|
| [#5620](https://github.com/opnsense/plugins/issues/5620) | net-mgmt/zabbix-proxy: add support for SSHKeyLocation option | feature | adopt: SSHKeyLocation option |

## 3. Declined and never-done items (726)

Union of (a) every feature-type issue closed `not_planned` (181) and (b) every `help wanted` issue closed without completion (709). Grouped by plugin, sorted by engagement within each group. Format: issue — type (year, engagement) — title — **disposition**.


### acme-client (44)

- [#3897](https://github.com/opnsense/plugins/issues/3897) — support (2024, e=23) — os-acme-client \| Cloudflare - domain validation failed (dns01) — **adopt (ISS-P-002)**
- [#4908](https://github.com/opnsense/plugins/issues/4908) — support (2025, e=13) — security/os-acme-client: Reducing the renewal interval results in auto renewal dns01 validation failed errors — **adopt (ISS-P-001): renewal interval semantics**
- [#1967](https://github.com/opnsense/plugins/issues/1967) — bug (2020, e=13) — security/acme-client: HTTP verification method fails with domain names resolving to IPv6 addresses — **adopt (ISS-P-003): HTTP-01 on IPv6**
- [#5445](https://github.com/opnsense/plugins/issues/5445) — support (2026, e=11) — ACME Client: Automations - Sync SSL certificate changes into running HAProxy not doing anything? — **adopt (ISS-P-011)**
- [#5086](https://github.com/opnsense/plugins/issues/5086) — support (2025, e=11) — Every year I have to reset my ACME client to make cert renewal work again — **adopt (ISS-P-001)**
- [#3590](https://github.com/opnsense/plugins/issues/3590) — feature (2023, e=10) — security/acme-client: ACME broken for INWX with Let’s Encrypt — **adopt (ISS-P-002): INWX**
- [#3479](https://github.com/opnsense/plugins/issues/3479) — feature (2023, e=10) — security/acme-client: Allow for short lived ACME certificates — **adopt: short-lived certs/ACME profiles (partly shipped: profiles)**
- [#5007](https://github.com/opnsense/plugins/issues/5007) — support (2025, e=9) — security/acme-client: OCSP must-staple checkbox has no effect — **design: OCSP must-staple is dead; drop the option**
- [#4203](https://github.com/opnsense/plugins/issues/4203) — other (2024, e=9) — acme-client: haproxy still serves old cert after renewal — **adopt (ISS-P-011): HAProxy hot-reloads certs via event bus**
- [#3073](https://github.com/opnsense/plugins/issues/3073) — bug (2022, e=8) — DNS-01 - All-Inkl Domain API - OUTDATED — **adopt (ISS-P-002): providers versioned with the ACME lib, not acme.sh snapshots**
- [#4711](https://github.com/opnsense/plugins/issues/4711) — support (2025, e=6) — security/acme-client: Certificate “Renewal Interval” setting ignored (always uses --days 1, automatic renewals never run) — **adopt (ISS-P-001)**
- [#4377](https://github.com/opnsense/plugins/issues/4377) — feature (2024, e=6) — security/acme-client feature request: add HPE ILO automation — **adopt: HPE iLO deploy hook**
- [#3845](https://github.com/opnsense/plugins/issues/3845) — support (2024, e=6) — security/acme-client: can't obtain production certificate using DNS challenge through Gandi DNS provider — **adopt (ISS-P-002)**
- [#2917](https://github.com/opnsense/plugins/issues/2917) — feature (2022, e=6) — security/acme-client: add support for generic post-cert-issue hooks — **adopt: generic post-issue hook (script/webhook)**
- [#5228](https://github.com/opnsense/plugins/issues/5228) — bug (2026, e=5) — security/acme-client: unable to get ipv6 certificate — **adopt (ISS-P-003)**
- [#5177](https://github.com/opnsense/plugins/issues/5177) — other (2026, e=5) — os-acme-client: reverting system config — **design avoids: a module never rewrites system config behind the user's back**
- [#4963](https://github.com/opnsense/plugins/issues/4963) — support (2025, e=5) — security/os-acme-client: HTTP-01 does not work without adding some lighttpd config — **design avoids (ISS-P-003)**
- [#4217](https://github.com/opnsense/plugins/issues/4217) — support (2024, e=5) — Let's Encrypt plugin: ACME Log Always Empty — **design avoids (ISS-P-030)**
- [#3338](https://github.com/opnsense/plugins/issues/3338) — feature (2023, e=5) — security/acme-client: Feature Request - Support for DNS-01 challenge using domain.com as registrar — **adopt: domain.com provider**
- [#3032](https://github.com/opnsense/plugins/issues/3032) — support (2022, e=5) — security/acme-client: DOS line-endings in generated config lead to operational failure — **design avoids (ISS-P-026): generated files never carry CRLF**
- [#4871](https://github.com/opnsense/plugins/issues/4871) — bug (2025, e=4) — os-acme-client: proxmox upload error — **adopt: Proxmox deploy hook regression tests**
- [#3864](https://github.com/opnsense/plugins/issues/3864) — support (2024, e=4) — security/acme-client: HTTP-01 challenge type not working on a fresh new install (24.1.3_1) — **design avoids (ISS-P-003)**
- [#3617](https://github.com/opnsense/plugins/issues/3617) — bug (2023, e=4) — security/acme-client: PowerDNS acme plugin problem — **adopt as regression test for the core module**
- [#5378](https://github.com/opnsense/plugins/issues/5378) — support (2026, e=3) — security/acme-client: automation "restart webGUI" not working — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#5167](https://github.com/opnsense/plugins/issues/5167) — bug (2026, e=3) — [Core] email address field max length — **adopt: email field length**
- [#4457](https://github.com/opnsense/plugins/issues/4457) — feature (2025, e=3) — security/acme-client: DNS-01 Request with cyon.ch not working — **adopt: feature backlog of the core module**
- [#4420](https://github.com/opnsense/plugins/issues/4420) — other (2024, e=3) — security/acme-client: DNS-01 Challenge Exoscale API deprecated — **adopt: review for the core module**
- [#4347](https://github.com/opnsense/plugins/issues/4347) — feature (2024, e=3) — security/acme-client: Add support for OpenSRS and Simple DNS Plus — **adopt: OpenSRS / Simple DNS Plus**
- [#4218](https://github.com/opnsense/plugins/issues/4218) — support (2024, e=3) — ACME-Client: Can not find dns api hook for: dns_transip — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3639](https://github.com/opnsense/plugins/issues/3639) — feature (2023, e=3) — security/acme-client: Add support for Synology SRM deploy hook — **adopt: Synology SRM deploy hook**
- [#3595](https://github.com/opnsense/plugins/issues/3595) — other (2023, e=3) — security/acme-client: simply.com DNS API not deleting TXT records — **adopt: review for the core module**
- [#5388](https://github.com/opnsense/plugins/issues/5388) — feature (2026, e=2) — security/acme-client: Add DNSAPI for Wix.com — **adopt: Wix provider**
- [#5373](https://github.com/opnsense/plugins/issues/5373) — support (2026, e=2) — security/acme-client: hosting.de DNS challenge fails due to missing environment variables and invalid API path — **adopt (ISS-P-002): hosting.de**
- [#5266](https://github.com/opnsense/plugins/issues/5266) — support (2026, e=2) — security/acme-client: curl unable to validate existing certificate in automation — **adopt: curl CA bundle in automations**
- [#4949](https://github.com/opnsense/plugins/issues/4949) — other (2025, e=2) — security/acme-client: specify different aliased domains for each domain is not possible — **adopt: per-domain challenge alias**
- [#4889](https://github.com/opnsense/plugins/issues/4889) — feature (2025, e=2) — os-acme-client: Add support for Dnsmasq DNS — **adopt: dnsmasq-backed DNS-01 for local CAs**
- [#4791](https://github.com/opnsense/plugins/issues/4791) — feature (2025, e=2) — [Feature Request] os-acme-client: profile support — **adopt: ACME profiles (shipped later)**
- [#4304](https://github.com/opnsense/plugins/issues/4304) — bug (2024, e=2) — ACME Plugin script to change certificate in REOLINK cameras — **adopt: Reolink hook (community)**
- [#4062](https://github.com/opnsense/plugins/issues/4062) — support (2024, e=2) — os-acme-client / acme.sh - namesilo dns challenge failure, might need to update acme.sh package shipped with opnsense — **adopt (ISS-P-002)**
- [#3800](https://github.com/opnsense/plugins/issues/3800) — feature (2024, e=2) — EuroDNS support for ACME Client Plugin — **adopt: EuroDNS provider**
- [#3119](https://github.com/opnsense/plugins/issues/3119) — bug (2022, e=2) — security/acme-client: missing control bar for System Log — **design avoids (ISS-P-030)**
- [#4659](https://github.com/opnsense/plugins/issues/4659) — feature (2025, e=1) — Feature request: ACME plugin: Add an automation to upload certificates to Proxmox Mail Gateway — **adopt: Proxmox Mail Gateway hook**
- [#3697](https://github.com/opnsense/plugins/issues/3697) — other (2023, e=1) — acme-client reverts own config to old version — **design avoids: same as #5177**
- [#3003](https://github.com/opnsense/plugins/issues/3003) — bug (2022, e=1) — security/acme-client: failure to upload certificate via sftp — **adopt as regression test for the core module**

### apcupsd (2)

- [#3300](https://github.com/opnsense/plugins/issues/3300) — bug (2023, e=4) — apcupsd doesn't report Back-UPS ES 600M1 status correctly — **adopt in NUT module**
- [#5383](https://github.com/opnsense/plugins/issues/5383) — other (2026, e=2) — Using APCUPSD to monitor a locally connected UPS and a shut down event is triggered, OPNsense halts instead of powering off — **adopt: UPS shutdown -> poweroff**

### bind (41)

- [#3225](https://github.com/opnsense/plugins/issues/3225) — other (2022, e=25) — dns/bind: Plugin Improvements — **adopt (ISS-P-019): BIND module feature list (views, ACL aliases, includes)**
- [#4887](https://github.com/opnsense/plugins/issues/4887) — feature (2025, e=15) — dns/bind: allow to set recursion no — **adopt: recursion no**
- [#4352](https://github.com/opnsense/plugins/issues/4352) — other (2024, e=13) — os-bind: Improve RNDC Key functionality and fix out of sync journals — **adopt (ISS-P-019): rndc key + journal handling**
- [#4890](https://github.com/opnsense/plugins/issues/4890) — feature (2025, e=8) — dns/bind: Add option for forward only tag on forward zones — **adopt: forward only**
- [#3495](https://github.com/opnsense/plugins/issues/3495) — bug (2023, e=7) — os-bind BIND+view — **adopt: views**
- [#5449](https://github.com/opnsense/plugins/issues/5449) — feature (2026, e=6) — os-bind: Add include directory for custom options (named.conf) — **adopt: include dir for custom options**
- [#4031](https://github.com/opnsense/plugins/issues/4031) — feature (2024, e=6) — os-bind: dns64 with ability to set ip ranges to exclude — **adopt: DNS64 with exclusions**
- [#3391](https://github.com/opnsense/plugins/issues/3391) — support (2023, e=6) — NSD support in the future? — **design: NSD not planned; BIND covers authoritative**
- [#5389](https://github.com/opnsense/plugins/issues/5389) — support (2026, e=4) — os-bind: port conflict validation for port 53 is not IP-specific — **adopt: port-conflict validation per listen IP**
- [#5068](https://github.com/opnsense/plugins/issues/5068) — other (2025, e=4) — os-bind: journals for primary zones can get corrupted on a reboot — **adopt (ISS-P-019)**
- [#4532](https://github.com/opnsense/plugins/issues/4532) — support (2025, e=4) — BIND DNS queries fail after upgrading to 24.7.12 — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#4444](https://github.com/opnsense/plugins/issues/4444) — feature (2025, e=4) — os-bind: allow to specify primaryip's port for secondary zone — **adopt: primary port**
- [#4310](https://github.com/opnsense/plugins/issues/4310) — bug (2024, e=4) — Opnsense - Bind Plugin  - Configuration settings - Unable to disable query logs. — **adopt: query log toggle**
- [#3654](https://github.com/opnsense/plugins/issues/3654) — bug (2023, e=4) — InvalidArgumentException when using DNS-01 challenge validation with OPNSense BIND API — **adopt: BIND API for ACME DNS-01 (sensr: local-zone provider)**
- [#3276](https://github.com/opnsense/plugins/issues/3276) — other (2023, e=4) — bind - reverse policy zone for individual overrides — **adopt: RPZ per-record overrides**
- [#3103](https://github.com/opnsense/plugins/issues/3103) — bug (2022, e=4) — BIND plugin API missing searchDomain action... — **adopt: API completeness**
- [#4789](https://github.com/opnsense/plugins/issues/4789) — bug (2025, e=3) — os-bind: Deleting an entry doesn't increase the serial — **adopt (ISS-P-019)**
- [#4751](https://github.com/opnsense/plugins/issues/4751) — bug (2025, e=3) — os-bind include notify source parameters — **adopt: notify-source**
- [#3302](https://github.com/opnsense/plugins/issues/3302) — support (2023, e=3) — dns/bind named start before nginx — **design avoids: unit ordering via systemd After=**
- [#3131](https://github.com/opnsense/plugins/issues/3131) — bug (2022, e=3) — os-bind: Add Responsibel Person Resource Record for zones "RP" — **adopt: RP record type**
- [#1715](https://github.com/opnsense/plugins/issues/1715) — other (2020, e=3) — os-bind: DNS Forwarder Port — **adopt: forwarder port**
- [#5178](https://github.com/opnsense/plugins/issues/5178) — bug (2026, e=2) — os-bind: custom port for forward zones — **adopt: forward zone port**
- [#5120](https://github.com/opnsense/plugins/issues/5120) — support (2025, e=2) — os-bind: Allow ACLs to reference firewall aliases — **adopt: ACLs reference firewall aliases**
- [#4993](https://github.com/opnsense/plugins/issues/4993) — other (2025, e=2) — dns/bind and dns/dnscrypt-proxy: sync DNSBLs with Unbound — **adopt: shared DNSBL source across resolvers**
- [#4733](https://github.com/opnsense/plugins/issues/4733) — bug (2025, e=2) — os-bind Adding records to zone does not default to currently selected zone — **adopt: UX default to current zone**
- [#4567](https://github.com/opnsense/plugins/issues/4567) — other (2025, e=2) — os-bind (1.33_1) - Dangling zone records left behind after zone deletion. — **design avoids: cascading delete**
- [#4504](https://github.com/opnsense/plugins/issues/4504) — bug (2025, e=2) — os-bind - BIND 9.20 incorrectly processing TCP retransmission packets for AXFR Zone Transfers — **upstream bind issue; pinned version**
- [#4435](https://github.com/opnsense/plugins/issues/4435) — other (2024, e=2) — os-bind: ACLs don't accept negative match — **adopt: negated ACL match**
- [#4356](https://github.com/opnsense/plugins/issues/4356) — bug (2024, e=2) — os-bind: DNSBL not working — **adopt: DNSBL regression tests**
- [#4106](https://github.com/opnsense/plugins/issues/4106) — feature (2024, e=2) — os-bind: Add also-notify support — **adopt: also-notify**
- [#3047](https://github.com/opnsense/plugins/issues/3047) — feature (2022, e=2) — os-bind: Add support for additional RPZ files and/or new addition to the blocklist — **adopt: additional RPZ sources**
- [#3004](https://github.com/opnsense/plugins/issues/3004) — bug (2022, e=2) — bind does not accept ACL `localnets` — **adopt: localnets ACL**
- [#5326](https://github.com/opnsense/plugins/issues/5326) — feature (2026, e=1) — os-bind [Feature Request]: Add import/export buttons for ACLs and zones. — **adopt: import/export zones (zone file import)**
- [#5106](https://github.com/opnsense/plugins/issues/5106) — other (2025, e=1) — os-bind: RNDC key file separation — **adopt: rndc key separation**
- [#5103](https://github.com/opnsense/plugins/issues/5103) — other (2025, e=1) — os-bind: Limit listening interfaces — **adopt: listen interfaces**
- [#3958](https://github.com/opnsense/plugins/issues/3958) — other (2024, e=1) — Two interface disconnects in a short time cause BIND to hang — **design avoids (ISS-P-020)**
- [#3314](https://github.com/opnsense/plugins/issues/3314) — other (2023, e=1) — os-bind: Serial not incremented on record deletes — **adopt (ISS-P-019)**
- [#3297](https://github.com/opnsense/plugins/issues/3297) — bug (2023, e=1) — DNS/BIND Silently Fails With ACL "Localhost" — **adopt: validation of ACL names**
- [#2868](https://github.com/opnsense/plugins/issues/2868) — feature (2022, e=1) — os-bind: add syslog support — **design avoids (ISS-P-030)**
- [#1791](https://github.com/opnsense/plugins/issues/1791) — bug (2020, e=1) — BIND dnsbl and whitelist issue with leading-dot TLD ".gle" (and possibly others?) — **adopt: DNSBL whitelist edge cases**
- [#1370](https://github.com/opnsense/plugins/issues/1370) — feature (2019, e=1) — dns/bind: add URLhaus to DNSBL — **adopt: URLhaus DNSBL source**

### c-icap (1)

- [#5301](https://github.com/opnsense/plugins/issues/5301) — bug (2026, e=2) — os-c-icap defaults to an IPv6-only ACL — **community (c-icap)**

### caddy (10)

- [#4095](https://github.com/opnsense/plugins/issues/4095) — feature (2024, e=14) — www/caddy: Allow writing *.global and *.conf files in the UI — **adopt: custom global/snippet files via UI (Caddy)**
- [#4747](https://github.com/opnsense/plugins/issues/4747) — support (2025, e=10) — caddy forward auth — **adopt: forward_auth (shipped later)**
- [#4642](https://github.com/opnsense/plugins/issues/4642) — feature (2025, e=9) — os-caddy: support response compression (zstd/gzip) — **adopt: encode zstd/gzip**
- [#4612](https://github.com/opnsense/plugins/issues/4612) — feature (2025, e=9) — os-caddy: add multiselect to handlers for multiple domains — **adopt: multi-domain handlers**
- [#4539](https://github.com/opnsense/plugins/issues/4539) — other (2025, e=8) — os-caddy: caddy lost dns.providers.route53 on last update — **design avoids (ISS-P-028): build-time module list pinned**
- [#4303](https://github.com/opnsense/plugins/issues/4303) — other (2024, e=5) — Can we include Keycloak as Auth in the Caddy Plugin? — **adopt: Keycloak via forward_auth docs**
- [#5008](https://github.com/opnsense/plugins/issues/5008) — support (2025, e=4) — Caddy: Add Gui options for advanced reverse_proxy settings (low-latency mode / Buffer settings) — **adopt: advanced reverse_proxy knobs**
- [#4760](https://github.com/opnsense/plugins/issues/4760) — support (2025, e=3) — os-caddy: Adding site-wise imports — **adopt: per-site imports (shipped later)**
- [#4416](https://github.com/opnsense/plugins/issues/4416) — feature (2024, e=2) — Caddy plugin: add support for multiple domains using different DNS providers — **adopt: per-domain DNS provider**
- [#4355](https://github.com/opnsense/plugins/issues/4355) — feature (2024, e=1) — www/caddy [Feature request]: Ability to bind to selected ip addresses — **adopt: bind addresses**

### chrony (6)

- [#5115](https://github.com/opnsense/plugins/issues/5115) — bug (2025, e=6) — os-chrony needs a config box for free-form text or a setting for orphan mode — **adopt: chrony custom config + orphan mode**
- [#3823](https://github.com/opnsense/plugins/issues/3823) — feature (2024, e=5) — [Feature request] Chrony Security - chrony.keys — **adopt: chrony keys / NTS**
- [#4326](https://github.com/opnsense/plugins/issues/4326) — bug (2024, e=4) — chrony does not want 0.opnsense.pool.ntp.org to be removed — **adopt: default pool removable**
- [#5360](https://github.com/opnsense/plugins/issues/5360) — feature (2026, e=3) — net/chrony - add tab to SERVICES:CHRONY:GENERAL window showing output of "chronyc clients" — **adopt: chronyc clients view**
- [#4461](https://github.com/opnsense/plugins/issues/4461) — bug (2025, e=2) — [net/chrony] makestep parameter configurable — **adopt: makestep**
- [#4514](https://github.com/opnsense/plugins/issues/4514) — feature (2025, e=1) — [NEW PLUGIN] gpsd plugin — **community module: gpsd**

### core-misfiled/other (12)

- [#3085](https://github.com/opnsense/plugins/issues/3085) — other (2022, e=11) — VPN no traffic is getting thru — **n/a: support**
- [#3310](https://github.com/opnsense/plugins/issues/3310) — bug (2023, e=8) — Throughput Drop Seemingly After Plugins Installed, Toggling Hardware Offload Solves It - But Won't Survive a Reboot — **n/a on Linux**
- [#5061](https://github.com/opnsense/plugins/issues/5061) — support (2025, e=5) — 25.7.8 update killed LAN-to-LAN connections — **n/a**
- [#3918](https://github.com/opnsense/plugins/issues/3918) — other (2024, e=5) — SIP packet inspection for informational purposes — **adopt later: SIP visibility via conntrack helper stats**
- [#4222](https://github.com/opnsense/plugins/issues/4222) — other (2024, e=4) — OpenC2 packet filtering plugin — **out of scope**
- [#5356](https://github.com/opnsense/plugins/issues/5356) — bug (2026, e=3) — Is node.js installed on current opensense? — **n/a**
- [#3266](https://github.com/opnsense/plugins/issues/3266) — bug (2023, e=3) — 2fa with mobile push notification — **adopt (core auth): push-based 2FA via WebAuthn/passkeys instead**
- [#3071](https://github.com/opnsense/plugins/issues/3071) — feature (2022, e=3) — Cannot assign network interface — **n/a**
- [#4957](https://github.com/opnsense/plugins/issues/4957) — other (2025, e=2) — Password saved in html — **n/a**
- [#3152](https://github.com/opnsense/plugins/issues/3152) — other (2022, e=2) — Simple Implementation of Automated Remote Backups — **adopt (ISS-P-021)**
- [#2779](https://github.com/opnsense/plugins/issues/2779) — bug (2022, e=2) — Upgrading to V22.1 breaks my 10Gig Network — **n/a**
- [#3491](https://github.com/opnsense/plugins/issues/3491) — support (2023, e=1) — Shouldn't this be a notice rather than an error? — **n/a**

### crowdsec (12)

- [#5438](https://github.com/opnsense/plugins/issues/5438) — bug (2026, e=5) — [os-crowdsec] CrowdSec Update to 1.7.8 is available — **design avoids (ISS-P-028)**
- [#4294](https://github.com/opnsense/plugins/issues/4294) — feature (2024, e=5) — Add additional Crowdsec bouncers (Caddy, nginx, HaProxy) — **adopt (ISS-P-018): bouncers for Caddy/HAProxy**
- [#3666](https://github.com/opnsense/plugins/issues/3666) — other (2023, e=4) — os-crowdsec - Log not forwarded to central logging — **design avoids (ISS-P-030)**
- [#4455](https://github.com/opnsense/plugins/issues/4455) — feature (2025, e=3) — crowdsec - Add default whitelist — **adopt: default whitelist (local nets)**
- [#3150](https://github.com/opnsense/plugins/issues/3150) — bug (2022, e=3) — Crowdsec reinstall from scratch — **adopt as regression test for the first-party module**
- [#3440](https://github.com/opnsense/plugins/issues/3440) — bug (2023, e=2) — os-crowdsec - Test command incorrect — **adopt as regression test for the first-party module**
- [#3410](https://github.com/opnsense/plugins/issues/3410) — bug (2023, e=2) — Crowdsec processes using almost 2GBs, memory leak or database issue? — **adopt: memory bound / DB housekeeping**
- [#3329](https://github.com/opnsense/plugins/issues/3329) — bug (2023, e=2) — crowdsec opnsense failed — **adopt as regression test for the first-party module**
- [#5318](https://github.com/opnsense/plugins/issues/5318) — feature (2026, e=1) — security/crowdsec: Add alert inspect detail modal showing full alert info — **adopt: alert detail modal**
- [#4862](https://github.com/opnsense/plugins/issues/4862) — other (2025, e=1) — CrowdSec Add/Delete/Export Machines from UI — **adopt: machine management UI**
- [#4332](https://github.com/opnsense/plugins/issues/4332) — feature (2024, e=1) — Crowdsec - Allow Manual Firewall rules by enabling Aliases only — **adopt: alias-only mode (no auto rules)**
- [#3648](https://github.com/opnsense/plugins/issues/3648) — feature (2023, e=1) — os-crowdsec: Feature Request: Add the possibility to insert whitelists IPs or Subnets through the web interface — **adopt: whitelist UI**

### ddclient (75)

- [#2842](https://github.com/opnsense/plugins/issues/2842) — other (2022, e=87) — os-ddclient Cloudflare API Key — **adopt (ISS-P-004): Cloudflare API tokens are first-class in the native DDNS engine (shipped later in os-ddclient native backend)**
- [#3233](https://github.com/opnsense/plugins/issues/3233) — feature (2022, e=33) — os-ddclient - Ability to choose IPv4 or IPv6 or IPv4/IPv6 for each entry — **adopt (ISS-P-004): per-entry IPv4/IPv6/both**
- [#3017](https://github.com/opnsense/plugins/issues/3017) — bug (2022, e=24) — dns/ddclient: no-ip broken — **adopt: provider definitions are data + contract tests against provider sandboxes**
- [#2798](https://github.com/opnsense/plugins/issues/2798) — bug (2022, e=22) — dns/ddclient: Missing provider "DynV6" — **adopt: dynv6 provider**
- [#4679](https://github.com/opnsense/plugins/issues/4679) — feature (2025, e=15) — os-ddclient: FEATURE REQUEST. Add interface restart if the ISP gave a private address — **adopt: CGNAT detection -> interface bounce option**
- [#2903](https://github.com/opnsense/plugins/issues/2903) — support (2022, e=15) — os-ddclient needs forced update interval setting — **adopt: forced update interval**
- [#2899](https://github.com/opnsense/plugins/issues/2899) — support (2022, e=15) — os-ddclient - Gateway group as monitored interface in Multi WAN configurations — **adopt (ISS-P-005): gateway group as monitored source**
- [#2880](https://github.com/opnsense/plugins/issues/2880) — feature (2022, e=15) — dns/ddclient: add cloudns — **adopt: ClouDNS provider**
- [#3021](https://github.com/opnsense/plugins/issues/3021) — bug (2022, e=13) — os-ddclient: (Dynamic DNS) - Check ip method: dyndns - No address found — **adopt as regression test for the core module**
- [#2826](https://github.com/opnsense/plugins/issues/2826) — support (2022, e=13) — dns/ddclient: add custom service type with curl — **adopt: custom URL provider (curl-style)**
- [#2988](https://github.com/opnsense/plugins/issues/2988) — other (2022, e=12) — dns/ddclient: Dashboard widget — **adopt: widget (shipped later)**
- [#3712](https://github.com/opnsense/plugins/issues/3712) — other (2023, e=11) — dns/ddclient: fix needed for dnsexit provider's json for hostnames updates — **adopt: review for the core module**
- [#3558](https://github.com/opnsense/plugins/issues/3558) — support (2023, e=10) — dns/ddclient: supporting IPv6 prefixes in native backend — **adopt: IPv6 prefix updates for hosts behind the firewall**
- [#3051](https://github.com/opnsense/plugins/issues/3051) — bug (2022, e=10) — os-ddclient checkip - randomly stopped working today using any given IP check service — **adopt as regression test for the core module**
- [#2802](https://github.com/opnsense/plugins/issues/2802) — bug (2022, e=10) — dns/ddclient: add manual account settings — **adopt as regression test for the core module**
- [#5097](https://github.com/opnsense/plugins/issues/5097) — other (2025, e=9) — ddclient: Protocol is used twice on query — **adopt: review for the core module**
- [#3135](https://github.com/opnsense/plugins/issues/3135) — bug (2022, e=9) — os-ddclient does not include cloudns and also doesn't support update URLs — **adopt as regression test for the core module**
- [#4761](https://github.com/opnsense/plugins/issues/4761) — bug (2025, e=8) — os-ddclient: No option for "on-root-domain=yes" setting makes updates fail (Invalid Domain) — **adopt as regression test for the core module**
- [#3535](https://github.com/opnsense/plugins/issues/3535) — support (2023, e=8) — ddclient OPNsense backend: Add new account class for single call URL Update for ipv4 and ipv6 — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#2844](https://github.com/opnsense/plugins/issues/2844) — feature (2022, e=8) — Dynamic DNS/ddclient Add Support for Azure DNS — **adopt: Azure DNS (shipped later)**
- [#5220](https://github.com/opnsense/plugins/issues/5220) — bug (2026, e=7) — os-ddclient: all GoDaddy dynamic DNS updates fail because TTL value is string (quoted) not integer — **adopt as regression test for the core module**
- [#4724](https://github.com/opnsense/plugins/issues/4724) — other (2025, e=7) — os-ddclient: Cloudflare DNS updates with multiple hostnames write all to same entry — **adopt: review for the core module**
- [#4227](https://github.com/opnsense/plugins/issues/4227) — feature (2024, e=7) — Feature Request: Add some info to the DDNS widget - hostname.domain.com — **adopt: feature backlog of the core module**
- [#3671](https://github.com/opnsense/plugins/issues/3671) — other (2023, e=7) — os-ddclient - Support Linode as ddns provider — **adopt: review for the core module**
- [#3356](https://github.com/opnsense/plugins/issues/3356) — support (2023, e=7) — ddclient - won't accept two freedns accounts — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#2975](https://github.com/opnsense/plugins/issues/2975) — feature (2022, e=7) — dns/ddclient: add regfish — **adopt: feature backlog of the core module**
- [#5324](https://github.com/opnsense/plugins/issues/5324) — bug (2026, e=6) — os-ddclient (native) gives error when defining multiple hostnames — **adopt as regression test for the core module**
- [#5107](https://github.com/opnsense/plugins/issues/5107) — other (2025, e=6) — ddclient: Mismatched protocols, no server override for `nsupdatev4` and `nsupdatev6` account types — **adopt: review for the core module**
- [#2914](https://github.com/opnsense/plugins/issues/2914) — support (2022, e=6) — os-ddclient plugin does not support linode dynamic dns update — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#2862](https://github.com/opnsense/plugins/issues/2862) — bug (2022, e=6) — os-ddclient : force-update (nice-to-have) — **adopt as regression test for the core module**
- [#2861](https://github.com/opnsense/plugins/issues/2861) — bug (2022, e=6) — os-ddclient should display the status — **adopt as regression test for the core module**
- [#5289](https://github.com/opnsense/plugins/issues/5289) — bug (2026, e=5) — os-ddclient errors with Cloudflare based configuration using the native tool — **adopt as regression test for the core module**
- [#3757](https://github.com/opnsense/plugins/issues/3757) — bug (2024, e=5) — [os-ddclient] Azure Service Type Missing resourceId Field — **adopt as regression test for the core module**
- [#2892](https://github.com/opnsense/plugins/issues/2892) — feature (2022, e=5) — dns/ddclient: add AWS Route53 — **adopt: Route53 provider (shipped later)**
- [#4555](https://github.com/opnsense/plugins/issues/4555) — bug (2025, e=4) — os-ddclient Multiple domains with same host/subdomain, doesn't update subsequent entries — **adopt as regression test for the core module**
- [#4460](https://github.com/opnsense/plugins/issues/4460) — feature (2025, e=4) — ddclient should provide an override to allow updating non-public IPs — **adopt: allow private addresses override**
- [#4429](https://github.com/opnsense/plugins/issues/4429) — bug (2024, e=4) — os-ddclient retains cache after failover to node with different wan address.  Never updates — **adopt (ISS-P-005): cache reset on CARP failover**
- [#3965](https://github.com/opnsense/plugins/issues/3965) — feature (2024, e=4) — ddclient: allow hostname starting with dot for porkbun provider — **adopt: feature backlog of the core module**
- [#3069](https://github.com/opnsense/plugins/issues/3069) — other (2022, e=4) — os-ddclient - no independent ipv6 change detection — **adopt (ISS-P-004): independent v4/v6 change detection**
- [#2943](https://github.com/opnsense/plugins/issues/2943) — feature (2022, e=4) — os-ddclient - Feature request: select IPv4 or IPv6 for Google DDNS — **adopt: feature backlog of the core module**
- [#2775](https://github.com/opnsense/plugins/issues/2775) — bug (2022, e=4) — dns/ddclient missing OVH dyndns update method — **adopt as regression test for the core module**
- [#4895](https://github.com/opnsense/plugins/issues/4895) — feature (2025, e=3) — ui/dyndns:  os-ddclient: Add functionality to monitor gateway groups for failover support in multi-wan setups (IPv4/IPv6). — **adopt (ISS-P-005)**
- [#3578](https://github.com/opnsense/plugins/issues/3578) — support (2023, e=3) — dns/ddclient: show IP and Sync-Time Issue — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3396](https://github.com/opnsense/plugins/issues/3396) — other (2023, e=3) — ddclient updates DNS entry without having an IP address — **adopt: review for the core module**
- [#3048](https://github.com/opnsense/plugins/issues/3048) — feature (2022, e=3) — Add Support for Azure DNS in the `os-ddclient` plugin — **adopt: Azure DNS (shipped later)**
- [#2987](https://github.com/opnsense/plugins/issues/2987) — feature (2022, e=3) — dns/ddclient needs support for GoDaddy dns for feature parity with legacy — **adopt: feature backlog of the core module**
- [#2916](https://github.com/opnsense/plugins/issues/2916) — support (2022, e=3) — os-ddclient http Update — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#2771](https://github.com/opnsense/plugins/issues/2771) — bug (2022, e=3) — dns/ddclient: Does not support @ or * in hostname field — **adopt as regression test for the core module**
- [#5334](https://github.com/opnsense/plugins/issues/5334) — bug (2026, e=2) — ddclient: generated config contains deprecated 'if-skip' option causing Perl warnings at boot — **adopt as regression test for the core module**
- [#5333](https://github.com/opnsense/plugins/issues/5333) — bug (2026, e=2) — ddclient: FAILED reported when provider returns HTML-wrapped OK or TOO_FREQ response — **adopt as regression test for the core module**
- [#5194](https://github.com/opnsense/plugins/issues/5194) — other (2026, e=2) — dns/ddclient: Improve Cloudflare configuration UX and help text — **adopt: review for the core module**
- [#4921](https://github.com/opnsense/plugins/issues/4921) — feature (2025, e=2) — [os-ddclient] Flexibility of custom POST/PUT requests — **adopt: feature backlog of the core module**
- [#4649](https://github.com/opnsense/plugins/issues/4649) — support (2025, e=2) — os-ddclient: Config file is not written correctly by WebGUI — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#4598](https://github.com/opnsense/plugins/issues/4598) — feature (2025, e=2) — dns/ddclient: Add provider TransIP — **adopt: feature backlog of the core module**
- [#4581](https://github.com/opnsense/plugins/issues/4581) — bug (2025, e=2) — dns/ddclient: Provider DNSExit - Cannot specify 'zone' field needed when hostname != zone — **adopt as regression test for the core module**
- [#4466](https://github.com/opnsense/plugins/issues/4466) — feature (2025, e=2) — os-ddclient / add option to update other hosts or aliases — **adopt: feature backlog of the core module**
- [#4433](https://github.com/opnsense/plugins/issues/4433) — bug (2024, e=2) — DNS is not updating for Godaddy — **adopt as regression test for the core module**
- [#3709](https://github.com/opnsense/plugins/issues/3709) — bug (2023, e=2) — ddclient plugin only works for Dynu third level hostnames — **adopt as regression test for the core module**
- [#3076](https://github.com/opnsense/plugins/issues/3076) — support (2022, e=2) — os-ddclient Multi-WAN scenario, all get the same public IP — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3072](https://github.com/opnsense/plugins/issues/3072) — bug (2022, e=2) — ddclient: gandi not working — **adopt as regression test for the core module**
- [#2928](https://github.com/opnsense/plugins/issues/2928) — bug (2022, e=2) — dd-client addon: delete button is not visible — **adopt as regression test for the core module**
- [#2872](https://github.com/opnsense/plugins/issues/2872) — other (2022, e=2) — os-ddclient check IP method "interface" behind IPv4 CGNAT with native IPv6 — **adopt: review for the core module**
- [#2793](https://github.com/opnsense/plugins/issues/2793) — feature (2022, e=2) — net/ddclient: add deSEC.io support — **adopt: feature backlog of the core module**
- [#5407](https://github.com/opnsense/plugins/issues/5407) — feature (2026, e=1) — dns/os-ddclient: add missing UI option for hostinger — **adopt: feature backlog of the core module**
- [#5354](https://github.com/opnsense/plugins/issues/5354) — other (2026, e=1) — ddclient: Stopped updating IPv6 records — **adopt: review for the core module**
- [#5304](https://github.com/opnsense/plugins/issues/5304) — feature (2026, e=1) — os-ddclient: add support for aliases/subdomains used with dynu — **adopt: feature backlog of the core module**
- [#5110](https://github.com/opnsense/plugins/issues/5110) — other (2025, e=1) — ddclient: Google Dynamic DNS Backend URL Update (301 Moved) — **adopt: review for the core module**
- [#5100](https://github.com/opnsense/plugins/issues/5100) — support (2025, e=1) — ddclient: unable to determine IPv6 address with strategy usev6=ifv6 — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3924](https://github.com/opnsense/plugins/issues/3924) — feature (2024, e=1) — Net/ddclient - Add Custom PATCH — **adopt: feature backlog of the core module**
- [#3861](https://github.com/opnsense/plugins/issues/3861) — feature (2024, e=1) — dns/ddclient: Add Cloudflare `dns_record_id` Input Field — **adopt: feature backlog of the core module**
- [#3672](https://github.com/opnsense/plugins/issues/3672) — feature (2023, e=1) — os-ddclient - Add configuration to support FreeDNS Randomized Update Token — **adopt: feature backlog of the core module**
- [#3427](https://github.com/opnsense/plugins/issues/3427) — bug (2023, e=1) — os-ddclient with opnsense backend and cloudflare doesn't work with API token — **adopt as regression test for the core module**
- [#3149](https://github.com/opnsense/plugins/issues/3149) — other (2022, e=1) — os-ddclient multiple ddns-providers, only the most recent entry is processed — **adopt: review for the core module**
- [#3045](https://github.com/opnsense/plugins/issues/3045) — support (2022, e=1) — dns/ddclient — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#2921](https://github.com/opnsense/plugins/issues/2921) — other (2022, e=1) — OS-DDClient: Default GW is not always the right interface to send to Dyn DNS providers with Multi-WAN — **adopt (ISS-P-005): per-entry source interface**

### dnscrypt-proxy (10)

- [#3452](https://github.com/opnsense/plugins/issues/3452) — other (2023, e=4) — DNSCrypt-Proxy plugin gets confused when Unbound is running on a different interface — **adopt: resolver chain detection**
- [#5016](https://github.com/opnsense/plugins/issues/5016) — bug (2025, e=2) — DNSCrypt-Proxy: Log after upgrade to OPNsense 25.7.7_4-amd64 — **ISS-P-030**
- [#4697](https://github.com/opnsense/plugins/issues/4697) — other (2025, e=2) — os-dynscrypt-proxy: forwarders input field "DNS Server" validates as IP address or hostname — **adopt: validation**
- [#4639](https://github.com/opnsense/plugins/issues/4639) — other (2025, e=2) — DNScrypt-proxy plugin randomly changes DNS servers despite static configuration — **adopt: static server pinning**
- [#3859](https://github.com/opnsense/plugins/issues/3859) — other (2024, e=2) — dnscrypt-proxy plugin ignores do not use IPv6 for DNS — **adopt: honour "no IPv6"**
- [#3170](https://github.com/opnsense/plugins/issues/3170) — feature (2022, e=2) — Add export/import of whitelists in dnscrypt-proxy — **adopt: import/export lists**
- [#5384](https://github.com/opnsense/plugins/issues/5384) — feature (2026, e=1) — Add http_proxy configuration option to DNSCrypt-Proxy plugin GUI — **adopt: http_proxy**
- [#5218](https://github.com/opnsense/plugins/issues/5218) — other (2026, e=1) — dns/dnscrypt-proxy: expose skip_incompatible option via GUI — **adopt: skip_incompatible**
- [#5205](https://github.com/opnsense/plugins/issues/5205) — other (2026, e=1) — dns/dnscrypt-proxy: explose lb_strategy parameter via GUI — **adopt: lb_strategy**
- [#4101](https://github.com/opnsense/plugins/issues/4101) — other (2024, e=1) — os-dnscrypt-proxy IP blocklist — **adopt: IP blocklist**

### dyndns (6)

- [#2745](https://github.com/opnsense/plugins/issues/2745) — support (2022, e=17) — DynDNS pushes temporary private IP address to dynamic DNS provider — **adopt: ignore temporary/private addresses**
- [#3472](https://github.com/opnsense/plugins/issues/3472) — bug (2023, e=4) — Dynamic DNS issue with Multiple Godaddy Hostnames (@) — **adopt (core DDNS): GoDaddy @ hosts**
- [#5232](https://github.com/opnsense/plugins/issues/5232) — other (2026, e=3) — DynDNS native backend - deSEC - v6 overwrites v4 update and vice versa — **adopt (ISS-P-004): v4 and v6 updates must not clobber each other**
- [#5079](https://github.com/opnsense/plugins/issues/5079) — bug (2025, e=2) — Dynamic DNS desec-v4 TTL — **adopt: TTL**
- [#3725](https://github.com/opnsense/plugins/issues/3725) — bug (2023, e=2) — [Dynamic DNS (dd-client)] usev6=ifv6 can not work with protocol=nsupdate @ v3.11.2 — **adopt: nsupdate v6**
- [#3416](https://github.com/opnsense/plugins/issues/3416) — feature (2023, e=1) — Not generating proper config for "Allow IPv6" disabled setting with dyndns2 — **adopt**

### etpro-telemetry (3)

- [#5394](https://github.com/opnsense/plugins/issues/5394) — bug (2026, e=4) — [SOLVED] security/etpro-telemetry: sensor_info.py timeout prevents telemetry widget from loading after 26.1.6 upgrade — **community (vendor telemetry)**
- [#4465](https://github.com/opnsense/plugins/issues/4465) — support (2025, e=2) — ET Telemetry Pro (os-etpro-telemetry): massive issues due to heavily outdated rules — **community (vendor telemetry)**
- [#3402](https://github.com/opnsense/plugins/issues/3402) — bug (2023, e=2) — Improve Button titles and Popup message for ET Telemetry Pro — **community (vendor telemetry)**

### firewall-api (10)

- [#4786](https://github.com/opnsense/plugins/issues/4786) — feature (2025, e=7) — [Feature Request] Integration Firewall Alias with AbuseIPDB Block — **adopt: AbuseIPDB/threat feeds as alias sources (core)**
- [#3197](https://github.com/opnsense/plugins/issues/3197) — support (2022, e=6) — Firewall plugin API returns false-positive information no matter the uuid — **design avoids (core API): read-after-write consistency**
- [#4999](https://github.com/opnsense/plugins/issues/4999) — support (2025, e=5) — Firewall services reload hangs when routing enable — **adopt: reload must not hang with routing enabled**
- [#3581](https://github.com/opnsense/plugins/issues/3581) — support (2023, e=5) — os-firewall plug in reporting values even if they are not yet applied — **design avoids: API returns staged vs applied state explicitly**
- [#3139](https://github.com/opnsense/plugins/issues/3139) — other (2022, e=4) — net/firewall: Gateway Groups not available — **adopt (ISS-P-023): gateway groups in rule API**
- [#5623](https://github.com/opnsense/plugins/issues/5623) — feature (2026, e=2) — Feature Request: [Caddy] Support Access List Nested Groups (similar to Firewall Alias Groups) — **adopt: nested alias groups in Caddy access lists**
- [#3207](https://github.com/opnsense/plugins/issues/3207) — bug (2022, e=2) — Usage of aliases outside of firewall rules? — **adopt: aliases usable in other modules**
- [#2879](https://github.com/opnsense/plugins/issues/2879) — bug (2022, e=2) — net/firewall Gateway Groups not supported — **adopt (ISS-P-023)**
- [#3255](https://github.com/opnsense/plugins/issues/3255) — other (2023, e=1) — Additive firewall aliases — **adopt: alias composition**
- [#2789](https://github.com/opnsense/plugins/issues/2789) — other (2022, e=1) — SNMP system type changed from "firewall" to "server" — **adopt: SNMP sysServices value**

### freeradius (26)

- [#3261](https://github.com/opnsense/plugins/issues/3261) — bug (2023, e=9) — Freeradius fails to start with DHCP enabled — **adopt: freeradius + DHCP ordering**
- [#3044](https://github.com/opnsense/plugins/issues/3044) — bug (2022, e=8) — FreeRadius EAP-TLS allows successfull auth without related user — **adopt: EAP-TLS must verify user mapping**
- [#664](https://github.com/opnsense/plugins/issues/664) — feature (2018, e=6) — freeradius plugin feature request: group attributes — **adopt: group attributes**
- [#4452](https://github.com/opnsense/plugins/issues/4452) — bug (2025, e=5) — FreeRadius - Add checkbox in the GUI to enable OCSP in the EAP module — **adopt: OCSP toggle**
- [#5196](https://github.com/opnsense/plugins/issues/5196) — feature (2026, e=2) — net/freeradius: allow remote mysql to be used for accounting — **adopt: remote MySQL accounting**
- [#4548](https://github.com/opnsense/plugins/issues/4548) — feature (2025, e=2) — FreeRadius 1.9.23: comma in password not allowed by webGUI although help text lists it as valid — **design avoids (ISS-P-026)**
- [#4537](https://github.com/opnsense/plugins/issues/4537) — other (2025, e=2) — user privilege for freeradius — **adopt: granular privileges**
- [#4297](https://github.com/opnsense/plugins/issues/4297) — bug (2024, e=2) — api freeradius /api/freeradius/user/searchUser — **adopt: API search**
- [#3833](https://github.com/opnsense/plugins/issues/3833) — support (2024, e=2) — os-freeradius location folder — **n/a**
- [#3036](https://github.com/opnsense/plugins/issues/3036) — bug (2022, e=2) — FreeRadius gives pap error when libressl — **n/a: LibreSSL**
- [#2933](https://github.com/opnsense/plugins/issues/2933) — feature (2022, e=2) — os-freeradius should allow colons in usernames and passwords — **design avoids (ISS-P-026)**
- [#5397](https://github.com/opnsense/plugins/issues/5397) — other (2026, e=1) — net/freeradius - custom default vlan-ID for mikrotik attributes — **adopt: default VLAN attributes**
- [#5117](https://github.com/opnsense/plugins/issues/5117) — feature (2026, e=1) — [Freeradius] when creating user, password contain comma (,) will trigger Text does not validate error. @ is not allowed too. — **design avoids (ISS-P-026)**
- [#4969](https://github.com/opnsense/plugins/issues/4969) — bug (2025, e=1) — net/freeradius: Fallback authentication does not work — **adopt: fallback auth tests**
- [#4754](https://github.com/opnsense/plugins/issues/4754) — other (2025, e=1) — net/freeradius: multiple Cisco-AV-Pair with the same name — **adopt: repeated AV pairs**
- [#4308](https://github.com/opnsense/plugins/issues/4308) — feature (2024, e=1) — Add message authenticator support to core RADIUS client (auth server) implementation — **adopt (core RADIUS client): Message-Authenticator (BlastRADIUS)**
- [#4250](https://github.com/opnsense/plugins/issues/4250) — bug (2024, e=1) — net/freeradius - Error: It looks like the client has been updated to protect from the BlastRADIUS attack. — **adopt: BlastRADIUS defaults**
- [#4040](https://github.com/opnsense/plugins/issues/4040) — other (2024, e=1) — os-freeradius: EAP max TLS version increase — **adopt: TLS max version**
- [#4039](https://github.com/opnsense/plugins/issues/4039) — bug (2024, e=1) — os-freeradius: EAP TLS version min selector not working — **adopt: TLS min version**
- [#3990](https://github.com/opnsense/plugins/issues/3990) — bug (2024, e=1) — Plugin freeradius entry missing for remote syslog — **design avoids (ISS-P-030)**
- [#3750](https://github.com/opnsense/plugins/issues/3750) — feature (2024, e=1) — os-freeradius: missing option to set Framed-IPv6-Prefix — **adopt: Framed-IPv6-Prefix**
- [#3568](https://github.com/opnsense/plugins/issues/3568) — feature (2023, e=1) — freeradius: add option to configure Ruckus-User-Groups — **adopt: Ruckus attributes**
- [#3438](https://github.com/opnsense/plugins/issues/3438) — other (2023, e=1) — FreeRadius: No unique constraint for username — **design avoids: unique constraint on username**
- [#3185](https://github.com/opnsense/plugins/issues/3185) — other (2022, e=1) — net/freeradius - return memberOf attribute when using AD — **adopt: memberOf from AD**
- [#3126](https://github.com/opnsense/plugins/issues/3126) — feature (2022, e=1) — FreeRADIUS: Add ability to use ntlm_auth — **adopt: ntlm_auth**
- [#2925](https://github.com/opnsense/plugins/issues/2925) — feature (2022, e=1) — [os-freeradius] - Option "secp521r1" is missing and suggestions to improve the informational message — **adopt: secp521r1**

### frr (54)

- [#1972](https://github.com/opnsense/plugins/issues/1972) — feature (2020, e=48) — os-frr: No support for authentication in BGP — **adopt (ISS-P-007): BGP MD5/TCP-AO neighbour authentication (shipped later in os-frr)**
- [#1006](https://github.com/opnsense/plugins/issues/1006) — feature (2018, e=25) — Feature Request: BGP Peer Group Support — **adopt (ISS-P-007): peer groups (shipped later)**
- [#3179](https://github.com/opnsense/plugins/issues/3179) — support (2022, e=23) — BGP source IP address unpredictable when using CARP — **adopt (ISS-P-009): BGP update-source bound to CARP VIP**
- [#1005](https://github.com/opnsense/plugins/issues/1005) — feature (2018, e=23) — Feature Request: New Features on BGP — **adopt: show-commands in the routing diagnostics UI**
- [#3630](https://github.com/opnsense/plugins/issues/3630) — other (2023, e=18) — FRR: Can no longer match a prefix-list in a route-map — **adopt (ISS-P-007): prefix-list matching in route-maps**
- [#3520](https://github.com/opnsense/plugins/issues/3520) — bug (2023, e=13) — Static nullroutes does not show up in routing table in 23.7 — **adopt (ISS-P-008): null routes visible in routing table**
- [#3372](https://github.com/opnsense/plugins/issues/3372) — support (2023, e=11) — net/frr - BGP passwords not being added automatically (register_sas script not running) — **adopt (ISS-P-007): neighbour passwords applied natively**
- [#4821](https://github.com/opnsense/plugins/issues/4821) — support (2025, e=9) — Add RPKI support to FRR plugin — **adopt: RPKI (rtrlib) support**
- [#3392](https://github.com/opnsense/plugins/issues/3392) — bug (2023, e=9) — FRR weight on BGP Neigbors with IPv6 not working — **adopt: weight for IPv6 neighbours**
- [#5362](https://github.com/opnsense/plugins/issues/5362) — bug (2026, e=8) — os-frr: No possibility to select specific IP address as BGP source if interface contains multiple IP — **adopt (ISS-P-009): explicit source address**
- [#3508](https://github.com/opnsense/plugins/issues/3508) — other (2023, e=8) — os-frr: BGP authentication not always working — **adopt (ISS-P-007)**
- [#2202](https://github.com/opnsense/plugins/issues/2202) — feature (2021, e=8) — FRR: Add confederation GUI options. — **adopt: confederation options**
- [#4640](https://github.com/opnsense/plugins/issues/4640) — support (2025, e=7) — os-frr: bgp routes not routable even though they are advertised — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3193](https://github.com/opnsense/plugins/issues/3193) — bug (2022, e=7) — os-frr handling of rmap prefix-tree default node — **adopt: route-map default node semantics**
- [#3166](https://github.com/opnsense/plugins/issues/3166) — bug (2022, e=7) — FRRouting doesn't start after enabling SNMP AgentX — **adopt: SNMP AgentX with FRR**
- [#3926](https://github.com/opnsense/plugins/issues/3926) — bug (2024, e=5) — FRR BGP Prefix-List RouteMap Bug — **adopt (ISS-P-007)**
- [#3731](https://github.com/opnsense/plugins/issues/3731) — support (2023, e=5) — os-frr 1.37 Redistributing Kernel Routes into OSPF not working — **adopt: redistribute kernel/static into OSPF**
- [#3649](https://github.com/opnsense/plugins/issues/3649) — other (2023, e=5) — os-frr: BGP extended-nexthop — **adopt: extended-nexthop (RFC 5549)**
- [#3543](https://github.com/opnsense/plugins/issues/3543) — bug (2023, e=5) — FRR - Routing Issue - Redistribute Static/Kernel Routes — **adopt: redistribute static/kernel**
- [#3178](https://github.com/opnsense/plugins/issues/3178) — support (2022, e=5) — bgp update-source option missing or overwritten in os-frr (gui) — **adopt: update-source**
- [#2146](https://github.com/opnsense/plugins/issues/2146) — other (2020, e=5) — net/frr: Use "all" in "show bgp ... [json]" commands once it's available — **adopt: review for the core module**
- [#5038](https://github.com/opnsense/plugins/issues/5038) — feature (2025, e=4) — net/frr: Add remove-private-AS for BGP Neighbors — **adopt: remove-private-AS (shipped later)**
- [#4829](https://github.com/opnsense/plugins/issues/4829) — feature (2025, e=4) — [Feature Request] Add GUI Support for multiple OSPF and BGP processed of net/frr — **adopt later: multiple OSPF/BGP instances (VRF)**
- [#4783](https://github.com/opnsense/plugins/issues/4783) — support (2025, e=4) — os-frr: routes from connected wireguard peers not redistributed via BGP — **adopt: WireGuard peer routes redistributable**
- [#4333](https://github.com/opnsense/plugins/issues/4333) — feature (2024, e=4) — Add support for FRR and setkey Bidirectional — **out of scope: IPsec setkey bidirectional is FreeBSD-specific**
- [#3457](https://github.com/opnsense/plugins/issues/3457) — support (2023, e=4) — Updating the remote address in BGP neighbor does not update the configuration — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#3175](https://github.com/opnsense/plugins/issues/3175) — support (2022, e=4) — os-frr: daemon never starts — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#5233](https://github.com/opnsense/plugins/issues/5233) — feature (2026, e=3) — [FEATURE-REQUEST] Allow FRR to implement default routes — **adopt: originate default route option**
- [#3939](https://github.com/opnsense/plugins/issues/3939) — support (2024, e=3) — [BUG]  frr disconnects bgp neighbors when changing configuration — **adopt (ISS-P-006): hitless config apply**
- [#3846](https://github.com/opnsense/plugins/issues/3846) — other (2024, e=3) — Restarting the FRR process destroys OSPF — **adopt (ISS-P-006)**
- [#3463](https://github.com/opnsense/plugins/issues/3463) — bug (2023, e=3) — FRR OSPF area setup — **adopt as regression test for the core module**
- [#3214](https://github.com/opnsense/plugins/issues/3214) — bug (2022, e=3) — os-frr does not persist vtysh commands after reboot — **design avoids: all config via model; vtysh edits not supported**
- [#3100](https://github.com/opnsense/plugins/issues/3100) — feature (2022, e=3) — FRR: Allow multiple set commands in a Route Map entry — **adopt (ISS-P-007): multiple set statements per route-map entry**
- [#3099](https://github.com/opnsense/plugins/issues/3099) — feature (2022, e=3) — FRR: Route-Maps: Allow matching on Peer IP — **adopt (ISS-P-007): match peer**
- [#5049](https://github.com/opnsense/plugins/issues/5049) — other (2025, e=2) — net/frr: OSPF metric-type support — **adopt: OSPF metric-type**
- [#5033](https://github.com/opnsense/plugins/issues/5033) — feature (2025, e=2) — Request FRR to be built with PIM support — **adopt: PIM (multicast routing) module**
- [#4960](https://github.com/opnsense/plugins/issues/4960) — support (2025, e=2) — net/frr: add graceful-restart to OSPF — **adopt: OSPF graceful restart**
- [#4925](https://github.com/opnsense/plugins/issues/4925) — support (2025, e=2) — FRR OSPFv3 fails to start (os-frr) — **adopt: OSPFv3 regression test**
- [#4898](https://github.com/opnsense/plugins/issues/4898) — support (2025, e=2) — In the FRR routing plugin, if we apply static routes, it restarts the entire service, which interrupts BGP/OSPF sessions. — **adopt (ISS-P-006)**
- [#4603](https://github.com/opnsense/plugins/issues/4603) — support (2025, e=2) — net/frr bgpd does not receive announcements when zebra is enabled. — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#4447](https://github.com/opnsense/plugins/issues/4447) — other (2025, e=2) — BGP route redistribution into ospf6 — **adopt: review for the core module**
- [#3706](https://github.com/opnsense/plugins/issues/3706) — other (2023, e=2) — OSPFv3 link drops after 4.5 minutes due to (potential) Multicast Address Listening Interval timeout — **adopt: review for the core module**
- [#3557](https://github.com/opnsense/plugins/issues/3557) — other (2023, e=2) — BGP is not advertising — **adopt: review for the core module**
- [#3478](https://github.com/opnsense/plugins/issues/3478) — other (2023, e=2) — FRR Expose route-via-default — **adopt: review for the core module**
- [#3462](https://github.com/opnsense/plugins/issues/3462) — bug (2023, e=2) — net/frr  support ISIS dynamic routing protocol — **adopt later: IS-IS**
- [#3128](https://github.com/opnsense/plugins/issues/3128) — other (2022, e=2) — enable staticd (frr) by default — **design: staticd always on**
- [#2918](https://github.com/opnsense/plugins/issues/2918) — bug (2022, e=2) — net/frr: ospf6d incorrectly sending Hello Packets on pppoe0 interface instead of configured LAN interface — **adopt: ospf6d interface binding**
- [#5314](https://github.com/opnsense/plugins/issues/5314) — feature (2026, e=1) — net/frr: Add BFD Strict Mode option for BGP neighbors — **adopt: BFD strict mode**
- [#4864](https://github.com/opnsense/plugins/issues/4864) — support (2025, e=1) — Strange OSPFd and Zebra related errors — **design avoids: validation/diagnostics must make this misconfiguration visible**
- [#4863](https://github.com/opnsense/plugins/issues/4863) — support (2025, e=1) — Can not edit the OSPF Router ID — **adopt: editable OSPF router-id**
- [#3445](https://github.com/opnsense/plugins/issues/3445) — other (2023, e=1) — default gateway disconnect not generating OSPF events — **adopt: review for the core module**
- [#3366](https://github.com/opnsense/plugins/issues/3366) — bug (2023, e=1) — [BUG] Interface BGP routes not removed on interface disable or removal — **adopt: interface removal cleans BGP config**
- [#2952](https://github.com/opnsense/plugins/issues/2952) — other (2022, e=1) — BGP path prepending — **adopt: AS-path prepend in route-maps**
- [#2944](https://github.com/opnsense/plugins/issues/2944) — bug (2022, e=1) — FRR - Routing: BGP : Routemaps - Missing weight and local preference — **adopt (ISS-P-007): weight/local-pref set**

### gdrive-backup (1)

- [#4731](https://github.com/opnsense/plugins/issues/4731) — support (2025, e=1) — Backup in google drive creates empty files — **adopt (ISS-P-021)**

### git-backup (13)

- [#2994](https://github.com/opnsense/plugins/issues/2994) — bug (2022, e=14) — os-git-backup 1.0_1 does not initialise upstream properly, does not backup any files — **adopt (ISS-P-021)**
- [#4739](https://github.com/opnsense/plugins/issues/4739) — support (2025, e=10) — os-git-backup: Backups silently fail, web UI claims everything works — **adopt (ISS-P-021): failures become alerts**
- [#3132](https://github.com/opnsense/plugins/issues/3132) — other (2022, e=9) — Does git backup support other branches? — **adopt (ISS-P-021): branch selection**
- [#4464](https://github.com/opnsense/plugins/issues/4464) — support (2025, e=7) — os-git-backup: Git Backups shouldn't contain secrets — **adopt (ISS-P-021): secret-free export mode**
- [#3050](https://github.com/opnsense/plugins/issues/3050) — support (2022, e=6) — sysutils/git-backup: rc.syshook.d script does not appear to be running on 22.7-RC2 — **adopt (ISS-P-021)**
- [#4344](https://github.com/opnsense/plugins/issues/4344) — bug (2024, e=4) — os-git-backup should accept non standard ssh port in repo url — **adopt: ssh port in URL**
- [#4143](https://github.com/opnsense/plugins/issues/4143) — bug (2024, e=4) — os-git-backup - error in push — **adopt (ISS-P-021)**
- [#5440](https://github.com/opnsense/plugins/issues/5440) — support (2026, e=2) — sysutils/git-backup: not backing up new firewall rules — **adopt (ISS-P-021)**
- [#4723](https://github.com/opnsense/plugins/issues/4723) — support (2025, e=2) — os-git-backup - doesnt track config changes — **adopt (ISS-P-021)**
- [#3834](https://github.com/opnsense/plugins/issues/3834) — support (2024, e=2) — os-git-backup does not work with http:// Gitea server — **adopt: http remotes**
- [#5041](https://github.com/opnsense/plugins/issues/5041) — support (2025, e=1) — os-git-backup: automatic per system stable branch name different for each install — **adopt (ISS-P-021): deterministic branch naming**
- [#3775](https://github.com/opnsense/plugins/issues/3775) — support (2024, e=1) — Do not save root password when using git-backup — **adopt (ISS-P-021): secret-free export**
- [#3181](https://github.com/opnsense/plugins/issues/3181) — support (2022, e=1) — os-git-backup: doesn't work with ssh passphrases — **adopt: ssh key passphrase via agent**

### google-cloud-sdk (1)

- [#4946](https://github.com/opnsense/plugins/issues/4946) — bug (2025, e=1) — [os-google-cloud-sdk-1.0_1] gcloud sdk 537.0.0 broken in opnsense 25.7.3_7 — **out of scope: gcloud dropped**

### haproxy (10)

- [#3562](https://github.com/opnsense/plugins/issues/3562) — bug (2023, e=10) — net/haproxy: Haproxy startup errors are silently ignored in the frontend — **adopt (ISS-P-010): startup errors surfaced in UI**
- [#3971](https://github.com/opnsense/plugins/issues/3971) — support (2024, e=8) — haproxy Graphical Issues on Proxied Pages — **adopt: documentation of proxy header handling**
- [#3092](https://github.com/opnsense/plugins/issues/3092) — feature (2022, e=4) — net/haproxy map files updates from url like firewall aliases URL tables — **adopt: map files from URL (alias-style)**
- [#5039](https://github.com/opnsense/plugins/issues/5039) — support (2025, e=3) — HAProxy plugin: exportCerts.php uses cached PHP config causing renewed ACME certificates not to be deployed — **adopt (ISS-P-011): cert deploy reads live state**
- [#4564](https://github.com/opnsense/plugins/issues/4564) — support (2025, e=3) — net/haproxy : using standard logging — **design avoids (ISS-P-030): standard journald logging**
- [#3950](https://github.com/opnsense/plugins/issues/3950) — other (2024, e=3) — HAProxy - OR operator with multiple ACLs of the same name — **adopt (ISS-P-012): OR groups**
- [#4391](https://github.com/opnsense/plugins/issues/4391) — bug (2024, e=2) — net/haproxy: multiple map file rules in a single frontend are not working — **adopt: multiple map rules per frontend**
- [#4314](https://github.com/opnsense/plugins/issues/4314) — support (2024, e=2) — net/haproxy: not starting after boot/reboot — **adopt (ISS-P-010): boot path identical to apply path**
- [#3385](https://github.com/opnsense/plugins/issues/3385) — bug (2023, e=2) — HAProxy improve error handling. — **adopt (ISS-P-010)**
- [#4695](https://github.com/opnsense/plugins/issues/4695) — other (2025, e=1) — os-haproxy - ACL source IP matches any IPv6 - produce lag/delay — **adopt: review for the first-party module**

### igmp-proxy (1)

- [#5118](https://github.com/opnsense/plugins/issues/5118) — bug (2026, e=3) — os-igmp-proxy: doesn't respect CARP state — **adopt: CARP-aware igmpproxy**

### intrusion-detection-content (5)

- [#3594](https://github.com/opnsense/plugins/issues/3594) — other (2023, e=10) — Zeek IDS plugin — **community module: Zeek**
- [#3692](https://github.com/opnsense/plugins/issues/3692) — other (2023, e=5) — Suricata Snort VRT Rules Vastly Out of Date — **adopt: rule-source freshness alerts**
- [#4134](https://github.com/opnsense/plugins/issues/4134) — support (2024, e=4) — Suricata IPS error: Cannot allocate memory — **adopt: memory sizing guidance in core IDS**
- [#4059](https://github.com/opnsense/plugins/issues/4059) — bug (2024, e=3) — Intrusion Detection Plugin — **adopt as regression test for the first-party module**
- [#3331](https://github.com/opnsense/plugins/issues/3331) — bug (2023, e=2) — Suricata crashes with ntopng — **adopt as regression test for the first-party module**

### intrusion-detection-content-et-pro (1)

- [#3721](https://github.com/opnsense/plugins/issues/3721) — other (2023, e=1) — intrusion-detection-content-et-pro (v1.0.2_1): Gateway on WAN interface breaks when IDS is active on WAN interface. — **adopt: IDS on WAN without breaking gateway (core)**

### intrusion-detection-content-snort-vrt (1)

- [#3009](https://github.com/opnsense/plugins/issues/3009) — bug (2022, e=17) — BE 22.4.1: os-intrusion-detection-content-snort-vrt 1.1_1:  SC_ERR_NO_RULES_LOADED — **adopt: rule-source errors surfaced**

### iperf (4)

- [#3409](https://github.com/opnsense/plugins/issues/3409) — bug (2023, e=15) — Unable to get iperf package running after fresh 23.1(.6) install — **adopt: iperf in core diagnostics**
- [#4276](https://github.com/opnsense/plugins/issues/4276) — bug (2024, e=3) — iperf is still broken on 24.7.5_3 — **adopt**
- [#3945](https://github.com/opnsense/plugins/issues/3945) — support (2024, e=3) — os-iperf plugin does not open firewall — **adopt: auto firewall opening**
- [#3545](https://github.com/opnsense/plugins/issues/3545) — bug (2023, e=3) — os-iperf TypeError on failed iPerf3 causes browser not to show anything — **adopt: error handling**

### isc-dhcp (1)

- [#5211](https://github.com/opnsense/plugins/issues/5211) — support (2026, e=3) — net/isc-dhcp: ISC DHCPv6 choose subnet manually — **adopt (core DHCPv6): subnet selection**

### lcdproc-sdeclcd (2)

- [#5374](https://github.com/opnsense/plugins/issues/5374) — feature (2026, e=10) — [New Plugin] sysutils/lcdproc - Full LCDproc integration (replacement for lcdproc-sdeclcd) — **community module: full lcdproc**
- [#3060](https://github.com/opnsense/plugins/issues/3060) — other (2022, e=2) — [os-lcdproc-sdeclcd] lcdproc plugin needs some love. — **community**

### lldpd (4)

- [#5293](https://github.com/opnsense/plugins/issues/5293) — other (2026, e=8) — os-switchtracker for switch discovery and monitoring directly within OPNsense — **community module: switch tracker; core gets LLDP neighbours**
- [#4561](https://github.com/opnsense/plugins/issues/4561) — feature (2025, e=3) — os-lldpd: Add additional configuration input field — **adopt: lldpd custom config**
- [#4418](https://github.com/opnsense/plugins/issues/4418) — feature (2024, e=2) — Add ability to set chassis management ip via LLDP plugin — **adopt: management IP**
- [#3200](https://github.com/opnsense/plugins/issues/3200) — feature (2022, e=1) — Support for lldpd neighbours via snmp — **adopt: lldpd SNMP subagent**

### maltrail (1)

- [#3250](https://github.com/opnsense/plugins/issues/3250) — bug (2023, e=7) — [os-maltrail] Save button does not save — **out of scope: maltrail dropped**

### mdns-repeater (12)

- [#3352](https://github.com/opnsense/plugins/issues/3352) — other (2023, e=9) — mdns-repeater - Lack of MDNS relay for ipv6 — **adopt (ISS-P-029): IPv6 mDNS**
- [#2919](https://github.com/opnsense/plugins/issues/2919) — bug (2022, e=8) — mDNS Repeater CARP Failover file missing — **adopt (ISS-P-029): CARP-aware**
- [#3710](https://github.com/opnsense/plugins/issues/3710) — bug (2023, e=6) — OPNsense\Base\BaseModel->runMigrations() failed -  Option not in list when "lan" interface is missing — **design avoids: migrations tolerate missing interfaces**
- [#4430](https://github.com/opnsense/plugins/issues/4430) — other (2024, e=5) — os-mdns-repeater filter what is repeated by record type or other values such as port — **adopt (ISS-P-029): record-type filters**
- [#3418](https://github.com/opnsense/plugins/issues/3418) — bug (2023, e=4) — os-mdns-repeater: Support multiple instances of mdns-repeater — **adopt (ISS-P-029): multiple instances**
- [#5739](https://github.com/opnsense/plugins/issues/5739) — feature (2026, e=3) — net/avahi-reflector: proposal for an Avahi-based mDNS/DNS-SD reflector plugin — **adopt (ISS-P-029): Avahi reflector**
- [#3369](https://github.com/opnsense/plugins/issues/3369) — other (2023, e=3) — mdsn-repeater not stopping when CARP is disabled by the "Temporary Disable CARP" button — **adopt (ISS-P-029): CARP state**
- [#4585](https://github.com/opnsense/plugins/issues/4585) — bug (2025, e=2) — mdns-repeater issues with CARP — **adopt (ISS-P-029)**
- [#3771](https://github.com/opnsense/plugins/issues/3771) — bug (2024, e=2) — Make it clear that a reboot is required after configuring mdns-repeater with CARP support — **design avoids: no reboot ever required**
- [#1466](https://github.com/opnsense/plugins/issues/1466) — feature (2019, e=2) — mdns-repeater: allow multicast in firewall — **adopt: auto firewall rules for multicast**
- [#3973](https://github.com/opnsense/plugins/issues/3973) — bug (2024, e=1) — mdns-repeater plugin does not auto-start after system reboot — **adopt: autostart**
- [#3506](https://github.com/opnsense/plugins/issues/3506) — support (2023, e=1) — mDNS repeater not repeating address for chromecast audio and nest hubs — **adopt: Chromecast/Nest testing**

### monit (1)

- [#4468](https://github.com/opnsense/plugins/issues/4468) — feature (2025, e=2) — Monit - Allow cron-style negative schedules — **adopt: cron-style schedules in core health monitor**

### net-snmp (5)

- [#3680](https://github.com/opnsense/plugins/issues/3680) — support (2023, e=9) — Consolidation of BSNMPD — **adopt (core SNMP): one agent**
- [#4886](https://github.com/opnsense/plugins/issues/4886) — bug (2025, e=8) — Missing Authentication and Privacy Protocol Fields in SNMPv3 Configuration (OPNsense 25.1.6) NET-SNMP — **adopt**
- [#3657](https://github.com/opnsense/plugins/issues/3657) — bug (2023, e=4) — Mib File for plugin Net-SNMP on Opnsense — **adopt: ship MIB file**
- [#4704](https://github.com/opnsense/plugins/issues/4704) — bug (2025, e=3) — Cannot use valid SNMPv3 passphrases with special characters in NET-SNMP plugin (UI validation too strict) — **design avoids (ISS-P-026)**
- [#4907](https://github.com/opnsense/plugins/issues/4907) — other (2025, e=2) — SNMP custom config lines/SFP module temperatures — **adopt: custom lines / SFP temperatures via sensors**

### netbird (3)

- [#4934](https://github.com/opnsense/plugins/issues/4934) — bug (2025, e=27) — Netbird package doesn't start — **adopt (ISS-P-024): netbird start regression tests**
- [#5023](https://github.com/opnsense/plugins/issues/5023) — bug (2025, e=12) — os-netbird plugin not following OPNsense HA failover — **adopt (ISS-P-025): HA failover awareness for overlays**
- [#4881](https://github.com/opnsense/plugins/issues/4881) — other (2025, e=1) — security/netbird: No access to the firwawall itself with enabled "Access to LAN" — **adopt: self-access rule**

### netdata (4)

- [#4579](https://github.com/opnsense/plugins/issues/4579) — other (2025, e=28) — add: Beszel agent plugin — **community module: Beszel agent**
- [#2902](https://github.com/opnsense/plugins/issues/2902) — bug (2022, e=14) — os-netdata: Connect agent to netdata cloud fails — **community (netdata)**
- [#4770](https://github.com/opnsense/plugins/issues/4770) — bug (2025, e=6) — Netdata Plugin is broken — **community (netdata)**
- [#4239](https://github.com/opnsense/plugins/issues/4239) — other (2024, e=2) — [FR] Netdata integrate Streaming — **community (netdata)**

### new-plugin-request (14)

- [#2976](https://github.com/opnsense/plugins/issues/2976) — feature (2022, e=68) — Feature Request -- Safe Mode (Auto Rollback Changes if connection lost or not re-established within X time) — **adopt (ISS-P-022): commit-confirm / auto-rollback in core**
- [#4595](https://github.com/opnsense/plugins/issues/4595) — feature (2025, e=16) — OpenApi / Swagger: new plugin — **adopt: OpenAPI spec generated from the API (core)**
- [#1412](https://github.com/opnsense/plugins/issues/1412) — feature (2019, e=12) — Feature Request: Clash,a rule-based tunnel works like Surge — **out of scope**
- [#5347](https://github.com/opnsense/plugins/issues/5347) — feature (2026, e=8) — New plugin proposal: Xray-core proxy client with transparent LAN routing — **community module: xray**
- [#3458](https://github.com/opnsense/plugins/issues/3458) — feature (2023, e=4) — [FEATURE REQUEST] RTSP handler is needed — **adopt: RTSP conntrack helper option**
- [#5419](https://github.com/opnsense/plugins/issues/5419) — feature (2026, e=3) — [New Plugin] - net/os-netmap — **community module**
- [#5165](https://github.com/opnsense/plugins/issues/5165) — feature (2026, e=3) — Plugin request: Support for AdGuard VPN "TrustTunnel" protocol — **out of scope**
- [#4259](https://github.com/opnsense/plugins/issues/4259) — feature (2024, e=3) — Plugin for xymon-client — **community module: xymon**
- [#3913](https://github.com/opnsense/plugins/issues/3913) — feature (2024, e=3) — Request: Pomerium Plugin — **community module: Pomerium**
- [#2795](https://github.com/opnsense/plugins/issues/2795) — feature (2022, e=3) — Add "whois" as a Diagnostic tool under Interfaces — **adopt: whois in diagnostics**
- [#4027](https://github.com/opnsense/plugins/issues/4027) — feature (2024, e=2) — Support for watchdog on APU2 boards — **adopt: hardware watchdog (systemd watchdog) in core**
- [#3363](https://github.com/opnsense/plugins/issues/3363) — bug (2023, e=2) — Add custom host blocklist — **adopt: custom host blocklists in core DNS**
- [#5298](https://github.com/opnsense/plugins/issues/5298) — feature (2026, e=1) — Plugin request: Support rtp2httpd, a more powerful udpxy/msd_lite — **community module**
- [#3351](https://github.com/opnsense/plugins/issues/3351) — support (2023, e=1) — Add new cryptography method. — **n/a**

### nextcloud-backup (11)

- [#3311](https://github.com/opnsense/plugins/issues/3311) — bug (2023, e=12) — Nextcloud Backup not working with NC located on LAN — **adopt (ISS-P-021)**
- [#3405](https://github.com/opnsense/plugins/issues/3405) — support (2023, e=11) — nextcloud-backup: option to accept self-signed certificates — **adopt: self-signed CA pinning for backup targets**
- [#4902](https://github.com/opnsense/plugins/issues/4902) — other (2025, e=7) — os-nextcloud-backup — **adopt (ISS-P-021)**
- [#5296](https://github.com/opnsense/plugins/issues/5296) — bug (2026, e=6) — os-nextcloud-backup (maybe any remote backup plugin?) doesn't seem to be triggerered by config changes after update to 26.1.3 — **adopt (ISS-P-021): backup triggers tested on every config commit**
- [#4141](https://github.com/opnsense/plugins/issues/4141) — bug (2024, e=4) — os-nextcloud-backup doesn't work with hidden folders — **adopt: hidden folders**
- [#2893](https://github.com/opnsense/plugins/issues/2893) — feature (2022, e=4) — sysutils/nextcloud-backup: add option for "Backup Count" and prune old backup files — **adopt: retention count**
- [#4318](https://github.com/opnsense/plugins/issues/4318) — feature (2024, e=3) — [os-nextcloud-backup] [Feature Request] Add a backup count (keep last n) as in gdrive options — **adopt: retention count**
- [#5327](https://github.com/opnsense/plugins/issues/5327) — other (2026, e=2) — os-nextcloud-backup Timestring of backup files are in UTC — **adopt: local-time file names**
- [#3792](https://github.com/opnsense/plugins/issues/3792) — bug (2024, e=2) — Insecure array in in_array condition in os-nextcloud-backup plugin — **adopt: strict comparisons**
- [#3670](https://github.com/opnsense/plugins/issues/3670) — bug (2023, e=2) — os-nextcloud-backup: URL is incorrectly encoded if nextcloud username contains spaces — **adopt: URL encoding**
- [#5330](https://github.com/opnsense/plugins/issues/5330) — other (2026, e=1) — Encryption Password Not Removed When Deleting Field in NextCloud Backup Plugin — **adopt: clearing a secret field clears it**

### nginx (42)

- [#4076](https://github.com/opnsense/plugins/issues/4076) — other (2024, e=14) — www/nginx - Support gRPC proxy in nginx — **adopt in Caddy/HAProxy modules: gRPC proxying**
- [#4696](https://github.com/opnsense/plugins/issues/4696) — feature (2025, e=8) — www/nginx - Allow custom log filenames for HTTP Servers — **community (nginx)**
- [#3397](https://github.com/opnsense/plugins/issues/3397) — support (2023, e=7) — [NGINX] Very slow web GUI access when config has many banned IP addresses — **design avoids (ISS-P-013)**
- [#5125](https://github.com/opnsense/plugins/issues/5125) — feature (2026, e=6) — os-nginx: UI support for advanced configuration and proxy authentication (auth_request) — **adopt in Caddy: forward_auth**
- [#3423](https://github.com/opnsense/plugins/issues/3423) — feature (2023, e=6) — www/nginx Feature: allow enabling underscores_in_headers directive in server block — **community module (nginx)**
- [#5286](https://github.com/opnsense/plugins/issues/5286) — bug (2026, e=5) — nginx custom headers / Authorization-Header — **community module (nginx)**
- [#4396](https://github.com/opnsense/plugins/issues/4396) — other (2024, e=5) — Set "proxy_set_header Host" manually [NGINX] — **community module (nginx)**
- [#3905](https://github.com/opnsense/plugins/issues/3905) — bug (2024, e=5) — os-nginx - possibility to forward also the error_log — **community module (nginx)**
- [#3196](https://github.com/opnsense/plugins/issues/3196) — bug (2022, e=5) — Nginx Upstream won't update in os-nginx 1.31 — **community module (nginx)**
- [#3024](https://github.com/opnsense/plugins/issues/3024) — other (2022, e=5) — Nginx server names are not sanitized — **community module (nginx)**
- [#4080](https://github.com/opnsense/plugins/issues/4080) — bug (2024, e=4) — Two-Stage Rate Limiting — **community module (nginx)**
- [#4023](https://github.com/opnsense/plugins/issues/4023) — bug (2024, e=4) — NGINX - Non default behaviour - files within "root" directory and subfolders are served if no location is defined — **community module (nginx)**
- [#5343](https://github.com/opnsense/plugins/issues/5343) — bug (2026, e=3) — Nginx UI broken — **community module (nginx)**
- [#5280](https://github.com/opnsense/plugins/issues/5280) — bug (2026, e=3) — plugins/www /nginx - GUI: Missing German translation in Security Header admin interface — **community module (nginx)**
- [#4266](https://github.com/opnsense/plugins/issues/4266) — bug (2024, e=3) — [nginx] Enabling Advanced ACLs gives Error 500 — **community module (nginx)**
- [#4152](https://github.com/opnsense/plugins/issues/4152) — support (2024, e=3) — Plugins - Include the version number of the main software the plugin is based on — **community module (nginx)**
- [#3589](https://github.com/opnsense/plugins/issues/3589) — bug (2023, e=3) — Nginx OCSP stapling not possible without ssl_trusted_certificate — **community module (nginx)**
- [#3515](https://github.com/opnsense/plugins/issues/3515) — feature (2023, e=3) — www/nginx Add Permissions-Policy — **community module (nginx)**
- [#3228](https://github.com/opnsense/plugins/issues/3228) — feature (2022, e=3) — www/nginx: Add the respective nginx config parameters to all help messages — **community module (nginx)**
- [#3033](https://github.com/opnsense/plugins/issues/3033) — bug (2022, e=3) — nginx pid not at right place — **community module (nginx)**
- [#2810](https://github.com/opnsense/plugins/issues/2810) — other (2022, e=3) — Nginx dont start after installation — **community module (nginx)**
- [#2790](https://github.com/opnsense/plugins/issues/2790) — bug (2022, e=3) — ModSecurity instead or in addition to NAXSI on Nginx — **adopt (ISS-P-014): Coraza WAF in Caddy**
- [#4410](https://github.com/opnsense/plugins/issues/4410) — bug (2024, e=2) — os-nginx does not write config to file — **community module (nginx)**
- [#4351](https://github.com/opnsense/plugins/issues/4351) — other (2024, e=2) — NGINX - NAXSI new repo with additional rules — **n/a: NAXSI dropped**
- [#4278](https://github.com/opnsense/plugins/issues/4278) — bug (2024, e=2) — NGINX Alway's navigate to Generall Settings, Apply and restart NGINX — **community module (nginx)**
- [#3471](https://github.com/opnsense/plugins/issues/3471) — feature (2023, e=2) — os-nginx - Allow other types than just host and network in trust proxy firewall alias — **community module (nginx)**
- [#3469](https://github.com/opnsense/plugins/issues/3469) — feature (2023, e=2) — Add error_log to remote syslog in Nginx plugin — **community module (nginx)**
- [#3424](https://github.com/opnsense/plugins/issues/3424) — feature (2023, e=2) — www/nginx feature request enabling underscores_in_headers directive in server block — **community module (nginx)**
- [#3007](https://github.com/opnsense/plugins/issues/3007) — other (2022, e=2) — os-nginx: no proxy_redirect parameter setting via GUI — **community module (nginx)**
- [#2877](https://github.com/opnsense/plugins/issues/2877) — feature (2022, e=2) — www/nginx: Feature: Inclusion of a specified config file inclusion into location/server blocks — **community module (nginx)**
- [#2767](https://github.com/opnsense/plugins/issues/2767) — feature (2022, e=2) — [os-nginx] Add support for unix socket upstreams — **community module (nginx)**
- [#4684](https://github.com/opnsense/plugins/issues/4684) — feature (2025, e=1) — os-nginx : Allow changing error page file extension — **community module (nginx)**
- [#4624](https://github.com/opnsense/plugins/issues/4624) — bug (2025, e=1) — www/nginx: Proxy Error with LDAP — **community module (nginx)**
- [#4472](https://github.com/opnsense/plugins/issues/4472) — other (2025, e=1) — High Availability for nginx is not synchronizing removal of settings — **community module (nginx)**
- [#4277](https://github.com/opnsense/plugins/issues/4277) — bug (2024, e=1) — ACME / NGINX Issue Cert on Upstream-Server — **community module (nginx)**
- [#4273](https://github.com/opnsense/plugins/issues/4273) — other (2024, e=1) — [nginx] Set proper Basic Auth realm with Advanced ACLs — **community module (nginx)**
- [#4061](https://github.com/opnsense/plugins/issues/4061) — feature (2024, e=1) — [nginx] Add support for proxy_bind for proxy pass through — **community module (nginx)**
- [#3754](https://github.com/opnsense/plugins/issues/3754) — bug (2024, e=1) — Nginx does not appear to be listening on VPN Tunnel address 23.7.11 with os-nginx 1.32.2 — **community module (nginx)**
- [#3681](https://github.com/opnsense/plugins/issues/3681) — feature (2023, e=1) — www/nginx - Security Headers - add support for Reporting API — **community module (nginx)**
- [#3561](https://github.com/opnsense/plugins/issues/3561) — other (2023, e=1) — os-nginx: SYSLOG Targets: enable JSON — **community module (nginx)**
- [#3360](https://github.com/opnsense/plugins/issues/3360) — bug (2023, e=1) — os-nginx - Rewrite URL with semicolon causes problems — **community module (nginx)**
- [#2809](https://github.com/opnsense/plugins/issues/2809) — bug (2022, e=1) — [os-nginx] Proxy protocol does not apply to ssl, only to plain http, resulting in HTTP 400 errors — **community module (nginx)**

### node_exporter (5)

- [#3906](https://github.com/opnsense/plugins/issues/3906) — feature (2024, e=5) — [os-node_exporter ] Add SMART option to node exporter or option to use textfile collector — **adopt: SMART metrics exported natively**
- [#4275](https://github.com/opnsense/plugins/issues/4275) — feature (2024, e=3) — [node_exporter] Add textcollector in order to fetch more metrics — **adopt: textfile collector**
- [#4337](https://github.com/opnsense/plugins/issues/4337) — other (2024, e=2) — os-node_exporter !=   Prometheus Exporter — **adopt: name it "Prometheus exporter"**
- [#5454](https://github.com/opnsense/plugins/issues/5454) — feature (2026, e=1) — [os-node_exporter] Add textfile collector directory support — **adopt: textfile collector**
- [#4566](https://github.com/opnsense/plugins/issues/4566) — other (2025, e=1) — sysutils/node-exporter is not collecting IPv6 throughput — **adopt: IPv6 counters**

### nrpe (4)

- [#3817](https://github.com/opnsense/plugins/issues/3817) — support (2024, e=5) — NRPE move from package to plugin on 24.1 — **community (nrpe)**
- [#3796](https://github.com/opnsense/plugins/issues/3796) — bug (2024, e=2) — os-nrpe plugin complains when "Listen Address" is empty and fails silently with multiple IPs — **community (nrpe)**
- [#4932](https://github.com/opnsense/plugins/issues/4932) — feature (2025, e=1) — NRPE Plugin doesn't allow for DNS in allowed hosts — **community (nrpe)**
- [#3059](https://github.com/opnsense/plugins/issues/3059) — bug (2022, e=1) — os-nrpe plugin complains when "Listen Address" is empty and fails silently with multiple IPs — **community (nrpe)**

### ntopng (5)

- [#2185](https://github.com/opnsense/plugins/issues/2185) — feature (2021, e=7) — Feature request: ntopng plugin - allow additional settings for ntopng.conf — **community (ntopng)**
- [#3853](https://github.com/opnsense/plugins/issues/3853) — other (2024, e=2) — ntopng listening options (IPv6 / no http) — **community (ntopng)**
- [#4707](https://github.com/opnsense/plugins/issues/4707) — bug (2025, e=1) — net/ntopng plugin certificate configuration fails to pull full certchain — **community (ntopng)**
- [#3587](https://github.com/opnsense/plugins/issues/3587) — other (2023, e=1) — ntopng - Not showing all VLAN interfaces — **community (ntopng)**
- [#3086](https://github.com/opnsense/plugins/issues/3086) — other (2022, e=1) — Ntopng Community Edition — **community (ntopng)**

### nut (22)

- [#3013](https://github.com/opnsense/plugins/issues/3013) — bug (2022, e=15) — sysutils/nut [os-nut]: upsdrvctl shutdown does not get triggered — **adopt: UPS shutdown sequence tested (NUT module)**
- [#2846](https://github.com/opnsense/plugins/issues/2846) — other (2022, e=14) — sysutils/nut: Diagnostics --> UPS Status is empty in service mode standalone — **adopt: diagnostics for standalone mode**
- [#2851](https://github.com/opnsense/plugins/issues/2851) — feature (2022, e=9) — sysutils/nut: add support for timed shutdown with upssched — **adopt: upssched timed shutdown**
- [#1960](https://github.com/opnsense/plugins/issues/1960) — other (2020, e=9) — [FR] NUT - Email-Notifications — **adopt: notifications via core notification system**
- [#803](https://github.com/opnsense/plugins/issues/803) — feature (2018, e=9) — REQUEST:  NUT Widget for Dashboard — **adopt: widget (shipped later)**
- [#3855](https://github.com/opnsense/plugins/issues/3855) — bug (2024, e=7) — nut - lack of customisation - i.e. POWERDOWNFLAG shutting down UPS - cannot remove this flag — **adopt: POWERDOWNFLAG optional**
- [#3304](https://github.com/opnsense/plugins/issues/3304) — other (2023, e=7) — os-nut causes OPNsense web GUI to lock up under certain configurations — **design avoids: UI never blocks on a hung upsc call (timeouts)**
- [#4251](https://github.com/opnsense/plugins/issues/4251) — other (2024, e=5) — [os-nut] configuration incomplete — **adopt: full configuration coverage**
- [#5387](https://github.com/opnsense/plugins/issues/5387) — bug (2026, e=4) — NUT upsd fails to start on boot-up when configured to use APCUPSD-Driver — **adopt: unit ordering**
- [#3646](https://github.com/opnsense/plugins/issues/3646) — bug (2023, e=4) — sysutils/nut - I would like to be able to configure the NUT on a web interface. — **adopt: full UI coverage**
- [#5278](https://github.com/opnsense/plugins/issues/5278) — other (2026, e=3) — sysutils/nut: Support arbitrary users — **adopt: arbitrary users**
- [#3705](https://github.com/opnsense/plugins/issues/3705) — other (2023, e=3) — sysutils/nut -/usr/local/etc/nut/upsd.users is world readable — **design avoids: 0600 secrets files**
- [#3001](https://github.com/opnsense/plugins/issues/3001) — feature (2022, e=3) — sysutils/nut (OS-NUT): add support for the BCMXCP Serial driver — **adopt: BCMXCP serial driver**
- [#5319](https://github.com/opnsense/plugins/issues/5319) — bug (2026, e=2) — os-nut: Netclient option ALARMCRITICAL — **adopt: ALARMCRITICAL**
- [#5277](https://github.com/opnsense/plugins/issues/5277) — other (2026, e=2) — sysutils/nut: Support any UPS in diagnostics page and widget — **adopt: any UPS in widget**
- [#5273](https://github.com/opnsense/plugins/issues/5273) — other (2026, e=2) — sysutils/nut: Only one UPS supported at a time — **adopt: multiple UPS**
- [#4427](https://github.com/opnsense/plugins/issues/4427) — bug (2024, e=2) — OS-Nut on OPNSense 24.7.11 configuration of SNMP-driver results in "Driver not connected"-error (likely due to hardcoded 'monuser' profile name in upsmon.conf) — **adopt: SNMP driver profile**
- [#5300](https://github.com/opnsense/plugins/issues/5300) — bug (2026, e=1) — sysutils/nut: User passwords may contain invalid characters — **design avoids (ISS-P-026)**
- [#5275](https://github.com/opnsense/plugins/issues/5275) — other (2026, e=1) — systutils/nut: Support any arbitrary driver — **adopt: arbitrary driver**
- [#5274](https://github.com/opnsense/plugins/issues/5274) — other (2026, e=1) — sysutils/nut: Only one remote monitor can be used — **adopt: multiple monitors**
- [#3647](https://github.com/opnsense/plugins/issues/3647) — bug (2023, e=1) — sysutils/nut - Permissions issue — **adopt**
- [#3470](https://github.com/opnsense/plugins/issues/3470) — other (2023, e=1) — os-nut: Enable connection to QNAP NAS — **adopt: netclient for NAS**

### openconnect (9)

- [#661](https://github.com/opnsense/plugins/issues/661) — other (2018, e=21) — openconnect changes default route — **adopt: openconnect must not take default route unless asked**
- [#1359](https://github.com/opnsense/plugins/issues/1359) — bug (2019, e=11) — OpenConnect Startup - deletion failed for interface — **adopt**
- [#3699](https://github.com/opnsense/plugins/issues/3699) — bug (2023, e=5) — OpenConnect plugin is in a broken state — **adopt**
- [#4050](https://github.com/opnsense/plugins/issues/4050) — bug (2024, e=3) — openconnect: Start doesn't work after timeout — **adopt: reconnect/timeouts**
- [#4991](https://github.com/opnsense/plugins/issues/4991) — bug (2025, e=2) — os-openconnect  - Unable to configure nonexistent interface opt5 (ocvpn0) — **adopt: interface handling**
- [#3677](https://github.com/opnsense/plugins/issues/3677) — bug (2023, e=2) — openconnect - when setting config paramters manually (the ones not exposed in the GUI)  they are overwritten on each GUI change/save ! — **adopt: custom options preserved**
- [#3091](https://github.com/opnsense/plugins/issues/3091) — feature (2022, e=2) — security/openconnect reconnect feature (bug?) — **adopt: reconnect**
- [#3981](https://github.com/opnsense/plugins/issues/3981) — support (2023, e=1) — What Am I Missing? — **n/a**
- [#3907](https://github.com/opnsense/plugins/issues/3907) — other (2024, e=1) — OpenConnect VPN plugin stoken support required for RSA soft token — **adopt: stoken**

### openvpn-legacy (2)

- [#3600](https://github.com/opnsense/plugins/issues/3600) — bug (2023, e=2) — Correct config for OpenVPN: Client Specific Overrides with Topology P2P in split mode — **n/a: legacy**
- [#3599](https://github.com/opnsense/plugins/issues/3599) — bug (2023, e=2) — Correct config for OpenVPN: Client Specific Overrides with Topology P2P in split mode — **n/a: legacy**

### OPNProxy (5)

- [#5026](https://github.com/opnsense/plugins/issues/5026) — support (2025, e=7) — www/opnproxy - OPNproxy doesn't work at all. — **out of scope: OPNProxy dropped**
- [#4766](https://github.com/opnsense/plugins/issues/4766) — bug (2025, e=2) — opnproxy / squid wrong policy applied — **out of scope**
- [#4033](https://github.com/opnsense/plugins/issues/4033) — bug (2024, e=2) — OPNProxy - Reverse lookup if ip is tried — **out of scope**
- [#4828](https://github.com/opnsense/plugins/issues/4828) — other (2025, e=1) — OPNProxy - Squid - integrate the prometheus squid exporter to expose squid metrics — **out of scope**
- [#4793](https://github.com/opnsense/plugins/issues/4793) — feature (2025, e=1) — OPNProxy Feature Request — **out of scope**

### OPNWAF (3rd-party) (4)

- [#4625](https://github.com/opnsense/plugins/issues/4625) — support (2025, e=6) — os-OPNWAF:  Issue with Exchange Server Publishing via Web Application Firewall on OPNsense — **n/a: third-party OPNWAF**
- [#4584](https://github.com/opnsense/plugins/issues/4584) — feature (2025, e=3) — Feature Request: os-OPNWAF: Server_Aliases / Default Server — **n/a: third-party OPNWAF**
- [#4583](https://github.com/opnsense/plugins/issues/4583) — bug (2025, e=3) — os-OPNWAF: subfolder weren't able to proxy with upper redirect rule — **n/a: third-party OPNWAF**
- [#4527](https://github.com/opnsense/plugins/issues/4527) — other (2025, e=1) — os-OPNWAF geoip under access control — **n/a: third-party OPNWAF**

### postfix (10)

- [#1739](https://github.com/opnsense/plugins/issues/1739) — feature (2020, e=7) — Mail/Postfix add LMTP feature request — **community (postfix): LMTP**
- [#3390](https://github.com/opnsense/plugins/issues/3390) — bug (2023, e=6) — mail/postfix: leaving hostname empty does not use FQDN from Settings -> General — **community (postfix)**
- [#4571](https://github.com/opnsense/plugins/issues/4571) — support (2025, e=5) — Update routine from 25.1.1 to 25.1.2 throws 2 errors postfix-related, after reboot postfix refused to start and unbound needed a forced flush to solve the postfix-log floods of "sender address does not solve" — **community (postfix)**
- [#3251](https://github.com/opnsense/plugins/issues/3251) — feature (2023, e=5) — os-postfix 1.23_3 \| Add ways to edit master.cf using web UI — **community (postfix)**
- [#2830](https://github.com/opnsense/plugins/issues/2830) — bug (2022, e=5) — mail/postfix - outgoing authentication broken under some circumstances — **community (postfix)**
- [#3274](https://github.com/opnsense/plugins/issues/3274) — other (2023, e=4) — [os-postfix] use TLS certificate both for smtpd and smpt connections in postfix plugin — **community (postfix)**
- [#3489](https://github.com/opnsense/plugins/issues/3489) — feature (2023, e=2) — Postfix add missing headers — **community (postfix)**
- [#3147](https://github.com/opnsense/plugins/issues/3147) — bug (2022, e=2) — Postfix as a ms365 smtp-relay — **community (postfix)**
- [#4467](https://github.com/opnsense/plugins/issues/4467) — feature (2025, e=1) — Postfix: add support for -o inet_protocols=ipv4 under just the smtp setting — **community (postfix)**
- [#4151](https://github.com/opnsense/plugins/issues/4151) — other (2024, e=1) — OPNsense Postfix - DKIM Signing & Quarantine Support — **community (postfix): DKIM**

### q-feeds-connector (1)

- [#5223](https://github.com/opnsense/plugins/issues/5223) — bug (2026, e=4) — Unable to create a "new" rule for Q-Feeds — **community (vendor connector)**

### realtek-re (1)

- [#4559](https://github.com/opnsense/plugins/issues/4559) — support (2025, e=3) — os-realtek-re - update Realtek vendor driver — **n/a on Linux**

### redis (3)

- [#4413](https://github.com/opnsense/plugins/issues/4413) — other (2024, e=2) — redis service not locked down — **out of scope: redis dropped**
- [#3676](https://github.com/opnsense/plugins/issues/3676) — bug (2023, e=2) — redis plugin - redis wont start when carp ips in use as it will add duplicate interface IP — **out of scope**
- [#3343](https://github.com/opnsense/plugins/issues/3343) — bug (2023, e=2) — Replace Redis with KeyDB — **out of scope**

### relayd (3)

- [#3849](https://github.com/opnsense/plugins/issues/3849) — bug (2024, e=6) — relayd redirect not working — **out of scope: relayd dropped**
- [#3204](https://github.com/opnsense/plugins/issues/3204) — other (2022, e=5) — relayd not adding pf anchors — **out of scope: relayd dropped**
- [#2922](https://github.com/opnsense/plugins/issues/2922) — other (2022, e=1) — os-relayd: status ui lets you disable the last host in a table but not reenable — **out of scope: relayd dropped**

### rfc2136 (8)

- [#4055](https://github.com/opnsense/plugins/issues/4055) — bug (2024, e=10) — rfc2136: Failed nsupdate breaks cache — **adopt (core DDNS): failed nsupdate must not poison the cache**
- [#5272](https://github.com/opnsense/plugins/issues/5272) — other (2026, e=4) — rfc2136 IPv6 with zoneID — **adopt: IPv6 with zone id**
- [#2752](https://github.com/opnsense/plugins/issues/2752) — bug (2022, e=4) — RFC2136 not updating DNS when address changes — **adopt**
- [#3028](https://github.com/opnsense/plugins/issues/3028) — feature (2022, e=2) — Add more secure algorithms to RFC2136 client — **adopt: modern TSIG algorithms**
- [#2953](https://github.com/opnsense/plugins/issues/2953) — bug (2022, e=2) — rfc2136: Plugin can't update on a non-default port (!= 53) — **adopt: non-default port**
- [#4296](https://github.com/opnsense/plugins/issues/4296) — other (2024, e=1) — rfc2136: Support ipv6 prefix delegation update for static suffix — **adopt: PD-suffix updates**
- [#3896](https://github.com/opnsense/plugins/issues/3896) — bug (2024, e=1) — dns/rfc2136 doesn't log errors in nsupdate invocation — **design avoids (ISS-P-030)**
- [#3701](https://github.com/opnsense/plugins/issues/3701) — feature (2023, e=1) — dns/rfc2136: Do DNS request additionally or instead of cachedipv4 variable — **adopt: query live DNS instead of cache**

### rspamd (5)

- [#3620](https://github.com/opnsense/plugins/issues/3620) — bug (2023, e=2) — rspamd - add missing configuration options. — **community (rspamd)**
- [#3188](https://github.com/opnsense/plugins/issues/3188) — bug (2022, e=2) — mail/rspamd: Add DKIM support to GUI — **community (rspamd): DKIM**
- [#3629](https://github.com/opnsense/plugins/issues/3629) — feature (2023, e=1) — RSPAMD - Configurable Features in WEBGUI — **community (rspamd)**
- [#3621](https://github.com/opnsense/plugins/issues/3621) — other (2023, e=1) — rspamd - virustotal integration — **community (rspamd)**
- [#3108](https://github.com/opnsense/plugins/issues/3108) — other (2022, e=1) — RSPAMD: Field Expiration not applying — **community (rspamd)**

### sftp-backup (2)

- [#5131](https://github.com/opnsense/plugins/issues/5131) — other (2026, e=4) — os-sftp-backup - Version: 1.1_2 - extend default hardcoded upload file permissions from 0600 to 0666 — **adopt: upload permissions option**
- [#4737](https://github.com/opnsense/plugins/issues/4737) — feature (2025, e=3) — Add username/password login to SFTP settings backup — **adopt: password auth for SFTP target**

### shadowsocks (3)

- [#4001](https://github.com/opnsense/plugins/issues/4001) — support (2024, e=4) — Shadowsocks uses deprecated  pcre-8.45_4. — **community (shadowsocks)**
- [#4309](https://github.com/opnsense/plugins/issues/4309) — bug (2024, e=2) — "Mode" GUI option in ShadowSocks Local — **community**
- [#5171](https://github.com/opnsense/plugins/issues/5171) — bug (2026, e=1) — os-shadowsocks udp-over-tcp mode not working — **community**

### siproxd (2)

- [#5409](https://github.com/opnsense/plugins/issues/5409) — bug (2026, e=2) — siproxd issue while adding ip addresses — **community (siproxd)**
- [#5413](https://github.com/opnsense/plugins/issues/5413) — bug (2026, e=1) — siproxd issue while adding ip addresses — **community (siproxd)**

### smart (2)

- [#3513](https://github.com/opnsense/plugins/issues/3513) — support (2023, e=4) — 23.7-RC3 SMART status widget showing extra info that does not make sense — **adopt: SMART widget sanity**
- [#4667](https://github.com/opnsense/plugins/issues/4667) — other (2025, e=1) — os-smart — **adopt**

### squid (16)

- [#4392](https://github.com/opnsense/plugins/issues/4392) — other (2024, e=28) — www/squid - UT1 blacklist not showing category — **community (squid)**
- [#4191](https://github.com/opnsense/plugins/issues/4191) — support (2024, e=7) — os-squid: web proxy does not listen on all configured interfaces on startup — **community (squid)**
- [#4500](https://github.com/opnsense/plugins/issues/4500) — other (2025, e=6) — Workaround for os-squid SIGSEGV — **community (squid)**
- [#4398](https://github.com/opnsense/plugins/issues/4398) — support (2024, e=5) — Squid Web Proxy Service won't start when Remote Blacklist is enable. — **community (squid)**
- [#5366](https://github.com/opnsense/plugins/issues/5366) — support (2026, e=3) — os-squid: Segmentation fault (signal 11) on reload when using tcp_outgoing_address with WireGuard — **community (squid)**
- [#4929](https://github.com/opnsense/plugins/issues/4929) — other (2025, e=3) — OS-Squid - Categories are not shown Remote Access Control List — **community (squid)**
- [#4726](https://github.com/opnsense/plugins/issues/4726) — support (2025, e=3) — os-squid / configuration broken when using it as a transparent proxy — **community (squid)**
- [#4792](https://github.com/opnsense/plugins/issues/4792) — bug (2025, e=2) — Squid-OpnProxy Log Category Details and Alias Support. — **community (squid)**
- [#4781](https://github.com/opnsense/plugins/issues/4781) — bug (2025, e=2) — os-squid HTTPS port only listening on 127.0.0.1 — **community (squid)**
- [#3972](https://github.com/opnsense/plugins/issues/3972) — bug (2024, e=2) — Please add and complete of options for customizing and assigning web proxy and ssl filtering rules — **community (squid)**
- [#3596](https://github.com/opnsense/plugins/issues/3596) — other (2023, e=2) — Squid cache deny for dstdomain list — **community (squid)**
- [#4882](https://github.com/opnsense/plugins/issues/4882) — other (2025, e=1) — www/squid: SSL Inspection blocks CONNECT Reqests making URL based Whitelists unusable — **community (squid)**
- [#4502](https://github.com/opnsense/plugins/issues/4502) — feature (2025, e=1) — WWW/SQUID Squid proxy will block all HTTP request. — **community (squid)**
- [#4397](https://github.com/opnsense/plugins/issues/4397) — bug (2024, e=1) — www/squid - SSL Inspection Error on Firefox ---MOZILLA_PKIX_ERROR_KEY_PINNING_FAILURE — **community (squid)**
- [#4212](https://github.com/opnsense/plugins/issues/4212) — support (2024, e=1) — os-squid — **community (squid)**
- [#2937](https://github.com/opnsense/plugins/issues/2937) — bug (2022, e=1) — [bug] [proxy] The blacklist is not evaluated before thecustom whitelist — **community (squid)**

### sslh (3)

- [#4013](https://github.com/opnsense/plugins/issues/4013) — other (2024, e=4) — SSLH GUI Update — **community (sslh)**
- [#3436](https://github.com/opnsense/plugins/issues/3436) — other (2023, e=4) — net/sslh: Transparent Proxy — **community (sslh)**
- [#3433](https://github.com/opnsense/plugins/issues/3433) — other (2023, e=1) — net/sslh: Configuration of Unused Targets — **community (sslh)**

### strongswan-legacy (1)

- [#4404](https://github.com/opnsense/plugins/issues/4404) — feature (2024, e=1) — Feature Request -- Add dhcp and farp plugins to strongswan. — **adopt (core IPsec): dhcp/farp plugins**

### stunnel (3)

- [#4485](https://github.com/opnsense/plugins/issues/4485) — bug (2025, e=1) — security/stunnel: Service cannot be started when only TLS v1.3 ciphers are enabled — **community (stunnel)**
- [#4483](https://github.com/opnsense/plugins/issues/4483) — feature (2025, e=1) — security/stunnel: Option to specify local bind address — **community (stunnel)**
- [#4175](https://github.com/opnsense/plugins/issues/4175) — bug (2024, e=1) — os-stunnel not starting / status incorrect on 24.7.1 — **community (stunnel)**

### sunnyvalley (2)

- [#3305](https://github.com/opnsense/plugins/issues/3305) — support (2023, e=4) — Zenarmor plugin can't discover interfaces when development deployment type is selected — **n/a: vendor**
- [#5066](https://github.com/opnsense/plugins/issues/5066) — support (2025, e=2) — After the Zenarmor plugin is removed, the main menu entry remains — **design avoids: module uninstall removes menu/ACL entries atomically**

### tailscale (13)

- [#4661](https://github.com/opnsense/plugins/issues/4661) — support (2025, e=80) — os-tailscale: tailscale logged out from opnsense after reboot even though key expiry is disabled — **adopt (ISS-P-017): tailscaled state persisted in /var/lib; key reuse logic tested**
- [#5427](https://github.com/opnsense/plugins/issues/5427) — other (2026, e=7) — [os-tailscale] Tailscale Interface Consistent Flapping — **adopt (ISS-P-017): interface stability**
- [#5411](https://github.com/opnsense/plugins/issues/5411) — other (2026, e=7) — [os-tailscale] Support multiple concurrent Tailscale/Headscale instances — **adopt (ISS-P-024): multiple instances/Headscale**
- [#4434](https://github.com/opnsense/plugins/issues/4434) — other (2024, e=5) — os-tailscale: Static routes related to Tailscale don't survive a reboot — **adopt (ISS-P-017): routes survive reboot**
- [#5029](https://github.com/opnsense/plugins/issues/5029) — other (2025, e=4) — os-tailscale ignores Firewall Rules altogether. — **adopt (ISS-P-017): firewall applies**
- [#4944](https://github.com/opnsense/plugins/issues/4944) — feature (2025, e=3) — Tailscale needs to assign an interface & set firewall rules to allow ICMP on the Tailnet — **adopt (ISS-P-017)**
- [#5412](https://github.com/opnsense/plugins/issues/5412) — bug (2026, e=2) — security/tailscale Not getting advertised routes to OPNSense — **adopt (ISS-P-017)**
- [#5337](https://github.com/opnsense/plugins/issues/5337) — support (2026, e=2) — Tailscale's TUN interface leaves pf groups when recreated — **adopt (ISS-P-017): interface groups survive recreate**
- [#5212](https://github.com/opnsense/plugins/issues/5212) — bug (2026, e=2) — os-tailscale: disabled plugin causes error log spam when visiting the dashboard — **adopt: no log spam when disabled**
- [#5042](https://github.com/opnsense/plugins/issues/5042) — feature (2025, e=2) — security/tailscale: enable feature to avoid interfaces or addresses — **adopt: interface/address exclusions**
- [#5006](https://github.com/opnsense/plugins/issues/5006) — bug (2025, e=2) — os-tailscale Advertised Routes Doesn't — **adopt (ISS-P-017)**
- [#4866](https://github.com/opnsense/plugins/issues/4866) — other (2025, e=2) — os-tailscale: tailscaled CPU usage — **upstream; monitor**
- [#5114](https://github.com/opnsense/plugins/issues/5114) — other (2025, e=1) — Tailscale 1.3: Subnet route changes not advertised — **adopt (ISS-P-017)**

### tayga (3)

- [#5338](https://github.com/opnsense/plugins/issues/5338) — feature (2026, e=4) — [Tayga] Adding support for NAT46 — **adopt: NAT46 (Jool)**
- [#4606](https://github.com/opnsense/plugins/issues/4606) — feature (2025, e=2) — Feature Request: net/tayga support for single-host maps — **adopt: single-host maps**
- [#4088](https://github.com/opnsense/plugins/issues/4088) — bug (2024, e=2) — net/tayga does not correctly handle RFC8215 Local Use Prefixes — **adopt: RFC 8215 prefixes**

### telegraf (19)

- [#4407](https://github.com/opnsense/plugins/issues/4407) — feature (2024, e=6) — Add Loki support to Telegraf interface — **adopt: Loki output**
- [#4094](https://github.com/opnsense/plugins/issues/4094) — other (2024, e=5) — os-telegraf - OpenTelemetry Output configuration — **adopt: OTel output (shipped later)**
- [#4216](https://github.com/opnsense/plugins/issues/4216) — bug (2024, e=4) — Telegraf Fatal Error - /usr/local/bin/telegraf_pfifgw.php — **adopt: no PHP helper scripts**
- [#4118](https://github.com/opnsense/plugins/issues/4118) — feature (2024, e=4) — [os-telegraf] Please add CPU temperature monitoring — **adopt: CPU temperature via sensors in core metrics**
- [#2864](https://github.com/opnsense/plugins/issues/2864) — support (2022, e=4) — os-telegraf : ping6 broken in 22.1 — **n/a on Linux**
- [#1233](https://github.com/opnsense/plugins/issues/1233) — other (2019, e=4) — net-mgmt/telegraf: Incomplete process statistics — **adopt**
- [#4924](https://github.com/opnsense/plugins/issues/4924) — feature (2025, e=3) — Telegraf add local_address to influxdb_v2 — **adopt**
- [#2865](https://github.com/opnsense/plugins/issues/2865) — other (2022, e=3) — os-telegraf : timestamp is in UTC but formatted as local — **adopt: timestamps**
- [#5035](https://github.com/opnsense/plugins/issues/5035) — bug (2025, e=2) — Telegraf Plugin With InfluxDB 2.x and Grafana Dashboard — **adopt: InfluxDB2 docs**
- [#4343](https://github.com/opnsense/plugins/issues/4343) — bug (2024, e=2) — [Telegraf] permissions of /var/unbound/unbound_control.key incompatible with telegraf — **adopt: unbound stats via sensr metrics socket**
- [#4195](https://github.com/opnsense/plugins/issues/4195) — feature (2024, e=2) — os-telegraf: add name_prefix in influxdb config — **adopt**
- [#3339](https://github.com/opnsense/plugins/issues/3339) — bug (2023, e=2) — telegraf plugin not synchronizing config in HA — **adopt (ISS-P-025)**
- [#3137](https://github.com/opnsense/plugins/issues/3137) — other (2022, e=2) — net-mgmt/telegraf: Telegraf plugin sets `--quiet` in the rc script, overriding the UI and config file — **adopt: log level from UI**
- [#4720](https://github.com/opnsense/plugins/issues/4720) — other (2025, e=1) — os-telegraf: extend elasticsearch output options — **adopt**
- [#4406](https://github.com/opnsense/plugins/issues/4406) — feature (2024, e=1) — Add Fluent-bit Support for reporting — **adopt: fluent-bit output**
- [#4243](https://github.com/opnsense/plugins/issues/4243) — feature (2024, e=1) — [Telegraf] Add namepass option to outputs — **adopt: namepass**
- [#4140](https://github.com/opnsense/plugins/issues/4140) — other (2024, e=1) — os-telegraf - Enable Encoding Type for InfluxDB v2 output — **adopt**
- [#3492](https://github.com/opnsense/plugins/issues/3492) — bug (2023, e=1) — Telegraf doesn't handle special characters in passwords — **design avoids (ISS-P-026)**
- [#3248](https://github.com/opnsense/plugins/issues/3248) — bug (2023, e=1) — [os-telegraf] Error in plugin: metric parse error: expected field at 3:239 — **adopt**

### tftp (3)

- [#4734](https://github.com/opnsense/plugins/issues/4734) — bug (2025, e=4) — Can't set TFTP server to listen to IPv6 in `os-tftp` — **adopt: IPv6 listen**
- [#4875](https://github.com/opnsense/plugins/issues/4875) — other (2025, e=2) — [os-tftp] no logging is done — **design avoids (ISS-P-030)**
- [#4043](https://github.com/opnsense/plugins/issues/4043) — feature (2024, e=2) — os-tftp: Listen Address does not allow IPv6 — **adopt: IPv6 listen**

### theme-advanced (1)

- [#4207](https://github.com/opnsense/plugins/issues/4207) — bug (2024, e=10) — os-theme-advanced : Missing "Delete" Icon under System -> Snapshots — **ISS-P-027**

### theme-cicada (5)

- [#3816](https://github.com/opnsense/plugins/issues/3816) — bug (2024, e=6) — ACME certificates command column too narrow, os-theme-cicada & os-theme-rebellion — **ISS-P-027**
- [#4324](https://github.com/opnsense/plugins/issues/4324) — bug (2024, e=2) — [os-theme-cicada] Flashing Firewall Live Log on Dashboard — **ISS-P-027**
- [#3267](https://github.com/opnsense/plugins/issues/3267) — other (2023, e=2) — os-theme-cicada : Low color contrast on Unbound DNS reporting page — **ISS-P-027**
- [#4858](https://github.com/opnsense/plugins/issues/4858) — other (2025, e=1) — os-theme-cicada inconsistent font size for tabulator headers and tables compared to rest of theme — **ISS-P-027**
- [#2910](https://github.com/opnsense/plugins/issues/2910) — other (2022, e=1) — misc/theme-cicada: bottom right corner of some widgets not themed in Google Chrome and Safari — **ISS-P-027**

### theme-flexcolor (1)

- [#5283](https://github.com/opnsense/plugins/issues/5283) — bug (2026, e=2) — flexcolor theme: dashboard editing bug — **ISS-P-027**

### theme-rebellion (6)

- [#4121](https://github.com/opnsense/plugins/issues/4121) — other (2024, e=15) — os-theme-rebellion - enable dark mode for new widgets in 24.7+ dashboard — **ISS-P-027**
- [#4319](https://github.com/opnsense/plugins/issues/4319) — bug (2024, e=3) — [misc - theme-rebellion] Pop-Up title background bright green, text hardly readable — **ISS-P-027**
- [#5219](https://github.com/opnsense/plugins/issues/5219) — bug (2026, e=2) — cicada / rebellion: dnsmasq and theming - delete selected issue with multiple — **ISS-P-027**
- [#4014](https://github.com/opnsense/plugins/issues/4014) — bug (2024, e=2) — rebellion-theme: missing delete button — **ISS-P-027**
- [#3559](https://github.com/opnsense/plugins/issues/3559) — other (2023, e=2) — misc/theme-rebellion, aliases column width to small for buttons, resulting it to '...' — **ISS-P-027**
- [#3768](https://github.com/opnsense/plugins/issues/3768) — other (2024, e=1) — System-Configuration-History unreadable in os-theme-rebellion — **ISS-P-027**

### theme-tukan (1)

- [#4835](https://github.com/opnsense/plugins/issues/4835) — other (2025, e=8) — os-theme-tukan and os-theme-advanced: some lists have alternating colors which are hard to read with OpnSense 25.7 — **ISS-P-027**

### theme-vicuna (2)

- [#3290](https://github.com/opnsense/plugins/issues/3290) — other (2023, e=5) — os-theme-vicuna : Low color contrast on Unbound DNS reporting pages — **ISS-P-027**
- [#3767](https://github.com/opnsense/plugins/issues/3767) — other (2024, e=1) — System-Configuration-History unreadable in os-theme-vicuna — **ISS-P-027**

### themes (3)

- [#4090](https://github.com/opnsense/plugins/issues/4090) — bug (2024, e=9) — New dashboard, add widgets dropdown opens underneith, theme specific, 24.7.b_210 — **ISS-P-027**
- [#4630](https://github.com/opnsense/plugins/issues/4630) — feature (2025, e=4) — Feature Request: Tweak new logos for Cicada and Vicuna themes — **ISS-P-027**
- [#4179](https://github.com/opnsense/plugins/issues/4179) — other (2024, e=1) — Lighten Proofpoint logo SVG to work with dark and light themes — **ISS-P-027**

### tor (14)

- [#961](https://github.com/opnsense/plugins/issues/961) — feature (2018, e=11) — security/tor: Add support for configuring bridges (via ui/torrc custom entries) — **community (tor): bridges**
- [#1379](https://github.com/opnsense/plugins/issues/1379) — support (2019, e=5) — Tor: security optimizing - set *only* listening IP instead of listening interface(+all IPs) — **adopt pattern: listen on IP, not interface**
- [#3500](https://github.com/opnsense/plugins/issues/3500) — feature (2023, e=4) — os-tor: Add the FreeBSD nyx port to the OPNSense ports collection or provide a better tor management tool — **community (tor)**
- [#558](https://github.com/opnsense/plugins/issues/558) — other (2018, e=4) — os-tor exit settings, plus other tweaks — **community (tor)**
- [#3064](https://github.com/opnsense/plugins/issues/3064) — feature (2022, e=2) — [os-tor] - allow to specify outgoing interface — **community (tor)**
- [#2940](https://github.com/opnsense/plugins/issues/2940) — other (2022, e=2) — [TOR] Plugin binding to Virtual IP only when LAN interface selected — **community (tor)**
- [#2938](https://github.com/opnsense/plugins/issues/2938) — feature (2022, e=2) — os-tor: request feature to expose MyFamily config value — **community (tor)**
- [#3968](https://github.com/opnsense/plugins/issues/3968) — other (2024, e=1) — Tor: Select interfaces for OutboundBindAddress — **community (tor)**
- [#3889](https://github.com/opnsense/plugins/issues/3889) — other (2024, e=1) — [os-tor] tor is not able to listen on tailscale interface — **community (tor)**
- [#3690](https://github.com/opnsense/plugins/issues/3690) — other (2023, e=1) — [os-tor] Restart relay on interface address changes — **community (tor)**
- [#3502](https://github.com/opnsense/plugins/issues/3502) — bug (2023, e=1) — os-tor: Setting ControlPort is not working as intended by the package — **community (tor)**
- [#3501](https://github.com/opnsense/plugins/issues/3501) — feature (2023, e=1) — os-tor: Add a configuration option to set the management password — **community (tor)**
- [#3330](https://github.com/opnsense/plugins/issues/3330) — feature (2023, e=1) — [os-tor] relay port (ORPort) field is too restrictive, doesn't allow setting a listen ip — **community (tor)**
- [#3191](https://github.com/opnsense/plugins/issues/3191) — feature (2022, e=1) — security/tor: allow for control port exposure — **community (tor)**

### turnserver (1)

- [#4689](https://github.com/opnsense/plugins/issues/4689) — feature (2025, e=1) — os-turnserver: Feature request: Add support for long term credentials mechanism — **community (coturn)**

### udpbroadcastrelay (9)

- [#3303](https://github.com/opnsense/plugins/issues/3303) — support (2023, e=25) — os-udpbroadcastrelay: not starting when a WireGuard-Interface is selected — **adopt: relay on overlay/VPN interfaces**
- [#2817](https://github.com/opnsense/plugins/issues/2817) — bug (2022, e=5) — UDP Broadcast Relay not working after upgrade to OPNsense 22.1 — **adopt**
- [#5392](https://github.com/opnsense/plugins/issues/5392) — bug (2026, e=3) — os-udpbroadcastrelay: relay port validation error (listen port already in use) — **adopt: validation**
- [#5072](https://github.com/opnsense/plugins/issues/5072) — other (2025, e=3) — os-udpbroadcastrelay: Expose new configuration flags — **adopt: expose flags**
- [#5329](https://github.com/opnsense/plugins/issues/5329) — bug (2026, e=2) — os-udpbroadcastrelay does not start relay process (no process, config present) — **adopt**
- [#5032](https://github.com/opnsense/plugins/issues/5032) — other (2025, e=2) — udpbroadcastrelay delete button not visible (column width too small) — **core grid fixes**
- [#4327](https://github.com/opnsense/plugins/issues/4327) — bug (2024, e=2) — Cicada and udpbroadcastrelay bad CSS — **ISS-P-027**
- [#4256](https://github.com/opnsense/plugins/issues/4256) — other (2024, e=1) — net/udpbroadcastrelay readability on other than default themes — **ISS-P-027**
- [#4108](https://github.com/opnsense/plugins/issues/4108) — other (2024, e=1) — udpbroadcastrelay: support --msearch option — **adopt: msearch**

### unbound-plus (7)

- [#1778](https://github.com/opnsense/plugins/issues/1778) — feature (2018, e=23) — unbound: Allow easier DNS-over-TLS configuration — **adopt (core Unbound): DoT/DoH forwarding (shipped in core)**
- [#1503](https://github.com/opnsense/plugins/issues/1503) — feature (2019, e=13) — unbound: Add possibility to enter Access control and views — **adopt (core Unbound): ACLs/views**
- [#1699](https://github.com/opnsense/plugins/issues/1699) — bug (2020, e=11) — unbound-plus: list parsing problems, not working any more — **n/a: plugin removed**
- [#1802](https://github.com/opnsense/plugins/issues/1802) — bug (2020, e=4) — #Unbound-Plus - Only one DoT server possible — **adopt (core Unbound): multiple DoT servers (shipped in core)**
- [#2887](https://github.com/opnsense/plugins/issues/2887) — feature (2022, e=3) — Feature request: SNMP extend via custom/additional configuration file, a la Unbound — **adopt: custom config includes**
- [#4798](https://github.com/opnsense/plugins/issues/4798) — support (2025, e=1) — Unbound is blocking sites even though no blocklists are enabled — **adopt: clear DNSBL state indication**
- [#4052](https://github.com/opnsense/plugins/issues/4052) — other (2024, e=1) — Unbound activated but not blocking — **adopt**

### upnp (9)

- [#2843](https://github.com/opnsense/plugins/issues/2843) — feature (2022, e=15) — net/upnp UPnP is not responding to requests — **adopt: UPnP core module tests**
- [#3747](https://github.com/opnsense/plugins/issues/3747) — feature (2024, e=13) — os-upnp 1.5_5 - Not able to add port forwards — **adopt: port-forward permission model**
- [#4002](https://github.com/opnsense/plugins/issues/4002) — bug (2024, e=3) — net/upnp: show IPv6 pinholes on status page — **adopt: IPv6 pinholes on status**
- [#3125](https://github.com/opnsense/plugins/issues/3125) — bug (2022, e=3) — UPNP broadcasts on non-LAN interface — **adopt: strict interface binding**
- [#5105](https://github.com/opnsense/plugins/issues/5105) — bug (2025, e=2) — Firewall alias for UPNP forwarded ports  [net/upnp -- UPnP IGD & PCP/NAT-PMP Service] — **adopt: UPnP leases exposed as alias**
- [#4769](https://github.com/opnsense/plugins/issues/4769) — other (2025, e=2) — os-upnp tries NAT-PMP probing on WAN (when shouldn't) — **adopt: no NAT-PMP probing on WAN**
- [#5346](https://github.com/opnsense/plugins/issues/5346) — feature (2026, e=1) — [Feature request] net/upnp - Have option for multiple external interfaces — **adopt: multiple external interfaces**
- [#4004](https://github.com/opnsense/plugins/issues/4004) — other (2024, e=1) — net/upnp: enable LOG_INFO / LOG_DEBUG — **adopt: log levels**
- [#3686](https://github.com/opnsense/plugins/issues/3686) — other (2023, e=1) — net/upnp variable number of rules (instead of just 8) and unparsed "Description" field for each rule — **adopt: unlimited rules with descriptions**

### vmware (1)

- [#3293](https://github.com/opnsense/plugins/issues/3293) — support (2023, e=7) — os-vmware to start the vmware-guestd and vmware-dkmod services on installation. — **design avoids: guest agents enabled by toggle**

### vnstat (5)

- [#3174](https://github.com/opnsense/plugins/issues/3174) — other (2022, e=14) — Vnstat: Statistics tabs not showing — **adopt (core reporting)**
- [#1036](https://github.com/opnsense/plugins/issues/1036) — feature (2018, e=8) — [Feature request] vnstat widget — **adopt: traffic widget (core)**
- [#3688](https://github.com/opnsense/plugins/issues/3688) — bug (2023, e=5) — vnstat: doesn't handle interface alias updates — **design avoids: logical interface names**
- [#4432](https://github.com/opnsense/plugins/issues/4432) — feature (2024, e=3) — VnStat:  Option for VnStat to return structured data from the API requests — **adopt: structured API**
- [#4078](https://github.com/opnsense/plugins/issues/4078) — other (2024, e=1) — [os-vnstat] No stats on WAN interface using 4G dongle — **adopt**

### wazuh-agent (2)

- [#3577](https://github.com/opnsense/plugins/issues/3577) — bug (2023, e=4) — Wazuh plugin issue — **community (wazuh)**
- [#5221](https://github.com/opnsense/plugins/issues/5221) — bug (2026, e=2) — Wazuh agent reading log files, not sending them — **community (wazuh)**

### web-proxy-sso (1)

- [#560](https://github.com/opnsense/plugins/issues/560) — bug (2018, e=11) — www/web-proxy-sso - No Bump Sites — **community (squid sso)**

### wireguard (33)

- [#3658](https://github.com/opnsense/plugins/issues/3658) — support (2023, e=36) — os-wireguard 2.4_1 \| missing route to/from to virtual IPs of type Proxy ARP \| after upgrading OPNsense to 23.7.7 — **adopt (core WireGuard): proxy-ARP VIP routes**
- [#3615](https://github.com/opnsense/plugins/issues/3615) — support (2023, e=32) — os-wireguard 2.3 - CARP - interface remain active — **adopt (ISS-P-016): CARP-owned tunnels**
- [#2524](https://github.com/opnsense/plugins/issues/2524) — feature (2021, e=20) — Add option to make WireGuard service depend on a specific CARP vhid — **adopt (ISS-P-016): depend on CARP vhid**
- [#2927](https://github.com/opnsense/plugins/issues/2927) — bug (2022, e=12) — Please add option to support automatic reconnect when using wireguard with dynamic IP/DNS — **adopt (ISS-P-016): endpoint re-resolution**
- [#3268](https://github.com/opnsense/plugins/issues/3268) — feature (2023, e=9) — WireGuard-Go in the dashboard shown as not running — **n/a: wireguard-go removed**
- [#3325](https://github.com/opnsense/plugins/issues/3325) — other (2023, e=8) — Kernel Wireguard sticks to interface in multi-WAN — **adopt (ISS-P-016): multi-WAN source binding**
- [#3355](https://github.com/opnsense/plugins/issues/3355) — bug (2023, e=6) — Wireguard plugin API call — **adopt: API coverage**
- [#4523](https://github.com/opnsense/plugins/issues/4523) — support (2025, e=5) — os-wireguard rejects new tunnel definition with duplicate key message — **adopt: duplicate-key validation message**
- [#3547](https://github.com/opnsense/plugins/issues/3547) — feature (2023, e=5) — Add logging for os-wireguard — **adopt: logging (kernel wg has none; sensr logs handshakes via netlink)**
- [#2949](https://github.com/opnsense/plugins/issues/2949) — support (2022, e=5) — Wireguard configuration files are not updated on config.xml manual change — **design avoids: config.xml edits are not supported; API is**
- [#3764](https://github.com/opnsense/plugins/issues/3764) — support (2024, e=4) — os-wireguard - notifications for active unassigned endpoints — **adopt: unassigned-endpoint warnings**
- [#3378](https://github.com/opnsense/plugins/issues/3378) — bug (2023, e=4) — Wireguard, show Timestamp in UI under "VPN/Wireguard/Handshakes" — **adopt: handshake timestamps**
- [#3231](https://github.com/opnsense/plugins/issues/3231) — support (2022, e=4) — Interface assignment page doesn't handle offline Wireguard instances correctly. — **adopt: offline instances handled in assignment**
- [#3046](https://github.com/opnsense/plugins/issues/3046) — support (2022, e=4) — Wireguard breaking routing table (insert route incorrectly) — **adopt (ISS-P-016): route insertion rules**
- [#5766](https://github.com/opnsense/plugins/issues/5766) — feature (2026, e=3) — net/amneziawg: proposal, AmneziaWG as a faithful port of the core WireGuard plugin — **community module: AmneziaWG**
- [#3602](https://github.com/opnsense/plugins/issues/3602) — bug (2023, e=3) — Wireguard Tab Missing — **n/a**
- [#3373](https://github.com/opnsense/plugins/issues/3373) — support (2023, e=3) — WireGuard API — **adopt: WireGuard API**
- [#3582](https://github.com/opnsense/plugins/issues/3582) — bug (2023, e=2) — Failed work  wireguard — **n/a**
- [#3212](https://github.com/opnsense/plugins/issues/3212) — other (2022, e=2) — Make Wireguard widget customizable — **adopt: widget options**
- [#3211](https://github.com/opnsense/plugins/issues/3211) — other (2022, e=2) — Wireguard widget overflows when column gets to small — **adopt: responsive widget**
- [#3164](https://github.com/opnsense/plugins/issues/3164) — feature (2022, e=2) — WireGuard: "wg genpsk" command in GUI — **adopt: PSK generator**
- [#3155](https://github.com/opnsense/plugins/issues/3155) — bug (2022, e=2) — net/wireguard: wrong states shown for wireguard firewall rules — **adopt: rule states**
- [#3153](https://github.com/opnsense/plugins/issues/3153) — bug (2022, e=2) — add failover for Wiregaurd plugin — **adopt (ISS-P-016): failover**
- [#5099](https://github.com/opnsense/plugins/issues/5099) — support (2025, e=1) — Wireguard - if no dns is available at service start, tunnel doesnt come up until wireguard service restart — **adopt (ISS-P-016): endpoint DNS retry**
- [#3900](https://github.com/opnsense/plugins/issues/3900) — support (2024, e=1) — os-wireguard - exclude instance or peer configuration from XMLRPC sync. — **adopt (ISS-P-025): per-node sync exclusions**
- [#3857](https://github.com/opnsense/plugins/issues/3857) — other (2024, e=1) — Squid Web Proxy binding to WireGuard Interfaces — **adopt: proxies bind to overlay interfaces**
- [#3723](https://github.com/opnsense/plugins/issues/3723) — support (2023, e=1) — Wireguard VPN prevents PPPOE WAN connection — **adopt: PPPoE + WG ordering**
- [#3717](https://github.com/opnsense/plugins/issues/3717) — support (2023, e=1) — os-wireguard 2.5_2 - CARP - Static route not added — **adopt (ISS-P-016)**
- [#3294](https://github.com/opnsense/plugins/issues/3294) — bug (2023, e=1) — Difference in behaviour in wireguard-kmod vs original in wireguard-go not swapping to alternative gateway when default gateway fails over — **adopt (ISS-P-016): gateway failover re-binding**
- [#3056](https://github.com/opnsense/plugins/issues/3056) — other (2022, e=1) — Endpoint name instead of public key in Wireguard widget — **adopt: endpoint names in widget**
- [#3055](https://github.com/opnsense/plugins/issues/3055) — bug (2022, e=1) — Error message of wireguard endpoint name is misleading — **adopt: clear validation**
- [#3014](https://github.com/opnsense/plugins/issues/3014) — bug (2022, e=1) — net/wireguard - If running in a ha environment the hint to sync to BACKUP is missing after save/apply — **adopt: HA sync hint**
- [#2308](https://github.com/opnsense/plugins/issues/2308) — feature (2021, e=1) — net/wireguard: generate a public key on the fly for an existing private key — **adopt: derive pubkey from private key**

### wol (3)

- [#5145](https://github.com/opnsense/plugins/issues/5145) — bug (2026, e=5) — os-wol - 2.5_3 - WOL packet not work anymore on Intel I226-V — **adopt: WOL on I226 (Linux ethtool wol g)**
- [#2967](https://github.com/opnsense/plugins/issues/2967) — other (2022, e=3) — WOL-Plugin: UDP-Port used needs to be documented or configurable — **adopt: configurable port**
- [#4079](https://github.com/opnsense/plugins/issues/4079) — bug (2024, e=2) — Issue with WoL Packets on Incorrect Port in OPNsense 24.1.6 — **adopt**

### xen (2)

- [#4135](https://github.com/opnsense/plugins/issues/4135) — bug (2024, e=3) — OS-Xen guest utilities fored reboot — **n/a: FreeBSD xen tools**
- [#3312](https://github.com/opnsense/plugins/issues/3312) — bug (2023, e=2) — xcp-ng crashes abter installation of os-xen — **n/a**

### zabbix-agent (2)

- [#2996](https://github.com/opnsense/plugins/issues/2996) — feature (2022, e=6) — zabbix-agent2 support — **adopt: zabbix agent2 default**
- [#4705](https://github.com/opnsense/plugins/issues/4705) — bug (2025, e=5) — Missing Authentication and Privacy Protocol Fields in SNMPv3 Configuration (OPNsense 25.1.6) — **adopt: SNMPv3 fields**

### zabbix-proxy (5)

- [#5400](https://github.com/opnsense/plugins/issues/5400) — bug (2026, e=7) — zabbix7-proxy: Expose ProxyBufferMode and ProxyMemoryBufferSize in GUI — **adopt: proxy buffer options**
- [#5062](https://github.com/opnsense/plugins/issues/5062) — feature (2025, e=3) — net-mgmt/zabbix-proxy: add support for SNMP trapper — **adopt: SNMP trapper**
- [#4803](https://github.com/opnsense/plugins/issues/4803) — other (2025, e=3) — net-mgmt/zabbix-proxy & net-mgmt/zabbix-agent: Update Zabbix Agent/Proxy to 7.4 — **ISS-P-028**
- [#3662](https://github.com/opnsense/plugins/issues/3662) — bug (2023, e=3) — Remote OPNsense / Zabbix Proxy — **adopt**
- [#3713](https://github.com/opnsense/plugins/issues/3713) — bug (2023, e=2) — Zabbix Proxy package : missing Active mode in GUI — **adopt: active mode**

### zerotier (5)

- [#2831](https://github.com/opnsense/plugins/issues/2831) — bug (2022, e=3) — After reboot ,Zerotier stopped working until disable and renable the interface — **adopt (ISS-P-024): zerotier interface persistence**
- [#4011](https://github.com/opnsense/plugins/issues/4011) — feature (2024, e=2) — os-zerotier: Add capability to edit <network-id>.local.conf — **adopt: local.conf editing**
- [#3743](https://github.com/opnsense/plugins/issues/3743) — feature (2024, e=2) — os-zerotier: Unable to add mulitple zerotier networks — **adopt: multiple networks**
- [#4656](https://github.com/opnsense/plugins/issues/4656) — other (2025, e=1) — Firewall rules assigned to interface groups, including ZeroTier interfaces, are disregarded for ZeroTier interfaces after a reboot. — **adopt: interface groups on overlay interfaces after reboot**
- [#1367](https://github.com/opnsense/plugins/issues/1367) — other (2019, e=1) — net/zerotier: Kernel-Panic & Bootloop — **n/a**

Disposition summary for the declined set: adopt 495, community 125, design avoids 57, n/a 29, out of scope 17, upstream/other 3.

## 4. Top 60 most-wanted items by engagement (reactions + comments)

| Rank | # | Plugin | Title | Type | State | Engagement (rx+c) | Shipped in OPNsense? | sensr |
|---:|---|---|---|---|---|---:|---|---|
| 1 | [#2842](https://github.com/opnsense/plugins/issues/2842) | ddclient | os-ddclient Cloudflare API Key | other | closed/not_planned | 87 (38+49) | Yes, later — native backend got Cloudflare API-token support (dns/ddclient lib/account/cloudflare.py) | adopt (ISS-P-004): Cloudflare API tokens are first-class in the native DDNS engine (shipped later in os-ddclient native backend) |
| 2 | [#3094](https://github.com/opnsense/plugins/issues/3094) | wireguard | Request: Netmaker Plugin | feature | open/reopened | 84 (33+51) | No — still open (Netmaker) | adopt (ISS-P-024): Netmaker/Headscale/Netbird self-hosted overlay family as first-party modules |
| 3 | [#259](https://github.com/opnsense/plugins/issues/259) | new-plugin-request | Feature request: Layer2 scanner in diagnostic tools | feature | closed/completed | 81 (0+81) | Yes — ARP/L2 scan moved to core diagnostics | adopt: layer-2/ARP scan in core diagnostics (shipped in core) |
| 4 | [#4661](https://github.com/opnsense/plugins/issues/4661) | tailscale | os-tailscale: tailscale logged out from opnsense after reboot even though key expiry is disabled | support | closed/not_planned | 80 (8+72) | No — closed not_planned as upstream behaviour; still reported | adopt (ISS-P-017): tailscaled state persisted in /var/lib; key reuse logic tested |
| 5 | [#374](https://github.com/opnsense/plugins/issues/374) | nut | Feature Request: NUT plugin w/ UI | feature | closed/completed | 72 (0+72) | Yes — os-nut shipped | adopt: NUT as first-party UPS module |
| 6 | [#2976](https://github.com/opnsense/plugins/issues/2976) | new-plugin-request | Feature Request -- Safe Mode (Auto Rollback Changes if connection lost or not re-established within X time) | feature | closed/not_planned | 68 (13+55) | No — declined; core has no commit-confirm | adopt (ISS-P-022): commit-confirm / auto-rollback in core |
| 7 | [#3827](https://github.com/opnsense/plugins/issues/3827) | squid | www/squid: recent segmentation faults in squid binary | other | closed/completed | 62 (2+60) | Yes — squid rebuilt/fixed upstream | community module (squid) |
| 8 | [#4262](https://github.com/opnsense/plugins/issues/4262) | crowdsec | Reboot held up by Crowdsec refusing to stop | other | open/reopened | 62 (14+48) | No — open, upstream | design avoids (ISS-P-018): systemd TimeoutStopSec bounded for every module; a service can never hold a reboot |
| 9 | [#1303](https://github.com/opnsense/plugins/issues/1303) | freeradius | freeradius 1.9.2 broke configuration after update to opnsense 19.1.6 | bug | closed/completed | 51 (0+51) | Yes | adopt |
| 10 | [#1947](https://github.com/opnsense/plugins/issues/1947) | frr | net/frr7 - completely broken in 20.7 | support | closed/completed | 51 (5+46) | Yes — FRR7 fixed in 20.7.x | adopt |
| 11 | [#467](https://github.com/opnsense/plugins/issues/467) | shadowsocks | shadowsocks for opnsense | feature | closed/completed | 49 (0+49) | Yes — os-shadowsocks | community module (shadowsocks / sing-box) |
| 12 | [#1972](https://github.com/opnsense/plugins/issues/1972) | frr | os-frr: No support for authentication in BGP | feature | closed/not_planned | 48 (4+44) | Yes, later — neighbour password in os-frr | adopt (ISS-P-007): BGP MD5/TCP-AO neighbour authentication (shipped later in os-frr) |
| 13 | [#1591](https://github.com/opnsense/plugins/issues/1591) | rspamd | OPNsense 19.7.7. / Rspamd: IPv6 IO write error - duplicated mails | bug | closed/completed | 45 (0+45) | Yes | community module (rspamd) |
| 14 | [#1868](https://github.com/opnsense/plugins/issues/1868) | wireguard | net/wireguard: Generate QR-Code with qrencode? | other | closed/completed | 45 (9+36) | Yes — QR code in core WireGuard | adopt |
| 15 | [#2050](https://github.com/opnsense/plugins/issues/2050) | frr | FRR - ADD  BFD feature on web interface | feature | closed/completed | 45 (0+45) | Yes — BFD tab | adopt |
| 16 | [#5181](https://github.com/opnsense/plugins/issues/5181) | nextcloud-backup | os-nextcloud-backup 1.1 changes modus operandi and causes problems for existing backup schemes | feature | open/None | 44 (4+40) | No — open (behaviour change debate) | adopt (ISS-P-021): retention and naming behaviour must be configurable and migration-safe |
| 17 | [#1564](https://github.com/opnsense/plugins/issues/1564) | dyndns | DynDNS: Invalid argument supplied for foreach() | bug | closed/completed | 43 (1+42) | Yes | adopt |
| 18 | [#230](https://github.com/opnsense/plugins/issues/230) | quagga | Track: FRR Quagga fork | feature | closed/completed | 42 (0+42) | Yes — os-frr | adopt: FRR is the core routing stack |
| 19 | [#246](https://github.com/opnsense/plugins/issues/246) | siproxd | Feature Request: siproxd integration | feature | closed/completed | 42 (1+41) | Yes — os-siproxd | community module (siproxd) |
| 20 | [#2013](https://github.com/opnsense/plugins/issues/2013) | haproxy | net/haproxy: site redirects fails with ERR_HTTP2_SERVER_REFUSED_STREAM with LibreSSL | bug | closed/completed | 42 (0+42) | Yes — moved off LibreSSL | adopt |
| 21 | [#974](https://github.com/opnsense/plugins/issues/974) | bind | os-bind - Thoughts Features | feature | closed/completed | 41 (2+39) | Partly — host overrides/DNSBL added, chaining remains | adopt |
| 22 | [#615](https://github.com/opnsense/plugins/issues/615) | openvpn-legacy | OSPF config file with multiple OpenVPN needs more details | other | closed/completed | 40 (0+40) | Yes — per-interface OSPF settings | n/a (legacy / vendor / FreeBSD-specific / not a plugin issue) |
| 23 | [#583](https://github.com/opnsense/plugins/issues/583) | monit | Monit does not update | bug | closed/completed | 38 (0+38) | Yes | adopt |
| 24 | [#769](https://github.com/opnsense/plugins/issues/769) | haproxy | haproxy multiselect menus messed up after 18.7 update | bug | closed/completed | 38 (0+38) | Yes | adopt |
| 25 | [#3658](https://github.com/opnsense/plugins/issues/3658) | wireguard | os-wireguard 2.4_1 \| missing route to/from to virtual IPs of type Proxy ARP \| after upgrading OPNsense to 23.7.7 | support | closed/not_planned | 36 (0+36) | No — closed as support | adopt (core WireGuard): proxy-ARP VIP routes |
| 26 | [#466](https://github.com/opnsense/plugins/issues/466) | rspamd | mail/rspamd: Daemon sometimes doesn't start after reboot | bug | closed/completed | 34 (0+34) | Yes | community module (rspamd) |
| 27 | [#578](https://github.com/opnsense/plugins/issues/578) | frr | Feature Request: BGP IPv6 | feature | closed/completed | 34 (1+33) | Yes — BGP IPv6 | adopt |
| 28 | [#964](https://github.com/opnsense/plugins/issues/964) | nut | NUT:Blazer_ser driver permission | bug | closed/completed | 34 (0+34) | Yes | adopt |
| 29 | [#1014](https://github.com/opnsense/plugins/issues/1014) | dnscrypt-proxy | Feature Request: dnscrypt plugin support for squid transparent proxy | feature | closed/completed | 33 (0+33) | Yes | adopt |
| 30 | [#2550](https://github.com/opnsense/plugins/issues/2550) | acme-client | security/acme-client: Lets Encrypt certificates are provided by obsolete DST Root CA X3 | bug | closed/completed | 33 (0+33) | Yes | adopt |
| 31 | [#2554](https://github.com/opnsense/plugins/issues/2554) | acme-client | Let's Encrypt SSL certificates are being linked to an expired root certificate | other | closed/completed | 33 (0+33) | Yes | adopt |
| 32 | [#3233](https://github.com/opnsense/plugins/issues/3233) | ddclient | os-ddclient - Ability to choose IPv4 or IPv6 or IPv4/IPv6 for each entry | feature | closed/not_planned | 33 (10+23) | Partly — native backend has per-account v4/v6 types, not a single-entry toggle | adopt (ISS-P-004): per-entry IPv4/IPv6/both |
| 33 | [#96](https://github.com/opnsense/plugins/issues/96) | net-snmp | SNMP: Support for SNMPv3 | feature | closed/completed | 32 (1+31) | Yes — SNMPv3 in os-net-snmp | adopt: SNMPv3 in core SNMP agent |
| 34 | [#346](https://github.com/opnsense/plugins/issues/346) | frr | net/frr: ospfd generated rules should be extended | bug | closed/completed | 32 (0+32) | Yes | adopt |
| 35 | [#3615](https://github.com/opnsense/plugins/issues/3615) | wireguard | os-wireguard 2.3 - CARP - interface remain active | support | closed/not_planned | 32 (0+32) | No — closed as support; CARP-WG remains a design gap | adopt (ISS-P-016): CARP-owned tunnels |
| 36 | [#1488](https://github.com/opnsense/plugins/issues/1488) | virtualbox | Virtualbox guest additions | feature | closed/completed | 30 (0+30) | Yes — os-virtualbox | adopt: guest-agent toggle in core |
| 37 | [#3127](https://github.com/opnsense/plugins/issues/3127) | acme-client | security/acme-client: duplicate Common Names break acme.sh configuration | bug | closed/completed | 30 (0+30) | Yes | adopt |
| 38 | [#318](https://github.com/opnsense/plugins/issues/318) | freeradius | net/freeradius: add daily session limit feature to FreeRADIUS and GUI | feature | closed/completed | 29 (0+29) | Yes | adopt |
| 39 | [#866](https://github.com/opnsense/plugins/issues/866) | wireguard | opnsense-wireguard will not stop or restart properly | bug | closed/completed | 29 (0+29) | Yes | adopt |
| 40 | [#1494](https://github.com/opnsense/plugins/issues/1494) | haproxy | net/haproxy Rules in backends or frontends are not sortable | bug | closed/completed | 29 (0+29) | Yes — sortable rules | adopt |
| 41 | [#1951](https://github.com/opnsense/plugins/issues/1951) | wireguard | plugins/net/wireguard configuration reload support | feature | closed/completed | 29 (2+27) | Yes — reload instead of restart | adopt |
| 42 | [#2428](https://github.com/opnsense/plugins/issues/2428) | dyndns | Dynamic DNS (dyndns) - FreeDNS Update broken | bug | closed/completed | 29 (0+29) | Yes | adopt |
| 43 | [#4223](https://github.com/opnsense/plugins/issues/4223) | caddy | Caddy - Allow Access list selection for Handlers to be able to block certain paths from the internet. | feature | closed/completed | 29 (0+29) | Yes — Caddy access lists on handlers | adopt |
| 44 | [#276](https://github.com/opnsense/plugins/issues/276) | c-icap | possible core issue in service start order: c-icap + clamav | bug | closed/completed | 28 (0+28) | Yes | community module (c-icap) |
| 45 | [#292](https://github.com/opnsense/plugins/issues/292) | freeradius | net/freeradius: feature Improvements | feature | closed/completed | 28 (0+28) | Yes | adopt |
| 46 | [#1105](https://github.com/opnsense/plugins/issues/1105) | isc-dhcp | Feature: DHCP server able to handle non-interface configured subnets | feature | closed/completed | 28 (1+27) | Yes | adopt (core Kea DHCP): serve non-interface subnets for relay/HA appliance use |
| 47 | [#2587](https://github.com/opnsense/plugins/issues/2587) | haproxy | net/haproxy: Request logging not working | feature | closed/completed | 28 (1+27) | Yes | adopt |
| 48 | [#4392](https://github.com/opnsense/plugins/issues/4392) | squid | www/squid - UT1 blacklist not showing category | other | closed/not_planned | 28 (0+28) | No — declined (UT1 categories) | community (squid) |
| 49 | [#4579](https://github.com/opnsense/plugins/issues/4579) | netdata | add: Beszel agent plugin | other | closed/not_planned | 28 (16+12) | No — declined (Beszel) | community module: Beszel agent |
| 50 | [#507](https://github.com/opnsense/plugins/issues/507) | new-plugin-request | Feature request: modsecurity WAF for reverse proxy and WebUI itself | feature | closed/completed | 27 (0+27) | Partly — NAXSI in nginx, OPNWAF third-party; no modsecurity | adopt (ISS-P-014): Coraza WAF in the Caddy module |
| 51 | [#1326](https://github.com/opnsense/plugins/issues/1326) | dnscrypt-proxy | dnscrypt crashing | support | closed/completed | 27 (0+27) | Yes | adopt |
| 52 | [#3831](https://github.com/opnsense/plugins/issues/3831) | upnp | Indefinitely duplicated ip/port in os-upnp | other | closed/completed | 27 (2+25) | Yes | adopt |
| 53 | [#3872](https://github.com/opnsense/plugins/issues/3872) | caddy | www/caddy - Issue tracker for DNS Providers | support | closed/completed | 27 (0+27) | Yes — tracker, providers added over time | adopt |
| 54 | [#4662](https://github.com/opnsense/plugins/issues/4662) | shadowsocks | os-shadowsocks uses deprecated FreeBSD port shadowsocks-libev instead of using current shadowsocks-rust | other | closed/completed | 27 (2+25) | Yes — shadowsocks-rust | community module (shadowsocks) |
| 55 | [#4934](https://github.com/opnsense/plugins/issues/4934) | netbird | Netbird package doesn't start | bug | closed/not_planned | 27 (0+27) | No — declined as help wanted | adopt (ISS-P-024): netbird start regression tests |
| 56 | [#175](https://github.com/opnsense/plugins/issues/175) | haproxy | haproxy check interval not from UI setting | bug | closed/completed | 26 (0+26) | Yes | adopt |
| 57 | [#1092](https://github.com/opnsense/plugins/issues/1092) | freeradius | [freeradius] Support for remote MySQL database | feature | closed/completed | 26 (2+24) | Yes — MySQL in freeradius | adopt |
| 58 | [#2440](https://github.com/opnsense/plugins/issues/2440) | dnscrypt-proxy | DNSCrypt-Proxy logs no longer available in WebGUI | bug | closed/completed | 26 (2+24) | Yes | adopt |
| 59 | [#627](https://github.com/opnsense/plugins/issues/627) | frr | net/frr: update to FRR 5 | feature | closed/completed | 25 (0+25) | Yes | adopt |
| 60 | [#877](https://github.com/opnsense/plugins/issues/877) | bind | os-bind advanced config | other | closed/completed | 25 (0+25) | Yes — advanced config | adopt |

Observations: 50 of the top 60 were eventually shipped at least partly (several only years later, e.g. BGP neighbour passwords and peer groups, Cloudflare API tokens, the NUT widget); 10 never were. The never-shipped high-engagement items cluster around five themes sensr should own from day one: **(1)** mesh/overlay VPNs as real interfaces (Netmaker #3094, Tailscale state loss #4661, Netbird start #4934), **(2)** HA/CARP-aware services (WireGuard #3615, BGP source #3179, UDP relay on VPN interfaces #3303), **(3)** commit-confirm / safe mode (#2976), **(4)** reliable dynamic DNS (#2842, #3233, #3017), **(5)** services that must not block shutdown (#4262).

## 5. Per-plugin health and what it says about sensr's module boundaries

Bug pressure = bug-type issues per year of plugin life; declined share = not_planned / total. Both computed from the table in 1.5.

| Plugin | Issues | bugs | bugs/yr | declined share | help wanted never done | upstream-labelled | Diagnosis |
|---|---:|---:|---:|---:|---:|---:|---|
| acme-client | 397 | 128 | 10.7 | 11% | 44 | 40 | Not "buggy acme.sh" — it is **integration drift**: 400+ DNS-API hooks tracked as a frozen snapshot, renewal state inferred from files on disk, HTTP-01 via pf rdr to localhost, deploy automations as shell scripts. 40 of 94 `upstream` labels in the tracker are here. → core, with a native ACME client and an event bus. |
| frr | 224 | 54 | 5.4 | 24% | 53 | 4 | Two bug classes dominate: (a) **apply = restart**, dropping BGP/OSPF sessions; (b) **model gaps** (route-map/prefix-list/peer-group/auth options added one PR at a time over 8 years, 78 help-wanted). 24 cleanup labels show constant churn with FRR upstream versions. → core routing with a complete declarative model and frr-reload. |
| haproxy | 219 | 68 | 6.2 | 5% | 10 | 6 | Highest completion rate of the big plugins (90%) thanks to a dedicated maintainer; remaining pain is **template generation failures surfaced only in backend logs**, boot-vs-apply divergence, cert reload after ACME, rule ordering. → first-party module; copy the maintainer discipline. |
| nginx | 197 | 75 | 8.3 | 21% | 41 | 0 | 42 not_planned, 76 help-wanted never done; feature requests are an endless list of nginx directives to expose, plus a WAF (NAXSI) nobody maintains. Overlaps HAProxy and Caddy. → community module; sensr's WAF story is Coraza-in-Caddy. |
| ddclient | 155 | 55 | 6.1 | 50% | 74 | 3 | **Worst declined share of any major plugin (50%)**: 77 help-wanted never done, provider after provider (dynv6, no-ip, cloudns, Linode, Azure, GoDaddy, deSEC, TransIP, regfish, bunny.net…), plus multi-WAN/CARP semantics. Perl ddclient breaks with every provider API change. → core DDNS engine with providers as data. |
| caddy | 125 | 31 | 3.4 | 21% | 7 | 4 | Youngest big plugin, 78% completed, only 12 help-wanted-never-done, 17 cleanup. Its DNS-provider tracker (#3872) and layer-4 model are the healthiest patterns in the repo. → first-party and the default reverse proxy. |
| wireguard | 120 | 33 | 3.7 | 30% | 28 | 1 | Plugin-era history (now core): CARP ownership, DNS-name endpoints at boot, restart-on-save, multi-WAN binding, missing logs. 36 not_planned mostly "support". → informs core VPN design (ISS-P-016). |
| freeradius | 102 | 39 | 3.9 | 27% | 24 | 1 | 40 help-wanted never done; recurring **secret/char escaping** bugs (`%`, `,`, `@`, `:`), EAP/TLS option gaps, MAB fallback regressions in 2026. → first-party with a typed config renderer. |
| bind | 101 | 31 | 3.4 | 41% | 40 | 1 | Zone-file regeneration under a running named with dynamic updates loses records and serials (5 issues, 2 open); 51 help-wanted never done = long option tail (views, DNS64, also-notify, RP, ports). → first-party, driven through RFC2136/rndc. |
| dyndns | 94 | 39 | 3.9 | 7% | 6 | 4 | Legacy PHP DDNS, removed; 48 help-wanted. Same lessons as ddclient. |
| core-misfiled/other | 79 | 22 | 1.8 | 16% | 12 | 0 |  |
| new-plugin-request | 68 | 2 | 0.2 | 21% | 13 | 0 |  |
| telegraf | 66 | 20 | 2.0 | 32% | 19 | 0 | Output-plugin tail (Loki, OTel, fluent-bit), privilege problems reading pf counters, HA sync. → first-party. |
| nut | 60 | 27 | 2.7 | 37% | 22 | 1 | Hard-coded single UPS / single user / driver list; 30 help-wanted never done (upssched, notifications, arbitrary drivers). → first-party UPS module designed general from the start. |
| postfix | 54 | 16 | 1.6 | 19% | 10 | 0 | Steady small stream of directive requests; mail relay is niche on a firewall. → community. |
| git-backup | 41 | 19 | 2.7 | 34% | 13 | 0 | 26 bugs of 41 issues; silent failures, SSH URL handling, single branch, secrets in repo. Every backup plugin (git/nextcloud/sftp/gdrive/mail) reinvents triggers and failure reporting. → one core backup-targets engine (ISS-P-021). |
| upnp | 41 | 10 | 1.0 | 24% | 9 | 3 | Still legacy PHP pages; port-forward permission model and multi-WAN gaps. → core. |
| crowdsec | 39 | 17 | 3.4 | 31% | 12 | 4 | 30% not_planned; the stand-out is a service that blocks reboot (#4262, 48 comments). → first-party with bounded stop timeouts and proxy bouncers. |
| dnscrypt-proxy | 37 | 11 | 1.2 | 27% | 10 | 0 | Option-exposure tail (lb_strategy, skip_incompatible, http_proxy, blocklists). Most users only want DoT/DoH forwarding → core Unbound; keep as first-party for DNSCrypt/anonymised DNS. |
| squid | 36 | 14 | 1.4 | 44% | 16 | 3 | 44% not_planned, SIGSEGV threads, SSL-bump complaints; OPNsense itself demoted it. → community. |
| OPNWAF (3rd-party) | 35 | 5 | 1.7 | 11% | 4 | 0 |  |
| zabbix-agent | 35 | 7 | 0.7 | 9% | 2 | 1 | Healthy (83% completed) but plugin forks per Zabbix major version (zabbix6/7/74) are a packaging smell. → first-party, versions pinned in NixOS. |
| tor | 34 | 9 | 0.9 | 41% | 14 | 0 | 41% not_planned; binding/bridge/control-port option tail. → community. |
| firewall-api | 31 | 6 | 0.7 | 32% | 9 | 0 |  |
| tailscale | 29 | 5 | 1.2 | 45% | 13 | 0 | 45% not_planned and 8 open in 2026: state lost after reboot, `tailscale up` clobbering preferences, firewall bypass, HA. Fast-moving upstream CLI semantics. → first-party, drive via LocalAPI. |
| zabbix-proxy | 29 | 8 | 0.9 | 21% | 5 | 0 |  |
| quagga | 29 | 8 | 0.9 | 0% | 0 | 0 | Replaced by frr; 0 not_planned because it was simply retired. |
| zerotier | 27 | 6 | 0.7 | 19% | 5 | 1 | Interface persistence after reboot, multiple networks. → first-party overlay family. |
| nextcloud-backup | 26 | 12 | 1.3 | 42% | 11 | 0 | 42% not_planned, 1.1 behaviour change controversy (#5181, 40 comments). → core backup engine. |
| openconnect | 25 | 9 | 1.1 | 36% | 9 | 0 | Default-route hijack, reconnect, interface naming. → first-party VPN client. |
| unbound-plus | 24 | 6 | 0.7 | 29% | 7 | 0 | Retired; its DoT/ACL/views requests landed in core Unbound. |
| intrusion-detection-content | 22 | 9 | 0.9 | 23% | 5 | 0 | Rule-source freshness and loading errors. → first-party rule-source registry inside core IDS. |
| net-snmp | 20 | 6 | 0.6 | 25% | 5 | 2 | bsnmpd/net-snmp duplication (#3680), SNMPv3 field gaps, MIB missing. → core SNMP agent. |
| tinc | 20 | 11 | 1.0 | 0% | 0 | 0 | 100% completed, zero declined — tiny stable user base. → community. |
| rspamd | 20 | 8 | 1.1 | 25% | 5 | 0 | Last issue 2023; dormant. → community. |
| mdns-repeater | 19 | 6 | 0.6 | 63% | 11 | 0 | 63% not_planned: no IPv6, CARP, filters, multiple instances. → first-party, Avahi-based. |
| monit | 19 | 5 | 0.5 | 5% | 1 | 0 | Moved to core; health monitor lessons (cron schedules, integer validation). |
| ntopng | 18 | 7 | 0.8 | 28% | 5 | 1 | Heavy, upstream-driven regressions (InfluxDB flood, disk writes). → community. |
| relayd | 18 | 9 | 1.0 | 17% | 3 | 0 | OpenBSD tool; 4 cleanup, pf anchor issues. → drop on Linux. |

### 5.1 Cross-cutting bug classes (what the plugin tracker is really about)

Reading the open and declined sets, most plugin bugs are not about the wrapped daemon at all; they are **framework bugs that every plugin re-implements**:

1. **Config rendering without types** — list fields serialised as dicts (haproxy #5690), CSV fields that cannot hold `[::]:53` (dnscrypt #5486), secrets with `%`/`,`/`@`/`#` breaking files (freeradius #5696/#5678/#4548/#5117, telegraf #3492, nut #5300, net-snmp #4704), CRLF in generated configs (acme #3032), comma-joined resolvers in TOML (#5162). One typed renderer with per-format escaping removes the whole class (ISS-P-026).
2. **Apply = restart** — frr (#4898, #3939, #3846), wireguard pre-core (#1951), bind on every link-up (#5916), squid reload calling a non-existent rc verb (#5710, #5811). Services need declared reload semantics and event subscriptions scoped to the interfaces they use (ISS-P-006, ISS-P-020).
3. **Boot path ≠ apply path** — haproxy (#5576, #4314), bind-before-nginx (#3302), c-icap-before-clamd (#276), wireguard-before-DNS (#3203, #5099), freeradius-with-DHCP (#3261), tailscale state (#4661/#5903). systemd ordering plus idempotent "reconcile" instead of separate start/apply scripts (ISS-P-010).
4. **Status derived from "process is running"** — ddclient widget green on failure (#5879), git-backup silently failing (#4739), haproxy startup errors invisible (#3562), acme logs empty (#4217). Every module must report *outcome* state.
5. **HA sync without per-node fields** — net-snmp listen IP (#5479), tayga (#5503), telegraf (#3339), nginx (#4472), wireguard exclusions (#3900), netbird failover (#5023), mdns/CARP (#2919, #3369), igmp-proxy CARP (#5118), DDNS after failback (#5718, #4429). (ISS-P-025)
6. **Services that can hold the box hostage** — crowdsec blocking reboot (#4262), NUT locking the GUI (#3304), configd 120 s socket timeout on long DNSBL rebuilds (#5923). Bounded timeouts and async jobs (ISS-P-018).
7. **Secrets in logs/backups** — DuckDNS token in syslog (#5863), root password in git backup (#3775), world-readable upsd.users (#3705), passwords saved in HTML (#4956/#4957).
8. **Version coupling to upstream** — FRR 10.6.1 regressions (#5515, #5652), Zabbix 7.4/8.0 variants (#4803, #5665), Squid SIGSEGV (#3827), ntopng 7.0 (#5898), Caddy losing DNS modules on rebuild (#4539), shadowsocks-libev EOL (#4662). NixOS pinning + per-module regression suite (ISS-P-028).
9. **Themes** — 6 theme plugins generate ~50 contrast/visibility issues every time core changes markup. A token-based design system with built-in dark mode ends this (ISS-P-027).
10. **Logging** — a dozen issues are "plugin X does not log / does not reach remote syslog" (acme #4665, crowdsec #3666, nginx #3905/#3469, freeradius #3990, tftp #4875, cloudflared #5818, rfc2136 #3896). Modules get journald + structured forwarding for free (ISS-P-030).

### 5.2 Core vs module: the decision rule used in section 6

A capability goes into **sensr core** when (a) the tracker shows it is expected by most firewall users, (b) it needs tight coupling to interfaces/CARP/firewall state that plugins repeatedly got wrong, or (c) splitting it off created duplicate implementations (bsnmpd vs net-snmp, dyndns vs ddclient vs rfc2136, five backup plugins, six themes). It becomes a **first-party module** when it is a real daemon with its own user base and the plugin history shows a sustainable maintainer model (haproxy, caddy, bind, freeradius, crowdsec, nut, telegraf, zabbix, overlays). **Community** covers niche or declining daemons where OPNsense itself accumulated mostly `help wanted` debt (nginx, squid family, postfix/rspamd, tor, tinc, monitoring agents). **Drop** = no Linux equivalent needed, dead upstream, or vendor-specific.

## 6. Plugin-tier recommendation for sensr (every plugin directory)

Tiers: **core** = built into sensr; **first-party** = optional module built and released by the sensr project; **community** = module API supported, maintained outside the core team; **drop** = not carried; **n/a** = not applicable on Linux/NixOS or not a user-facing plugin.

| Directory | PLUGIN_COMMENT | Issues | open | Tier | Rationale |
|---|---|---:|---:|---|---|
| `benchmarks/iperf` | Connection speed tester | 11 | 0 | **core** | Diagnostics tool; auto-open firewall for the test window. |
| `databases/redis` | Redis DB | 7 | 0 | **drop** | Only a dependency (squid/OPNProxy); never user-facing. |
| `devel/debug` | Debugging Tools | 2 | 0 | **n/a** | Developer tooling lives in the sensr SDK/dev shell. |
| `devel/grid_example` | A sample framework application | 0 | 0 | **n/a** | SDK example module. |
| `devel/helloworld` | A sample framework application | 1 | 0 | **n/a** | SDK example module. |
| `dns/bind` | BIND domain name service | 101 | 8 | **first-party** | Authoritative DNS module; manage dynamic zones via RFC2136/rndc instead of regenerating zone files (#5931 class of bugs). |
| `dns/ddclient` | Dynamic DNS client | 155 | 10 | **core** | Dynamic DNS belongs in core (155+94+13 issues across ddclient/dyndns/rfc2136). Native Rust provider framework, per-entry v4/v6, gateway-group/CARP aware. |
| `dns/dnscrypt-proxy` | Flexible DNS proxy supporting DNSCrypt and DoH | 37 | 3 | **first-party** | Encrypted upstream DNS; also fold DoT/DoH forwarding into core Unbound so most users never need it. |
| `dns/rfc2136` | RFC-2136 Support | 13 | 0 | **core** | Fold into the core dynamic-DNS engine as the "nsupdate" provider. |
| `emulators/qemu-guest-agent` | QEMU Guest Agent for OPNsense | 7 | 1 | **core** | Guest agents are a System > Virtualization toggle (NixOS services.qemuGuest / vmware / xe-guest / virtualbox). |
| `ftp/tftp` | TFTP server | 7 | 1 | **first-party** | Small; IPv6 listen and logging. |
| `mail/postfix` | SMTP mail relay | 54 | 4 | **community** | Mail relay on a firewall is niche; keep as community module. |
| `mail/rspamd` | Protect your network from spam | 20 | 0 | **community** | Pairs with postfix. |
| `misc/theme-advanced` | Theme based on AdvancedTomato GUI | 1 | 0 | **drop** | Themes become a core design-token system with built-in dark mode; no theme plugins. |
| `misc/theme-cicada` | The cicada theme - dark grey onyx | 14 | 1 | **drop** | See theme-advanced. |
| `misc/theme-flexcolor` | Theme with 3 different color schemes: black as default, light and dark-light | 1 | 0 | **drop** | See theme-advanced. |
| `misc/theme-rebellion` | A suitably dark theme | 12 | 0 | **drop** | See theme-advanced. |
| `misc/theme-tukan` | The tukan theme - blue/white | 2 | 0 | **drop** | See theme-advanced. |
| `misc/theme-vicuna` | The vicuna theme - blue sapphire | 5 | 2 | **drop** | See theme-advanced. |
| `net-mgmt/collectd` | Collect system and application performance metrics periodically | 7 | 0 | **community** | Legacy; telegraf covers. |
| `net-mgmt/lldpd` | LLDP allows you to know exactly on which port is a server | 9 | 0 | **core** | LLDP neighbours in the interface diagnostics; management-IP and custom config exposed. |
| `net-mgmt/net-snmp` | Net-SNMP is a daemon for the SNMP protocol | 20 | 1 | **core** | SNMP v2c/v3 agent is a core management feature (replaces bsnmpd+net-snmp split, see #3680). |
| `net-mgmt/netdata` | Real-time performance monitoring | 14 | 0 | **community** | Heavy agent; core metrics endpoint instead. |
| `net-mgmt/nrpe` | Execute nagios plugins | 9 | 2 | **community** | Nagios NRPE; community. |
| `net-mgmt/telegraf` | Agent for collecting metrics and data | 66 | 1 | **first-party** | Metrics shipper (InfluxDB/OTel/Loki outputs); runs with least privilege but with access to pf-equivalent counters. |
| `net-mgmt/zabbix-agent` | Zabbix monitoring agent | 35 | 2 | **first-party** | Zabbix agent2; version variants pinned via NixOS instead of plugin forks. |
| `net-mgmt/zabbix-proxy` | Zabbix monitoring proxy | 29 | 1 | **first-party** | Zabbix proxy with SNMP trapper/active mode/buffer options. |
| `net/chrony` | Chrony time synchronisation | 14 | 0 | **core** | NTP is already core in OPNsense (ntpd); sensr ships chrony with keys/NTS/orphan/makestep exposed. |
| `net/cloudflared` | Cloudflare Tunnel integration | 4 | 1 | **community** | Cloudflare tunnel; small. |
| `net/firewall-legacy` | Firewall rules legacy support | 0 | 0 | **n/a** | Legacy PHP firewall pages; sensr is MVC/API-first from day one. |
| `net/freeradius` | RADIUS Authentication, Authorization and Accounting Server | 102 | 5 | **first-party** | RADIUS server for 802.1X/MAB/captive portal; strict escaping of secrets in generated config. |
| `net/frr` | The FRRouting Protocol Suite | 224 | 7 | **core** | Dynamic routing (BGP/OSPF/OSPFv3/BFD/RIP/static) is a firewall core function. Drive FRR via frr-reload (incremental) instead of restarting daemons; full route-map/prefix-list model. |
| `net/ftp-proxy` | Control ftp-proxy processes | 4 | 0 | **drop** | pf ftp-proxy; Linux uses the nf_conntrack_ftp helper (core NAT option). |
| `net/google-cloud-sdk` | Google Cloud SDK | 1 | 0 | **drop** | Broken (#4946), no reason to ship a cloud CLI on a firewall. |
| `net/haproxy` | Reliable, high performance TCP/HTTP load balancer | 219 | 11 | **first-party** | Load balancer/reverse proxy module (219 issues, high engagement). Validate config before apply, hitless reload, cert hot-reload from the cert store, ordered rules with full ACL expressions. |
| `net/igmp-proxy` | IGMP-Proxy Service | 12 | 2 | **core** | Multicast proxy with quickleave toggle, per-interface whitelist, CARP-aware. |
| `net/isc-dhcp` | ISC DHCPv4/v6 server | 8 | 1 | **n/a** | ISC DHCP is EOL; sensr core DHCP is Kea (plus dnsmasq for small sites). Carry over the PD-route (#5824) and non-interface-subnet (#1105) lessons. |
| `net/mdns-repeater` | Proxy multicast DNS between networks | 19 | 1 | **first-party** | mDNS/DNS-SD reflector using Avahi reflector (IPv6, filters, CARP-aware). |
| `net/ndp-proxy-go` | IPv6 Neighbor Discovery Protocol (NDP) Proxy | 1 | 0 | **core** | Linux has kernel proxy_ndp/ndppd; expose as an IPv6 interface option, not a plugin. |
| `net/netflector` | Reflect link-local service discovery between interfaces | 0 | 0 | **first-party** | Link-local service-discovery reflector (merge with mDNS module). |
| `net/ntopng` | Traffic Analysis and Flow Collection | 18 | 2 | **community** | Heavy; sensr core flow reporting (NetFlow/IPFIX) covers most needs. |
| `net/radsecproxy` | RADIUS proxy provides both RADIUS UDP and TCP/TLS (RadSec) transport | 2 | 0 | **community** | RadSec proxy; pairs with FreeRADIUS. |
| `net/realtek-re` | Realtek re(4) vendor driver | 2 | 1 | **n/a** | FreeBSD vendor driver; Linux r8169/r8125 in-kernel. |
| `net/relayd` | Relayd Load Balancer | 18 | 0 | **drop** | OpenBSD relayd; on Linux HAProxy/Caddy cover it. 18 issues, declining. |
| `net/shadowsocks` | Secure socks5 proxy | 9 | 0 | **community** | Censorship-circumvention proxy; community (with sing-box/xray requests #5836). |
| `net/siproxd` | Siproxd is a proxy daemon for the SIP protocol | 6 | 0 | **community** | SIP proxy; niche, stale. |
| `net/sslh` | sslh configuration front-end | 4 | 0 | **community** | Protocol demultiplexer; niche. |
| `net/tayga` | Tayga NAT64 | 9 | 2 | **first-party** | NAT64 (prefer Jool on Linux; NAT46 and single-host maps). |
| `net/turnserver` | The coturn STUN/TURN Server | 6 | 0 | **community** | coturn; niche. |
| `net/udpbroadcastrelay` | Control udpbroadcastrelay processes | 12 | 0 | **first-party** | UDP broadcast relay with msearch, WireGuard interfaces allowed. |
| `net/upnp` | UPnP IGD & PCP/NAT-PMP Service | 41 | 3 | **core** | miniupnpd (IGD/PCP/NAT-PMP) with nftables backend; rules as first-class objects, multiple external interfaces, IPv6 pinholes on status page. |
| `net/vnstat` | Network traffic monitor | 16 | 1 | **core** | Per-interface traffic accounting is a core reporting feature (use nftables counters + own time series instead of vnstat). |
| `net/wol` | Wake on LAN Service | 15 | 1 | **core** | Diagnostics tool (IPv6-only interfaces, configurable port). |
| `net/zerotier` | Virtual Networks That Just Work | 27 | 0 | **first-party** | Overlay VPN family. |
| `security/acme-client` | ACME Client | 397 | 18 | **core** | ACME is part of the certificate store: built-in client (Rust ACME lib), DNS-01 providers as data, renewal state tracked in the trust store, deploy hooks on an event bus. 397 issues = the single biggest plugin pain point. |
| `security/clamav` | Antivirus engine for detecting malicious threats | 10 | 0 | **community** | Follows squid/c-icap. |
| `security/crowdsec` | Lightweight and collaborative security engine | 39 | 5 | **first-party** | Collaborative IPS with nftables bouncer; stop-timeout bounded so it never blocks reboot; proxy bouncers for Caddy/HAProxy. |
| `security/etpro-telemetry` | ET Pro Telemetry Edition | 16 | 0 | **community** | Vendor telemetry programme; only if Proofpoint partnership exists. |
| `security/intrusion-detection-content-at-antiphishing` | Anti-phishing rules | 2 | 1 | **first-party** | IDS rule source with dataset files. |
| `security/intrusion-detection-content-et-open` | IDS Proofpoint full ET open ruleset complementary subset for ET Pro Telemetry edition | 2 | 0 | **first-party** | IDS rule sources are a core IDS feature (rule-source registry), not separate packages. |
| `security/intrusion-detection-content-et-pro` | IDS Proofpoint ET Pro ruleset (needs a valid subscription) | 2 | 0 | **first-party** | IDS rule source (subscription). |
| `security/intrusion-detection-content-pt-open` | IDS Positive Technologies ESC ruleset | 0 | 0 | **first-party** | IDS rule source. |
| `security/intrusion-detection-content-snort-vrt` | IDS Snort VRT ruleset (needs registration or subscription) | 1 | 0 | **first-party** | IDS rule source (subscription). |
| `security/maltrail` | Malicious traffic detection system | 12 | 2 | **drop** | Stale upstream, 13 issues incl. "save does not save". |
| `security/netbird` | Peer-to-peer VPN that seamlessly connects your devices | 13 | 1 | **first-party** | Overlay VPN family. |
| `security/openconnect` | OpenConnect Client | 25 | 0 | **first-party** | VPN client (AnyConnect/ocserv) as a WAN-type interface, stoken support. |
| `security/openvpn-legacy` | OpenVPN legacy support | 11 | 1 | **n/a** | Legacy OpenVPN pages; sensr ships only the instance model. |
| `security/q-feeds-connector` | Connector for Q-Feeds threat intel | 15 | 2 | **community** | Vendor threat-intel connector; generic "threat feed -> alias/DNSBL" API in core instead. |
| `security/strongswan-legacy` | IPsec legacy support | 4 | 1 | **n/a** | Legacy IPsec tunnel pages; sensr ships only swanctl connections. |
| `security/stunnel` | Stunnel TLS proxy | 9 | 0 | **community** | TLS wrapper; niche. |
| `security/tailscale` | VPN mesh securely connecting clients using WireGuard | 29 | 8 | **first-party** | Mesh VPN family (tailscale/netbird/zerotier) share one "overlay VPN" module shape: real interface, firewall-ruleable, state preserved across reboot, Headscale support. |
| `security/tinc` | Tinc VPN | 20 | 0 | **community** | Legacy mesh VPN; superseded by WireGuard overlays. |
| `security/tor` | The Onion Router | 34 | 2 | **community** | Tor relay/client; 34 issues, mostly binding/bridge options. |
| `security/wazuh-agent` | Agent for the open source security platform Wazuh | 10 | 2 | **community** | SIEM agent; community. |
| `sysutils/apcupsd` | APCUPSD - APC UPS daemon | 4 | 0 | **community** | Superseded by NUT module (apcupsd driver supported there). |
| `sysutils/beats` | Send logs, network, metrics and heartbeat to Elasticsearch | 0 | 0 | **community** | Elastic beats shipper. |
| `sysutils/cpu-microcode` | CPU microcode updates | 3 | 0 | **core** | NixOS hardware.cpu.*.updateMicrocode; a checkbox in System. |
| `sysutils/dec-hw` | Deciso hardware specific information | 2 | 0 | **n/a** | Deciso hardware specifics. |
| `sysutils/dmidecode` | Display hardware information on the dashboard | 4 | 0 | **core** | Hardware info on dashboard is core. |
| `sysutils/gdrive-backup` | Backup configurations using Google Drive | 1 | 0 | **core** | Backend of the unified backup-targets engine. |
| `sysutils/git-backup` | Track config changes using git | 41 | 6 | **core** | Unified "config backup targets" engine: git / sftp / s3 / nextcloud-webdav / gdrive / mail backends, encryption, secret-free export, status API, retention. |
| `sysutils/hw-probe` | Collect hardware diagnostics | 0 | 0 | **core** | Hardware diagnostics export is core support tooling. |
| `sysutils/lcdproc-sdeclcd` | LCDProc for SDEC LCD devices | 2 | 0 | **community** | Hardware-specific LCD; community (full lcdproc requested #5374). |
| `sysutils/mail-backup` | Send configuration file backup by e-mail | 2 | 0 | **core** | Backend of the unified backup-targets engine. |
| `sysutils/munin-node` | Munin monitoring agent | 0 | 0 | **community** | Legacy monitoring. |
| `sysutils/nextcloud-backup` | Track config changes using NextCloud | 26 | 3 | **core** | Backend (WebDAV) of the unified backup-targets engine. |
| `sysutils/node_exporter` | Prometheus exporter for machine metrics | 10 | 0 | **core** | Built-in Prometheus/OpenMetrics endpoint (sensr exports its own metrics; textfile collector dir supported). |
| `sysutils/nut` | Network UPS Tools | 60 | 0 | **first-party** | UPS module: arbitrary drivers/users, multiple UPS, upssched, notifications, widget. Merge apcupsd use-cases. |
| `sysutils/puppet-agent` | Manage Puppet/OpenVox Agent | 1 | 0 | **community** | Config management agent (NixOS makes it less relevant). |
| `sysutils/sftp-backup` | Backup configurations using SFTP | 8 | 0 | **core** | Backend of the unified backup-targets engine. |
| `sysutils/smart` | SMART tools | 15 | 1 | **core** | Disk health in the core hardware/health page with graphs. |
| `sysutils/virtualbox` | VirtualBox guest additions | 1 | 0 | **core** | Same virtualization toggle. |
| `sysutils/vmware` | VMware tools | 3 | 0 | **core** | Same virtualization toggle. |
| `sysutils/xen` | Xen guest utilities | 7 | 0 | **core** | Same virtualization toggle. |
| `vendor/sunnyvalley` | Vendor Repository for Zenarmor - Enterprise SASE & SSE platform (NGFW, SWG, CASB, ZTNA, SD-WAN) | 5 | 1 | **n/a** | Zenarmor vendor repo; third-party decision. |
| `www/c-icap` | c-icap connects the web proxy with a virus scanner | 15 | 0 | **community** | Follows squid. |
| `www/cache` | Webserver cache | 3 | 0 | **drop** | Inert web-cache helper, 3 issues. |
| `www/caddy` | Modern Reverse Proxy with Automatic HTTPS, Dynamic DNS and Layer4 Routing | 125 | 2 | **first-party** | Default simple reverse proxy with automatic HTTPS and layer-4; low bug ratio, strong maintainer model worth copying. |
| `www/nginx` | Nginx HTTP server and reverse proxy | 197 | 12 | **community** | Overlaps HAProxy+Caddy; 197 issues, 76 help-wanted never done, NAXSI WAF dead-end. Keep as community module; WAF via Coraza in Caddy instead. |
| `www/OPNProxy` | OPNsense proxy additions | 9 | 1 | **drop** | Commercial squid access-control add-on; 9 issues, "doesn't work at all" (#5026). |
| `www/squid` | Squid is a caching proxy for the web | 36 | 2 | **community** | Forward proxy is declining (OPNsense demoted it too); community module without SSL-bump promises. |
| `www/web-proxy-sso` | Kerberos authentication module | 4 | 0 | **community** | Kerberos SSO for squid. |

Historic / removed plugins seen in the tracker:

| Plugin (historic) | Issues | Tier | Rationale |
|---|---:|---|---|
| wireguard | 120 | **core** | Already core in OPNsense since 24.1; 120 plugin-era issues (CARP ownership, DNS endpoints, restart-on-save) feed the core VPN design. |
| dyndns | 94 | **core** | Removed legacy DDNS; merged into core dynamic-DNS engine. |
| quagga | 29 | **core** | Predecessor of frr. |
| unbound-plus | 24 | **core** | DoT/views/ACL features are core Unbound options. |
| monit | 19 | **core** | Moved to core in OPNsense; sensr: health monitor built on systemd + own checks. |
| arp-scan | 6 | **core** | Layer-2 scan is a core diagnostics tool. |
| firewall-api | 31 | **core** | os-firewall API plugin was folded into core; sensr is API-first. |
| web-proxy-useracl | 4 | **drop** | Squid ACL helper. |
| boot-delay | 0 | **n/a** | FreeBSD boot ordering hack. |
| speedtest / l2tp / softether / fetchmail / apuled / intel-ix | 7 | **drop** | Never merged or removed. |

Tier totals over the 102 directories: community 28, core 27, first-party 24, drop 13, n/a 10. New-plugin proposals still open (checkmk, tang, S3 backup, xray/sing-box, ONT widget, Gatus, Newt, WARP, VEP1400, Splunk HEC, wanquota, policy analyzer, sonar, mDNS-bridge, Avahi reflector, AmneziaWG, gpsd, lcdproc, switchtracker, Zeek, Beszel, Netmaker) are dispositioned in sections 2 and 3; S3 backup, Splunk HEC, wanquota, policy analyzer, sonar, mDNS reflector and Netmaker/Headscale belong in core or first-party, the rest are community candidates.

## 7. The 30 most impactful items (stable IDs)

| ID | Finding | Plugin(s) | Evidence (issues) | sensr tier | Design response |
|---|---|---|---|---|---|
| ISS-P-001 | ACME renewal must be decided from the trust store, not the file acme.sh wrote | acme-client | #5746 #5852 #4711 #4908 #5086 #5497 #3127 | core | Renewal date computed from the on-disk cert; certs renewed but never imported/deployed; "every year I must reset ACME". sensr: ACME orders are state machines persisted in the cert store; renewal = (store cert NotAfter − window) ∧ last deploy succeeded; failed deploys alert. |
| ISS-P-002 | DNS-01 providers as data, versioned with the ACME library | acme-client | #3897 #3845 #4062 #3073 #3590 #5373 #5899 #5388 #3800 #4347 + ~60 provider requests | core | 400+ acme.sh hooks frozen per release break when provider APIs change; UI fields lag acme.sh. sensr: provider descriptors (auth fields, zone lookup, TXT create/delete) in a data file, contract-tested, hot-updatable without a release; nsupdate/local-BIND provider built in. |
| ISS-P-003 | HTTP-01 answered natively, no rdr to loopback | acme-client | #5730 #4963 #3864 #1967 #5228 #3023 | core | pf rdr to 127.0.0.1 is dropped by the kernel; lighttpd snippets required; IPv6-only hosts fail. sensr: the management HTTP listener serves `/.well-known/acme-challenge` on the chosen interfaces (v4+v6) for the order duration. |
| ISS-P-004 | Native dynamic-DNS engine with per-entry v4/v6 and token auth | ddclient / dyndns / rfc2136 | #2842 (e=87) #3233 (e=33) #3017 #2798 #2880 #2892 #2844 #5232 #3069 #5324 #5289 | core | Perl ddclient breaks per provider; tokens, v4/v6 split, multiple hostnames, @/* hosts all declined for years. sensr: Rust engine, provider descriptors, per-hostname record set (A/AAAA), explicit change detection per family. |
| ISS-P-005 | Dynamic DNS is multi-WAN and CARP aware | ddclient | #2899 #4895 #5718 #4429 #5578 #2921 #3076 | core | Monitored source must be a gateway group or specific interface; failback resets the cache; status shows which node updated. Updates compare to provider state, not local cache. |
| ISS-P-006 | Routing config applies incrementally (frr-reload), never by restarting daemons | frr | #4898 #3939 #3846 #1951(wg) #5916(bind) | core | Any change (even a static route) restarts FRR and drops all BGP/OSPF sessions. sensr: generate frr.conf, diff with frr-reload.py semantics, apply via vtysh; static routes through staticd. |
| ISS-P-007 | Complete declarative BGP/OSPF model (auth, peer groups, route-map/prefix-list algebra) | frr | #1972 (e=48) #1006 #3630 #3100 #3099 #2944 #2952 #3926 #3372 #3508 #5038 #2202 #5314 | core | Eight years of one-option-per-PR. sensr: model the FRR grammar subset explicitly (neighbour auth, peer-group inheritance, route-map entries with N match/N set, prefix/AS-path/community lists, confederation, remove-private-AS, BFD strict) and generate from it. |
| ISS-P-008 | Kernel FIB and routing RIB must agree after boot | frr | #5897 #5624 #3520 #3366 | core | OSPF routes "installed" in zebra but missing from FIB after reboot; static routes not applied; null routes invisible. sensr: single owner (staticd/zebra) for all non-connected routes, post-boot consistency check, routing table UI reads the kernel. |
| ISS-P-009 | Routing follows CARP state | frr | #3179 #5496 #5362 #3178 #5918 | core | BGP source address unpredictable with CARP VIPs; demotion does not change metrics. sensr: update-source selectable per neighbour (VIP or address), CARP demotion hooks into route-map weights/metrics. |
| ISS-P-010 | Validate before commit; boot path = apply path | haproxy (+all) | #3562 #5690 #5576 #4314 #3385 #5626(bind) #276 #3302 #3203 | core framework | Startup errors only in backend log; template generation failures as a red banner; manual start needed after reboot. sensr: every module implements `render → validate (daemon -c) → commit → reconcile`; the same reconcile runs at boot under systemd ordering. |
| ISS-P-011 | Certificate changes propagate through an event bus | acme-client ↔ haproxy/nginx/caddy | #4203 #5039 #5445 #2248 #2628 | core | Renewed cert not served until manual restart; HA sync of certs fails. sensr: cert store emits `cert.updated`; consumers hot-reload (HAProxy runtime API, Caddy admin API); HA sync carries the store. |
| ISS-P-012 | Reverse-proxy rules have stable ordering and real condition expressions | haproxy | #2584 #1494 #5709 #3950 #4391 | first-party | Rules reorder when unrelated objects change; conditions limited to one ACL. sensr: explicit sequence numbers per parent, boolean expression trees over named ACLs, drag-and-drop ordering as a core grid feature (#5896). |
| ISS-P-013 | Runtime state (bans, leases, caches) never lives in the configuration | nginx (+upnp, ddclient) | #4577 #3397 #942 #5105 | core framework | Autoblock bans written into config.xml slow the whole GUI and flood the config history. sensr: runtime store with TTL, exposed as aliases, excluded from backups. |
| ISS-P-014 | WAF via Coraza in the Caddy module, not NAXSI/ModSecurity in nginx | nginx / OPNWAF | #2790 #507 #5656 #4351 + 35 OPNWAF issues | first-party | NAXSI is unmaintained and returns 200 on block; the only maintained WAF (OPNWAF/Apache+ModSecurity) is a third-party repo with its own 35 issues. sensr: Coraza (OWASP CRS) as a Caddy handler. |
| ISS-P-015 | Caddy is the default reverse proxy; its DNS-provider tracker model is the template | caddy | #3872 #4223 #4747 #4612 #4642 #4095 #4539 | first-party | Healthiest plugin in the repo (78% completed). sensr: Caddy module with layer-4, access lists (nested groups, #5623), forward_auth, encode, per-domain DNS providers, built with a pinned xcaddy module list. |
| ISS-P-016 | WireGuard tunnels are CARP-owned, re-resolve endpoints and bind per WAN | wireguard (now core) | #3615 (e=32) #2524 #3717 #2927 #5099 #3203 #3325 #3294 #3046 #3153 #3658 | core | Tunnel stays up on the BACKUP node; DNS-name endpoints fail at boot; sticks to one WAN. sensr: optional CARP vhid dependency, endpoint re-resolution on handshake timeout, fwmark/source policy per gateway, handshake log via netlink. |
| ISS-P-017 | Overlay VPNs (Tailscale/Netbird/ZeroTier) are real interfaces with persistent state | tailscale / netbird / zerotier | #4661 (e=80) #5631 #5903 #5029 #5593 #5878 #4434 #5337 #4934 #5023 #2831 #4656 | first-party | Logged out after reboot; `tailscale up` resets preferences; traffic bypasses firewall; routes/interface groups lost on recreate. sensr: state in /var/lib, config via LocalAPI/`tailscale set`, stable interface names registered as firewall interfaces, HA-aware. |
| ISS-P-018 | No service may block shutdown; proxy bouncers for CrowdSec | crowdsec | #4262 (e=62) #4294 #4923 #5848 #5587 #3304(nut) #5923 | first-party | CrowdSec refuses to stop and holds reboots for minutes. sensr: TimeoutStopSec per unit, KillMode, async long jobs; CrowdSec module ships nftables bouncer + Caddy/HAProxy SPOA bouncers; alias creation independent of other aliases. |
| ISS-P-019 | Authoritative DNS zones are mutated via RFC2136/rndc, never regenerated under a live named | bind | #5931 #5816 #4789 #3314 #4352 #5068 #3225 | first-party | Static records added to dynamic zones vanish; deletes do not bump serial; journals corrupt on reboot. sensr: zone content changes go through nsupdate with TSIG; serial managed by named; `rndc freeze/thaw` only for full reloads. |
| ISS-P-020 | Services subscribe to interface events only for interfaces they use | bind (+many) | #5916 #3958 #5581 #5551 #3690(tor) | core framework | BIND restarted on every link-up anywhere; dnscrypt stops daily; Unbound not rebinding after overlay comes up. sensr: event bus with interface-scoped subscriptions; reload (not restart) handlers. |
| ISS-P-021 | One encrypted, secret-free, status-reporting backup-targets engine | git/nextcloud/sftp/gdrive/mail-backup | #5181 (e=44) #4464 #3775 #5833 #5872 #5605 #4739 #2994 #5296 #5744 #2893 #4318 #3405 #4731 #5500 | core | Five plugins, each with its own trigger, failure mode and secret handling; silent failures; passwords in repos; single branch for all nodes. sensr: core engine with pluggable targets (git, S3, SFTP, WebDAV/Nextcloud, GDrive, mail), client-side encryption, secret-free export, retention, status API, alerts on failure, per-node naming. |
| ISS-P-022 | Commit-confirm / safe mode | core (requested in plugins) | #2976 (e=68) | core | Declined for OPNsense. sensr: every apply can be armed with a rollback timer that reverts unless confirmed from a working session (also solves "25.7.8 update killed LAN-to-LAN" class). |
| ISS-P-023 | API-first firewall model (gateway groups, aliases, staged vs applied state) | firewall-api | #1720 #1749 #3139 #2879 #3197 #3581 #4786 | core | The os-firewall API plugin lagged the GUI for years (no gateway groups, no SNAT, false-positive reads). sensr: single model serves GUI and API; responses carry staged/applied revision; threat feeds as alias sources. |
| ISS-P-024 | Self-hosted overlay controllers (Netmaker, Headscale, Netbird) as first-party modules | wireguard / tailscale | #3094 (e=84) #5411 #4934 | first-party | Most-reacted open issue in the tracker. sensr: overlay family shares one module shape; Headscale/Netbird server URL configurable; multiple instances. |
| ISS-P-025 | HA config sync supports per-node overrides | net-snmp, tayga, telegraf, nginx, wireguard, netbird, mdns, igmp, ddclient | #5479 #5503 #3339 #4472 #3900 #5023 #2919 #3369 #5118 #5718 | core | Listen addresses, node names and CARP roles are copied verbatim to the backup, breaking services there. sensr: every field can be marked node-local; modules declare CARP-follow behaviour. |
| ISS-P-026 | Typed configuration rendering with per-format escaping | freeradius, telegraf, nut, net-snmp, haproxy, dnscrypt, acme | #5696 #5678 #4548 #5117 #2933 #3492 #5300 #4704 #5690 #5486 #5162 #3032 | core framework | Secrets and list fields break generated files. sensr: Rust typed models → serde-style emitters (INI/TOML/YAML/radius/haproxy) with escaping owned by the emitter; forms never reject valid characters. |
| ISS-P-027 | Design-token theming with built-in dark mode; no theme plugins | theme-* (6 plugins, ~50 issues) | #4121 #5564 #5572 #5600 #4207 #3816 #4090 #5921 #5912 | core | Every core markup change breaks six themes (contrast, missing buttons, flashing). sensr: CSS tokens, light/dark/high-contrast in core, user themes as token overrides. |
| ISS-P-028 | Upstream versions pinned per release with per-module regression suites | frr, zabbix, squid, ntopng, caddy, shadowsocks, crowdsec | #5515 #5652 #4803 #5665 #859 #3827 #5898 #4539 #4662 #5438 | core (NixOS) | Plugin forks per upstream major (zabbix6/7/74), FRR point releases breaking BGP, Caddy losing modules on rebuild. sensr: NixOS pins, overlay patches, e2e tests (BGP peering, Zabbix handshake) in CI before bump. |
| ISS-P-029 | mDNS/DNS-SD reflector with IPv6, filters, CARP and multiple instances | mdns-repeater / netflector / udpbroadcastrelay | #3352 #2919 #4430 #3418 #5739 #5904 #3369 #4585 #3303 #4108 | first-party | mdns-repeater is IPv4-only, single instance, CARP-blind; 63% of its issues declined. sensr: Avahi reflector (or mdns-bridge) with record-type filters, IPv6, CARP follow; UDP broadcast relay with msearch and overlay interfaces. |
| ISS-P-030 | Structured logging for every module by default | acme, crowdsec, nginx, freeradius, tftp, cloudflared, rfc2136, dnscrypt, haproxy | #4665 #4217 #3119 #3666 #3905 #3469 #3990 #4875 #5818 #3896 #5016 #4564 #5534 | core framework | "Plugin X does not log / does not reach remote syslog" is a recurring issue per plugin. sensr: all daemons under systemd → journald with module tags; remote forwarding, retention and the log viewer come from core. |

### 7.1 Priority order for sensr

Phase 1 (core foundations that remove whole bug classes): ISS-P-010, -026, -020, -025, -030, -028, -022, -027.
Phase 2 (core features the plugin tracker proves are expected): ISS-P-001…-005 (certificates + dynamic DNS), -006…-009 (routing), -011, -013, -016, -021, -023.
Phase 3 (first-party modules): ISS-P-012/-015 (HAProxy/Caddy), -014 (WAF), -017/-024 (overlays), -018 (CrowdSec), -019 (BIND), -029 (mDNS).
