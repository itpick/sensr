# 05 — Business-tier features: what OPNsense Business Edition / Deciso add-ons offer, what competitors add, and how sensr should implement them

Status: research + design sketch (2026-11-15). Companion to the core-feature research docs (01–04); every item below assumes the core firewall/VPN/DHCP/DNS/HA features exist first and refers to them by name.

Source conventions used in this document:

- `docs:<path>` = file in the OPNsense documentation repo (github.com/opnsense/docs, `source/` tree; a local checkout was used). The same page is published at `https://docs.opnsense.org/<path-without-.rst>.html`.
- Web sources are given as URLs. Claims that came only from marketing pages or forum posts are flagged as such.

---

## 1. What "Business Edition" actually is

OPNsense Business Edition (BE) is not a different code base. It is (a) a separate, slower release train built from a community release plus "additional reliability improvements", (b) a commercial package repository that carries a handful of closed-source Deciso plugins, and (c) a bundle of non-software perks. Deciso's own list (`docs:be.rst`):

> Mission critical · LINCE compliant · Commercial firmware repository · Free GeoIP database · Official OPNsense Open Virtualisation Image · Central Management (one click remote host access, provisioning, monitoring) · Web Application Firewall · Authoritative DNS server · Free E-Book (English & German)

Pricing (shop.opnsense.com, fetched 2026-11-15):

| Item | Price | Notes |
|---|---|---|
| Business Edition licence | €149 / year / installation | https://shop.opnsense.com/product/opnsense-business-edition/ ; multi-install keys via sales |
| Business Edition 3-year prepaid | €399 (list €447) | https://shop.opnsense.com/product/opnsense-business-edition-3yr/ |
| Business Support Subscription | €329 / year | https://shop.opnsense.com/product/opnsense-business-support-subscription/ ; 20 % off with BE licence on every device |
| Business Support Package (2 h, no subscription) | €429 | https://shop.opnsense.com/product/business-support-package-no-subscription/ |
| Reseller Support Subscription | €699 / year | https://www.deciso.com/?p=5288 |
| Proofpoint ET Pro IDS ruleset | sold separately | listed as "compatible" on the BE product page |

Support model (`docs:support.rst`): three tiers of plugin support (Tier 1 core, Tier 2 officially supported plugin, Tier 3 community-maintained); commercial support is an annual fee on top.

### 1.1 Release-by-release inventory of BE-specific additions

BE used CE version numbers until 21.1; from 21.4 the numbering diverged (April = x.4, October = x.10), and each BE release is "based on the OPNsense <CE version> community version with additional reliability improvements" (`docs:releases/BE_*.rst`). The table lists only what is *BE-specific* (commercial plugins, repo perks, certification); everything else in those notes is CE code that reached BE a few months later.

| BE release | BE-specific additions | Source |
|---|---|---|
| 19.1 – 20.7 | BE = CE numbering. Free GeoIP database access for BE customers starts 2020 ("since 2020" on the shop page); 19.7.10 adds the GeoIP configuration page. | `docs:releases/BE_19.7.rst`, shop page |
| 21.4 | Version numbers diverge from CE. `os-OPNcentral 1.1` (compatibility with new firmware API) — OPNcentral already existed as the central-management plugin. | `docs:releases/BE_21.4.rst` |
| 21.10 | **OPNWAF 1.0** introduced (Apache-based reverse proxy + OWASP CRS). **os-OPNBEcore 1.0** introduced: ships the pieces a *managed* node needs so OPNcentral no longer has to be installed on managed nodes. OPNcentral 1.3/1.4: "improved provisioning to allow unique local content". | `docs:releases/BE_21.10.rst` lines 70-71, 83, 118, 362-364, 423 |
| 22.4 | **os-OPNProxy 1.0.1** introduced (advanced web-proxy access management: user/group/network policies, categorised domain lists, policy tester). OPNcentral 1.5; OPNBEcore 1.0.2 "cleans up LDAP sync task". | `docs:releases/BE_22.4.rst` lines 185-187, 447 |
| 22.10 | No new commercial plugin; LINCE evaluation cycle starts at 22.4 ("BE22.04-STIC_OPNSENSE_CQ-ETR"). | `docs:security.rst` results table |
| 23.4 | OPNcentral 1.6, OPNBEcore 1.1 (minor). | `docs:releases/BE_23.4.rst` |
| 23.10 | OPNcentral 1.7–1.9 ("any interface" floating-rule sync; passes `impersonated_by` revision attribute to managed node = per-admin audit trail across fleet; download memory fix). OPNWAF 1.0.1–1.3 (SSLVerifyDepth for client-cert auth). OPNProxy 1.0.3/1.0.4 (TLS client-cert validation, ident removed). CE-side: "firmware: add audit messages for relevant API actions", "improve config revision audit ability". LINCE Certified. | `docs:releases/BE_23.10.rst` lines 52-53, 129-130, 260-262, 532-535 |
| 24.4 | OPNcentral 1.10 (config-diff comparison, new API-enabled components), OPNWAF 1.4/1.5. **OPNProxy 1.0.5 "business plugin released to community version"** — Squid moved to a plugin and OPNProxy was open-sourced into the community plugin set. OPNBEcore rule-sync fix. LINCE Compliant. Marketing: "only open source firewall with formal LINCE compliance". | `docs:releases/BE_24.4.rst` lines 79-80, 154, 375, 456, 474; https://www.deciso.com/opnsense-business-edition-24-4-released/ |
| 24.10 | OPNWAF 1.6 "multiple new features". LINCE Certified; the 24.10 evaluation report notes a **read-only audit role**. | `docs:releases/BE_24.10.rst` line 506; `docs:security.rst`; BE24.10-STIC_OPNSENSE_HIGH-ETR-v1.0.pdf |
| 25.4 | **User Portal** (self-service password/language, TOTP token management, OpenVPN profile download) shipped as `system: add a user portal …` — part of BE core, documented under vendor/deciso. OPNBEcore 1.5, OPNWAF 1.8, OPNcentral 1.11. New US-based business mirror; CRL checking of repo certificates. LINCE Certified. Marketing adds "Enhanced Security Zones … for compliance-driven environments". | `docs:releases/BE_25.4.rst` lines 400, 515-517; `docs:vendor/deciso/userportal.rst`; https://deciso.com/wp-content/uploads/2025/04/Press-release-Deciso_OPNsense_BE_25_4.pdf |
| 25.10 | **OpenID Connect** (OPNBEcore 1.6) for WebGUI login, captive portal zones and OPNWAF virtual servers. **Scheduled jobs** (one-time timed configd commands). OPNWAF 2.0 (OIDC, custom error documents, updated CRS), 2.1. OPNcentral 1.12. "Strict Web UI mode" (non-root GUI, experimental; CE code). LINCE Certified. | `docs:releases/BE_25.10.rst` lines 336, 621-622, 700-701; `docs:vendor/deciso/oidc.rst`, `scheduled_jobs.rst`; https://www.deciso.com/opnsense-business-edition-25-10-elevating-enterprise-control-with-smarter-security-seamless-identity-and-scheduled-automation/ |
| 26.4 | **os-OPNDNS 1.0** (PowerDNS Authoritative; static + RFC2136 dynamic zones; primary/secondary HA). OPNWAF 2.3–2.5, OPNBEcore 1.9. User-portal OpenVPN custom configs; OIDC improvements. LINCE Certified (IAD-2604). 26.4.2 fixed an "audit log injection". | `docs:releases/BE_26.4.rst` lines 89-90, 120, 152-153; `docs:vendor/deciso/opndns.rst`; https://alternativeto.net/news/2026/4/opnsense-business-edition-26-4-adds-openvpn-custom-configs-improved-openid-connect-and-more/ |
| 26.10 | OPNDNS is the headline feature. OPNWAF 2.6, OPNcentral 1.13. | `docs:releases/BE_26.10.rst` lines 9, 291-292 |

Reseller/partner summary of the delta (Thomas-Krenn, https://www.thomas-krenn.com/en/wiki/Additional_features_of_the_OPNsense_Business_Edition): Tested updates (BE repository), GeoIP database, OVA image, OPNcentral, OPNWAF, Advanced Web Proxy, User Portal, e-book, "support of active development", up to 20 % support discount. ET Pro ruleset and extended blocklists are available to both editions.

### 1.2 Each Deciso commercial component in detail

**OPNcentral — central management** (`docs:vendor/deciso/opncentral.rst`, https://docs.opnsense.org/vendor/deciso/opncentral.html)

- Architecture: the central node is itself an OPNsense BE box running `os-OPNcentral`; managed nodes only need `os-OPNBEcore` (since 21.10). Transport is the ordinary REST API over HTTPS using a per-node API key+secret generated in the managed node's user manager. Nodes are addressed by URL (FQDN recommended so certificate SANs match). Certificate validation can be disabled (not advised).
- Host inventory: add/clone/edit/delete hosts; download a node's config (or all as zip); link a central certificate that is pushed to the node's WebGUI (central ACME/cert management).
- Host groups for multi-tenancy: hosts → host groups; user groups constrain access to host groups. Warning in the docs that a host in several groups must be constrained in all of them to avoid accidental access — i.e. coarse, additive ACL.
- Centralised backups: nightly backup of every node's config; retention = N sequential + N per interval (daily/weekly/monthly); manual "Execute backup"; cron job `OPNcentral - backup remote hosts` for more frequent runs.
- One-click remote login ("Connect to managed machine"): auto-login into the node's GUI with the API-token user's privileges; requires BE on the node and browser trust of the node certificate.
- Firmware status/upgrade: query all nodes, show installed version, pending update, reboot-required; bulk upgrade with an "Enable reboot" gate.
- Service status/control: matrix of host × service; restart selected services.
- Resource status: per node hostname, version, CPU type, last config change (who + module), CPU/mem/swap, interfaces up/down, aggregated HA/CARP status, root FS, gateway status + max delay, state-table usage, alias usage, source-tracking usage, traffic in/out by protocol.
- Provisioning ("sharing settings"): the central host acts as the *template*; the same "classes" as HA XMLRPC sync (users & groups, aliases, firewall rules, NAT, categories, WebGUI, certificates, …) are pushed to selected nodes; status per class per host (equal / changes ready / unknown / unreachable); partial-merge semantics per class (API keys preserved on user merge; aliases in use are kept; rules on interfaces unknown to the central node are preserved; floating/group/interface ordering; multi-interface rules dropped; certificates and WebGUI must not be synced together). Cron job `OPNcentral - provision / reconfigure remote hosts` for daily drift correction.
- 23.10 adds `impersonated_by` so the node's config-revision audit shows which central admin made the change.

**OPNWAF — web application firewall / reverse proxy** (`docs:vendor/deciso/opnwaf.rst`)

- Apache httpd + mod_proxy + ModSecurity with the OWASP Core Rule Set; "paranoia level" selector; request-body limit action (partial processing for WebDAV/Nextcloud uploads); allowed HTTP verbs; custom error documents (2.0).
- Virtual servers with internal certificates *or* one-click ACME (Let's Encrypt, `tls-alpn-01` default, `http-01` for the HA backup); TLS security profiles; client-certificate auth with CA/CRL/verify depth (1.3+).
- Locations: Proxy Pass, Proxy Pass Match (regex), Redirect, Redirect Match, and a canned **Exchange Server** location set (OWA/ECP/EWS/ActiveSync/OAB/MAPI/Autodiscover); request-header add/merge/unset; access-control by hostname; load balancing / TLS offload.
- OIDC authentication in front of a virtual server (`/oidc/callback`, 2.0+).
- HA: CARP pair, ACME challenge path forwarded from master to backup; "HA Peer" and challenge-type settings deliberately not synced.
- Diagnostics: active request list / worker activity for backend-health debugging.

**OPNDNS — authoritative DNS** (`docs:vendor/deciso/opndns.rst`, BE 26.4+)

- PowerDNS Authoritative behind the GUI. Static zones (GUI-managed RRsets incl. MX/SRV/TXT, reverse zones) and `allowupdate` zones for RFC 2136 (fed by Kea DHCP). Primary/secondary role with one configured peer for AXFR + NOTIFY. Designed to sit beside Unbound (Unbound stays on :53, forwards internal zones to e.g. :53053). Explicitly not meant for public authoritative hosting.

**OpenID Connect** (`docs:vendor/deciso/oidc.rst`, BE 25.10+, shipped in os-OPNBEcore)

- Providers configured under System → Access → OpenID Connect: application code, service type (WebGui/Admin, Captive Portal, OPNWAF), provider URL (`.well-known/openid-configuration`), client id/secret, auth method (POST/BASIC/provider default), extra scopes; local-database mapping: user-identification claim, create/update local user, group attribute, default groups, limit groups. Endpoints `/api/oidc/rp/{login,finalize}/<appcode>`, `/api/captiveportal/access_oidc/{login,finalize,logout}/…`. Captive portal needs a custom template and firewall exemptions for the IdP (Entra ID etc.). Notably: **no SAML**, and OIDC is BE-only.

**User Portal** (`docs:vendor/deciso/userportal.rst`, BE 25.4+)

- Replaces Lobby → Password. Tabs gated by group membership: change password/language; create/regenerate TOTP token (group-gated); download OpenVPN profiles per instance (certificate lifetime, key type, digest, export template, hostname, static-challenge OTP, custom config). Admin side under System → Settings → Portal Admin. Worked example: three groups (`user_default_priv`, `user_otp_priv`, `user_ovpn_priv`) + TOTP + OpenVPN.

**Scheduled jobs** (`docs:vendor/deciso/scheduled_jobs.rst`, BE 25.10+)

- One-shot timed execution of configd commands (vs cron's periodic schedule): time, countdown, command, parameters, description. Use cases: updates in a maintenance slot, planned shutdown before a power cut.

**OPNProxy — advanced proxy access management** (`docs:manual/opnproxy.rst`; was BE-only 22.4 → 24.4, now a community plugin)

- Policies on top of Squid: audience = users/groups (prefixed `*` for users) and/or networks; match = built-in category (adult, advertisements, malware, gambling, gaming, …) or custom domain/path lists (`.domain` for subdomains, `*` for "everything"); action allow/deny; closest-match wins; explicit allow beats deny; policy tester. Needs Redis and SSL inspection (full bump or "SNI only").

**os-OPNBEcore** — the managed-node side of OPNcentral plus BE-only core bits (rule-sync behaviour, LDAP sync task, OIDC, scheduled jobs). Not documented on its own page; version history in the BE release notes.

**Non-software perks**: commercial repo with slower cadence and CRL-checked certificates and a US mirror (25.4.3); free MaxMind GeoIP database access; OVA image; "Practical OPNsense" e-book; twice-yearly LINCE evaluation by jtsec, certified by Spain's CCN (`docs:security.rst`: stages *In testing → Tested → LINCE Compliant → Certification pending → LINCE Certified*; reports BE 22.4 … BE 26.4 downloadable).

---

## 2. What business buyers expect that OPNsense (even BE) lacks

Reference points: Netgate Nexus / pfSense Plus, Sophos Central, FortiManager/FortiAnalyzer, Arista ETM (Untangle) Dashboard.

**Netgate Nexus** (https://www.netgate.com/nexus, https://docs.netgate.com/pfsense/en/latest/mim/index.html, https://docs.netgate.com/pfsense/en/latest/releases/26-07.html): $49/yr per managed instance, unlimited admin seats, 24×7 TAC. Self-hosted Go controller ("your data is your own"), new single-page GUI + API for local and remote instances, **"highly secure mesh VPN network between instances"**, **remote interactive consoles**, "boot configuration selection and updates" (ZFS boot-environment selection for rollback), two-way JSON registration (registration data → controller, activation data → instance). Requires pfSense Plus 25.11+ on Netgate hardware or AWS/Azure; 26.07 adds Nexus-exclusive **CoreDNS**, **ThreatGate** (bulk address/domain feeds for rules, aliases and DNS groups) and **Snort 3**. Forum users report (unverified) no fine-grained RBAC for operators and no HA controller yet. pfSense Plus itself was announced with "business-level dashboard and reporting" and "Zero Touch Provisioning for easier drop-ship of unprovisioned appliances" (https://www.netgate.com/blog/announcing-pfsense-plus).

**Sophos Central (Fusion)** (https://www.sophos.com/en-us/products/next-gen-firewall/ecosystem-central): firewall group management, **scheduled firmware updates**, **backup management**, **zero-touch deployment**, **SD-WAN VPN orchestration** (point-and-click hub-and-spoke/full mesh), individual + multi-firewall reporting, custom report templates, scheduled and exported reports, cloud log retention 7 d / 30 d / 1 yr by tier, XDR/MDR connector, integrated ZTNA gateway. MSP positioning (https://www.sophos.com/en-us/partner-news/why-msps-need-a-firewall-vendor-built-for-their-world).

**FortiManager / FortiAnalyzer** (https://docs.fortinet.com/document/fortimanager/7.2.4/administration-guide/753593 and related): **ADOMs** (administrative domains = tenants), **policy packages** scoped to device/VDOM/ADOM, device-DB vs policy-package status (drift detection), SQL-based reporting with templates/schedules/output profiles, granular RBAC for multi-tenancy.

**Arista ETM (Untangle) Dashboard** (https://www.untangle.com/wp-content/uploads/Arista-ETM-MSPs-Data-Sheet.pdf, https://support.edge.arista.com/hc/en-us/articles/360004334054-What-is-Command-Center-): configuration templates with real-time sync, one-to-many policy push, appliance groups with aggregated stats, shared WAN routing policies, **automatic daily backups + restore**, zero-touch provisioning, **global alerts to Slack/PagerDuty/VictorOps/email**, 30-day aggregated reporting.

Gap list (OPNsense CE + BE vs. the above):

| Gap | OPNsense today | Business expectation |
|---|---|---|
| Declarative config-as-code / GitOps | Imperative XML config; XMLRPC/HA-class sync; OPNcentral pushes "classes" by overwrite-merge | Versioned templates with per-site variables, plan/diff/apply, rollback, PR-style review |
| Zero-touch provisioning | None (manual install + config import; opnsense-pi-style seeding is a community pattern) | Ship box, plug in, it enrols and pulls its config |
| SD-WAN orchestration | Manual WireGuard/IPsec per site; gateway groups per box | Controller-built overlays (hub/spoke/mesh), path-quality steering, one-click site add |
| SSO breadth | OIDC (BE only), LDAP, RADIUS, TOTP | OIDC *and* SAML, passkeys/WebAuthn, group→role mapping, SCIM optional |
| RBAC | Privilege list per group; OPNcentral host groups; read-only audit role | Roles scoped to tenant/site/node; separation of controller admin vs tenant operator; approval workflows |
| Audit log | Config-revision diff + API audit messages in syslog | Tamper-evident, exportable, fleet-wide, who/what/where/before/after, SIEM export |
| Backups | Local history; `os-git-backup` plugin (Git/Nextcloud/Google Drive/SFTP); OPNcentral nightly central backup (BE) | Encrypted scheduled backups to S3/Git/SFTP out of the box, fleet retention policy, restore test |
| Compliance reporting | LINCE certificate of the *product*; no reports about *your* config | Posture checks, rule hygiene (unused/shadowed rules), scheduled PDF/HTML reports, evidence export |
| Fleet alerting | Monit per box; no fleet alerting | Fleet-wide alert rules → email/Slack/PagerDuty/webhook |
| Central logging/analytics | Per-box syslog-ng forwarding; no retention tier | Central log store with retention, search, multi-firewall reports |
| Remote console | OPNcentral one-click GUI login (BE) | Brokered shell/console through the management tunnel |
| Controller HA / SaaS | Single OPNsense box as controller | HA controller; optional hosted controller |
| Firmware lifecycle | OPNcentral bulk upgrade (BE); ZFS snapshots | Scheduled rollout waves, canaries, automatic rollback |
| Threat-intel feeds | Suricata rules (ET Open/Pro), alias URL tables, Unbound blocklists | Curated managed feeds pushed fleet-wide (Nexus "ThreatGate") |
| ZTNA / identity-aware access | Captive portal + VPN | Identity-aware application gateway |

---

## 3. sensr business-feature catalogue

Format per item: **ID · name** — description · why businesses need it · sensr design sketch · depends on · effort (S ≤ 2 wk, M ≤ 6 wk, L ≤ 3 mo, XL > 3 mo, one engineer) · phase.

Architectural assumptions shared by all sketches (align with the core design docs):

- `sensr-core`: single Rust daemon owning the typed configuration model (serde-backed, versioned schema), a reconciler that renders config into kernel/nftables/service state, and a REST + gRPC API (axum + tonic). Config is stored as content-addressed, signed *generations* (same mental model as NixOS generations) so rollback is cheap and every change has an identity.
- `sensr-ui`: web UI that talks only to the API (no privileged PHP-style page code).
- NixOS image: built with `nixos-generators`/`nix build`; `/boot` is a FAT partition that is read on first boot; the system is otherwise immutable, with `/var/lib/sensr` as the only mutable state.
- Phases: **P1** = ship with the first business-capable release (mostly core-adjacent, cheap); **P2** = fleet management MVP; **P3** = "match BE" services (WAF, auth DNS, portal, SD-WAN); **P4** = MSP/enterprise.

### 3.1 Identity, access, audit (core-adjacent, P1)

**BIZ-001 · OIDC admin login** — Log into the sensr UI/API via any OpenID Connect provider (Entra ID, Okta, Authentik, Keycloak, Zitadel); claim→group→role mapping; JIT user creation; optional group allow-list. *Why*: central identity, MFA inherited from the IdP, instant offboarding; OPNsense gates this behind BE. *Design*: `sensr-auth` crate using the `openidconnect` crate; discovery via `.well-known`; PKCE + nonce; session = signed cookie bound to the API; provider objects in the config model with `service_scope: [admin, portal, captive_portal, waf]` exactly like Deciso's "service" field so one provider definition is reused everywhere; JWKS cached and refreshed. *Depends on*: core user/role model. *Effort*: M. *Phase*: P1.

**BIZ-002 · SAML 2.0 admin login** — SP-initiated SAML with metadata import, signed assertions, group attribute mapping. *Why*: many SMB/enterprise IdP contracts and government tenders still require SAML; OPNsense has none. *Design*: same `sensr-auth` crate, `samael` crate for assertion validation; share the role-mapping layer with BIZ-001. *Depends on*: BIZ-001. *Effort*: M. *Phase*: P1/P2.

**BIZ-003 · MFA: TOTP + WebAuthn/passkeys for local accounts** — TOTP (RFC 6238) and FIDO2 passkeys for admin and portal users; enforce-MFA policy per role. *Why*: insurer and compliance checklists; OPNsense has TOTP only. *Design*: `totp-rs`, `webauthn-rs`; credentials stored in the user object; recovery codes. *Depends on*: core users. *Effort*: S–M. *Phase*: P1.

**BIZ-004 · Scoped RBAC** — Roles = sets of permissions (`firewall.rules.write`, `vpn.read`, `system.firmware.apply`, …) scoped to a resource tree `tenant/site/node`; built-in roles *owner, admin, operator, auditor (read-only), portal-user*. *Why*: separation of duties, MSP technicians who may touch customer A but not B, auditors with read-only access (the LINCE reports call this out). *Design*: permission check middleware in the API (tower layer) evaluating `(subject, action, resource)`; policy stored in config; same engine reused by `sensr-fleet` with the resource tree extended upward. Keep it a simple RBAC-with-scopes, not a full ABAC engine; export decisions to the audit log. *Depends on*: core API. *Effort*: M. *Phase*: P1.

**BIZ-005 · Tamper-evident audit log** — Every API mutation, login, privilege change, config apply and firmware action recorded as structured JSON (`who, via (ui/api/fleet, impersonated_by), what, resource, before/after diff hash, result, request id`), hash-chained (each record carries the previous record's hash), periodically signed with the node key, exported via syslog/TLS, OTLP logs, or pulled by the fleet. *Why*: compliance (ISO 27001 A.8.15, NIS2, PCI 10.x), forensics, MSP accountability; OPNsense has revision diffs and audit lines in syslog, and had an "audit log injection" bug in 26.4.2 — a typed, escaped log avoids the class. *Design*: `sensr-audit` crate wrapping `tracing` with a dedicated appender to an append-only file + SQLite index; chain verification command `sensr audit verify`; retention policy; fleet aggregation in BIZ-021. *Depends on*: BIZ-004 for actor identity. *Effort*: M. *Phase*: P1.

**BIZ-006 · Scoped API tokens & service accounts** — Tokens with expiry, scope (subset of the caller's permissions), source-network constraint, last-used tracking, one-click revoke; service accounts for automation and for the fleet agent. *Why*: Terraform/Ansible/CI integrations; OPNsense tokens inherit the full user privilege set. *Design*: hashed tokens (argon2), token object references a role scope; rate limiting per token. *Depends on*: BIZ-004. *Effort*: S. *Phase*: P1.

### 3.2 Lifecycle, backup, scheduling (core-adjacent, P1)

**BIZ-007 · Scheduled and encrypted off-box backups** — Push each config generation (or nightly) to Git (SSH/HTTPS), S3-compatible, SFTP, WebDAV/Nextcloud; age/`rage` or passphrase encryption; retention; one-click restore from any remote. *Why*: "where is last Tuesday's config" is the first question in any incident; OPNsense needs the `os-git-backup` plugin and offers only local history otherwise. *Design*: `sensr-backup` task in core using `git2`, `object_store` (S3/Azure/GCS), `russh-sftp`; backup payload = signed generation tarball + manifest; restore performs schema migration then creates a new generation (never overwrite). *Depends on*: config generations. *Effort*: M. *Phase*: P1.

**BIZ-008 · Scheduled jobs & maintenance windows** — One-shot jobs (BE "scheduled jobs") plus cron-style jobs and named maintenance windows that other features (firmware rollout, provisioning) must respect. *Why*: updates at 02:00 Sunday, planned shutdown before a power cut, change freezes. *Design*: `sensr-sched` module: `tokio` timer wheel, persisted job table, job = typed action enum (reboot, shutdown, update, apply-generation, run-backup, custom hook); windows = RRULE strings (`rrule` crate). *Depends on*: core action framework. *Effort*: S. *Phase*: P1.

**BIZ-009 · Config generations, diff, rollback, boot-environment selection** — Every apply = new generation; UI shows semantic diff; rollback to any generation; OS-level rollback via NixOS generations/`bootctl` entries (the Nexus "boot configuration selection" feature for free). *Why*: safe change management; auditors ask for "evidence of change and rollback". *Design*: generations stored as signed JSON + rendered artefacts; semantic diff on the typed model (not text); "auto-rollback if the management session is lost within N minutes" (commit-confirm) in core; NixOS system generations exposed via the API with a "boot once into generation X" action. *Depends on*: core. *Effort*: M (mostly core work). *Phase*: P1.

**BIZ-010 · Release channels: `stable` and `lts`** — Two signed Nix binary caches / flake branches: *stable* follows core releases; *lts* lags by ≥1 release, receives security backports, and is what the paid tier or certification covers (OPNsense's "tested updates" repository). *Why*: this is the single most valuable BE perk for conservative buyers. *Design*: Nix flake outputs `sensr.stable` and `sensr.lts`; CI publishes closures to a cache signed with a channel key; node setting `update.channel`; optional authenticated cache (Nix netrc) if the channel is paid. *Depends on*: build pipeline. *Effort*: S (process heavy, code light). *Phase*: P1.

**BIZ-011 · Virtual appliance & cloud images** — OVA/OVF, qcow2, VHDX, AMI/Azure images, Raspberry Pi/ARM SBC images, all from the same flake. *Why*: BE sells the OVA; Nix makes every format a one-liner. *Design*: `nixos-generators` formats + `nixos-rebuild build-image`; cloud-init-compatible seed reading (BIZ-013) for cloud. *Depends on*: image build. *Effort*: S. *Phase*: P1.

**BIZ-012 · GeoIP & curated feeds** — Country aliases and GeoIP enrichment using a fully free database (IPFire `libloc`, public domain) by default, MaxMind GeoLite2 if the operator supplies a key, and a hook for paid feeds (ET Pro IDS rules, URL/category lists) with API-key auth. *Why*: BE's "free GeoIP" exists only because MaxMind licensing got awkward; sensr can ship a free one in core and treat paid feeds as a data subscription, not a software tier. *Design*: `sensr-feeds` fetcher with ETag caching, signature/hash verification, nftables set rendering; feed objects in config with optional credential reference. *Depends on*: alias/set engine. *Effort*: S–M. *Phase*: P1.

### 3.3 Fleet management (P2)

**BIZ-013 · Zero-touch provisioning (ZTP)** — An unconfigured sensr image enrols itself into a fleet on first boot. *Why*: drop-ship to branches; Netgate and Sophos both sell this. *Design*: the generic image's `/boot` (FAT, the same partition the firmware reads, which is how the opnsense-pi reference seeds `config.xml`) may contain `sensr-seed.toml`: `fleet_url`, one-time `enrollment_token` (or a tenant-scoped bootstrap cert), `interface_roles` (by MAC, PCI path or `wan=first-link-up`), optional static WAN, optional full config. A `sensr-firstboot` systemd unit (Rust binary) reads it before networking starts, writes the initial generation, brings up WAN (DHCP/PPPoE/static), and `sensr-agent` performs the enrolment (BIZ-014). Alternatives, all supported by the same unit: USB stick with the seed, cloud-init user-data (for BIZ-011 cloud images), DHCP option 43/60 vendor string pointing at the fleet, or TPM-attested identity (`tss-esapi`) when the fleet pre-registers the device's EK. Nix angle: a fleet can also *build* per-site images (`nix build .#site-berlin`) with the seed baked in — pure NixOS, no runtime secret on the FAT partition except the token. Seed is deleted after a successful enrolment. *Depends on*: BIZ-014, core interface model. *Effort*: M. *Phase*: P2.

**BIZ-014 · `sensr-fleet` central manager + `sensr-agent`** — Separate Rust service (axum/tonic + Postgres; SQLite for single-tenant small deployments) that manages a fleet of nodes over mTLS. *Why*: this is OPNcentral/Nexus/Central — the feature that turns a firewall into a product MSPs can run. *Design*:
  - Identity: fleet runs a private CA (`rcgen` + `rustls`); enrolment exchanges a one-time token for a node certificate (SPIFFE-style `spiffe://fleet/tenant/<t>/site/<s>/node/<id>` SAN); automatic renewal; revocation list distributed to the fleet.
  - Transport: the **agent dials out** (QUIC via `quinn` or WebSocket/HTTP2 via `tonic`) to the fleet, keeps a persistent bidirectional stream, so NAT'd/CGNAT branches work without inbound rules (the Nexus "mesh VPN" effect without needing a mesh). Optional WireGuard management overlay for shells and syslog (BIZ-023/021).
  - Agent is a thin shim inside `sensr-core` (feature flag), not a second daemon: it exposes the same API over the tunnel with the actor = fleet service account + `impersonated_by` header carried into BIZ-005.
  - Inventory & health: node metadata, version, HA role, resource/state/gateway metrics streamed as OTLP metrics; service status; "last config change by whom".
  - Firmware: desired version per node/group; rollout waves with canary count, max unavailable, maintenance windows (BIZ-008), health gate (agent must re-connect and report healthy within N minutes or the fleet issues rollback via BIZ-009).
  - Remote GUI: short-lived delegated session token minted by the fleet, honoured by the node UI (OPNcentral's one-click login without sharing API secrets).
  - Fleet backups: every generation the node applies is mirrored to the fleet store; retention per policy (sequential + interval exactly as OPNcentral); restore = push generation.
  *Depends on*: BIZ-004/005/006/009. *Effort*: XL. *Phase*: P2.

**BIZ-015 · Declarative templates & provisioning (config-as-code)** — Fleet-owned *templates* (partial typed configs with variables) assigned to groups/sites; the fleet computes the desired generation per node, shows a plan (diff) and applies it; drift detection reports nodes whose live config no longer matches; GitOps mode watches a Git repo. *Why*: OPNcentral's overwrite-merge "classes" are the weakest part of BE (the docs warn you can lock yourself out); FortiManager policy packages and Arista templates are what buyers compare against. *Design*: templates are the same serde model with `${var}` placeholders and merge rules per section (`replace`, `merge-by-key`, `prepend`/`append` for rule lists — mirrors the OPNcentral ordering lessons: floating → group → interface); variables per tenant/site/node; render engine in Rust (no external templating language); plan = semantic diff; apply via BIZ-014 with commit-confirm; interface abstraction via roles (`wan`, `lan`, `guest`) so a rule template is portable across hardware. Local overrides allowed only in sections the template marks `locally_extensible` (OPNcentral's "unique local content"). *Depends on*: BIZ-014, BIZ-009. *Effort*: L. *Phase*: P2.

**BIZ-016 · Central certificate & ACME management** — Fleet-level CA/ACME issuing WebUI, VPN and WAF certificates to nodes; CRL/OCSP; renewal tracking. *Why*: OPNcentral pushes WebGUI certs; expired certs are a top MSP ticket. *Design*: `instant-acme` with DNS-01 through the fleet's DNS provider credentials so branch nodes never need inbound 80/443; certificates are config objects pushed via BIZ-015. *Depends on*: BIZ-014, core trust store. *Effort*: M. *Phase*: P2.

**BIZ-017 · Fleet alerting & notifications** — Alert rules (node offline, HA failover, gateway down, disk/state table thresholds, IDS severity, cert expiry, drift) → email, Slack, Teams, PagerDuty, generic webhook, Matrix; per-tenant routing. *Why*: Arista/Sophos table stakes; OPNsense has only Monit per box. *Design*: rules evaluated in `sensr-fleet` on the metric/event stream; node-local subset in core for standalone boxes; `lettre` for SMTP, `reqwest` for webhooks; dedup/silence windows. *Depends on*: BIZ-014. *Effort*: M. *Phase*: P2.

### 3.4 "Match Business Edition" services (P3)

**BIZ-018 · SD-WAN overlay orchestration** — Fleet builds WireGuard overlays (hub-and-spoke, full mesh, dual-hub), allocates addressing, exchanges keys, pushes routes/BGP (via core FRR integration) and policy-based path selection with latency/loss/jitter monitoring and failover; application/DSCP-aware steering. *Why*: Sophos "SD-WAN VPN orchestration", Fortinet SD-WAN; the thing that makes multi-site customers choose a vendor. *Design*: topology object in the fleet → per-node WireGuard + routing config via BIZ-015; path monitor = Rust replacement for `dpinger` emitting metrics; steering rendered as nftables marks + policy routes; multi-WAN gateway groups from core. *Depends on*: core WireGuard, multi-WAN/gateway groups, FRR, BIZ-015. *Effort*: XL. *Phase*: P3.

**BIZ-019 · Web application firewall / reverse proxy** — Virtual servers, locations (proxy, regex proxy, redirect, Exchange preset), TLS offload + ACME, client-cert auth, OWASP CRS with paranoia level, header rewriting, OIDC pre-authentication, HA-aware ACME, request/worker diagnostics. *Why*: OPNWAF is BE's flagship paid plugin; SMBs publish Exchange/Nextcloud/ERP behind the firewall. *Design*: two-stage. Stage 1 (M): Rust config generator driving NixOS-packaged **nginx + libmodsecurity3 + OWASP CRS** (or Apache, as Deciso does) — ModSecurity/CRS has no mature Rust equivalent and fighting that is not the differentiator. Stage 2 (XL, optional): `sensr-waf` on **Pingora** (Cloudflare's Rust proxy framework) with a CRS-compatible rule engine, once Stage 1 proves demand. ACME via `instant-acme`; OIDC via BIZ-001's provider objects. *Depends on*: core trust store, BIZ-001. *Effort*: M (stage 1) / XL (stage 2). *Phase*: P3.

**BIZ-020 · Authoritative DNS with RFC 2136** — Static zones, reverse zones, dynamic zones fed by DHCP (Kea/our own DHCP) via RFC 2136 with TSIG, primary/secondary AXFR+NOTIFY, DNSSEC optional; resolver forwards internal zones. *Why*: OPNDNS is BE 26.4's headline; AD-less SMBs need internal DNS. *Design*: prefer **Hickory DNS** (Rust; authoritative server with SQLite zone store and RFC 2136 dynamic update) embedded as a library in a `sensr-dns-auth` service; fallback plan is NixOS-packaged Knot or PowerDNS behind the same API. Zone data lives in the config model so templates (BIZ-015) can push fleet-wide zones. *Depends on*: core DHCP, core resolver (Unbound or Hickory recursor). *Effort*: L. *Phase*: P3.

**BIZ-021 · Central logging, retention & reporting** — Nodes ship structured logs (firewall, IDS, DNS, DHCP, VPN, audit) to the fleet; retention tiers; search; per-tenant multi-firewall reports (top talkers, blocked threats, VPN usage), scheduled PDF/HTML/CSV export. *Why*: Sophos sells log retention by tier; every MSP needs "monthly report for the customer". *Design*: agent tails core's `tracing` JSON streams and forwards over the mTLS tunnel (or via `vector`); fleet stores in ClickHouse (or Parquet on object storage + DataFusion for the small tier); reports rendered from SQL templates with `typst` for PDF. *Depends on*: BIZ-014, BIZ-005. *Effort*: L–XL. *Phase*: P3/P4.

**BIZ-022 · User self-service portal** — End-user portal: change password, enrol TOTP/passkey, download OpenVPN/WireGuard/IPsec profiles (per-instance policy, cert lifetime, templates, custom config), see active sessions; OIDC login. *Why*: BE 25.4 user portal; cuts helpdesk tickets. *Design*: `sensr-portal` routes in the same axum server on a separate listener/vhost with its own RBAC role; VPN profile generation reuses core export code; QR codes for WireGuard/TOTP. *Depends on*: core VPN, BIZ-001/003/004. *Effort*: M. *Phase*: P3.

**BIZ-023 · Remote console via the fleet** — Brokered interactive shell / serial-like console to a node through the mTLS tunnel, with session recording into the audit log. *Why*: Nexus's most-praised feature; saves truck rolls when the GUI is broken. *Design*: agent spawns a PTY (`portable-pty`) only for fleet sessions holding the `node.console` permission; stream multiplexed on the existing tunnel; asciicast recording stored with the audit record. *Depends on*: BIZ-014, BIZ-004/005. *Effort*: M. *Phase*: P3.

**BIZ-024 · Captive portal & VPN SSO (OIDC/SAML)** — Guest/BYOD captive portal and VPN authentication through the IdP, with per-zone provider choice and automatic IdP allow-listing. *Why*: BE 25.10 added OIDC to the captive portal; schools and hospitality ask for it. *Design*: captive portal in core uses BIZ-001 providers; IdP domains resolved to a dynamic nftables set (OPNsense needs manual Dnsmasq IPset tricks). *Depends on*: core captive portal, BIZ-001/002. *Effort*: M. *Phase*: P3.

### 3.5 MSP / enterprise (P4)

**BIZ-025 · Multi-tenant fleet (MSP mode)** — Tenants as hard isolation boundary in `sensr-fleet`: separate CA, separate RBAC tree, per-tenant templates/variables/feeds/alerts/reports, white-label portal, tenant-scoped API tokens, cross-tenant views only for the MSP owner role. *Why*: OPNcentral's host-group ACL is additive and easy to misconfigure; FortiManager ADOMs are the benchmark. *Design*: `tenant_id` on every fleet table with row-level security in Postgres; URL-prefixed tenant routing; optional per-tenant Postgres schema for stricter isolation. *Depends on*: BIZ-004, BIZ-014/015/017/021. *Effort*: L. *Phase*: P4.

**BIZ-026 · Compliance & posture reporting** — Rule hygiene (unused, shadowed, any-any, expired schedules), configuration checks against a published baseline (CIS-style: admin on management interface only, MFA enforced, logging on, default-deny, firmware age), evidence bundle (config generation + audit excerpt + check results) exportable per node/tenant, scheduled. *Why*: NIS2/ISO/PCI auditors want evidence about *your* configuration, not a vendor certificate. *Design*: checks as Rust functions over the typed config model (`sensr-lint`), runnable locally (`sensr lint`) and fleet-wide; results stored as events; PDF via `typst`. *Depends on*: BIZ-005, BIZ-021. *Effort*: M–L. *Phase*: P4.

**BIZ-027 · Change approval workflow** — Four-eyes approval for template/plan apply, change tickets with external reference (Jira/ServiceNow link), scheduled apply in a maintenance window, automatic rollback on health failure. *Why*: enterprise change management; nothing in OPNsense/BE. *Design*: plan objects in the fleet with states draft → pending-approval → approved → scheduled → applied/rolled-back; approvers defined per tenant/site in RBAC. *Depends on*: BIZ-015, BIZ-008. *Effort*: M. *Phase*: P4.

**BIZ-028 · HA fleet controller & hosted option** — Active/standby `sensr-fleet` on Postgres streaming replication or Patroni; agents configured with multiple fleet endpoints; packaging as a NixOS module and a container; documented hosted-SaaS deployment for those who do not want to run it. *Why*: Nexus lacks HA controller (per forum); MSPs cannot have a single point of management failure. *Design*: stateless fleet pods behind a VIP/LB; leader election only for schedulers (Postgres advisory locks). *Depends on*: BIZ-014. *Effort*: M. *Phase*: P4.

**BIZ-029 · Advanced forward-proxy access control (categories)** — User/group/network policies against categorised domain lists, custom lists, SNI-only or full-bump inspection, policy tester. *Why*: schools, factories; OPNProxy (now community). *Design*: nftables + an SNI-filtering proxy in Rust (Pingora-based) for the SNI-only mode; full bump via NixOS-packaged Squid only if demanded; category data as a paid or community feed (BIZ-012). *Depends on*: BIZ-012, BIZ-019 stage 2. *Effort*: L. *Phase*: P4.

**BIZ-030 · Third-party security evaluation / certification** — Periodic independent evaluation of the `lts` channel (LINCE via a Spanish CCN-accredited lab such as jtsec, or an equivalent Common-Criteria-light scheme; BSI/ANSSI qualification later), published ETR, and a security.txt + CVE process. *Why*: BE's "only LINCE compliant open source firewall" claim wins public tenders. *Design*: no code; budget line and release-process requirement (reproducible Nix builds, SBOM via `sbomnix`, signed closures make the evidence trivial). *Depends on*: BIZ-010. *Effort*: L (process, €). *Phase*: P4.

**BIZ-031 · Identity-aware application gateway (ZTNA-lite)** — Publish internal apps through BIZ-019 with OIDC/SAML auth, device posture header checks, per-app RBAC groups; no client VPN needed. *Why*: Sophos "integrated ZTNA gateway"; SMBs replacing VPN for a few apps. *Design*: extension of the WAF virtual server: `auth_policy` with groups from BIZ-001 claims, short-lived signed cookies, optional mTLS device certs from BIZ-016. *Depends on*: BIZ-019, BIZ-001/002/016. *Effort*: M. *Phase*: P4.

**BIZ-032 · Managed threat-intel feeds fleet-wide ("ThreatGate"-style)** — Fleet-curated allow/block lists (IP, domain, URL) with sources, review, and push to all nodes' nftables sets, DNS blocklists and IDS rule enablement; per-tenant exceptions. *Why*: Nexus 26.07 ThreatGate; MSPs want one place to block an indicator everywhere. *Design*: feed objects in BIZ-015 templates; delta sync over the tunnel; DNS RPZ rendering for the resolver. *Depends on*: BIZ-012, BIZ-015. *Effort*: M. *Phase*: P4.

### 3.6 Summary table

| ID | Feature | Effort | Phase | Hard dependencies |
|---|---|---|---|---|
| BIZ-001 | OIDC admin login | M | P1 | core users/roles |
| BIZ-002 | SAML admin login | M | P1/P2 | BIZ-001 |
| BIZ-003 | TOTP + WebAuthn | S–M | P1 | core users |
| BIZ-004 | Scoped RBAC | M | P1 | core API |
| BIZ-005 | Tamper-evident audit log | M | P1 | BIZ-004 |
| BIZ-006 | Scoped API tokens | S | P1 | BIZ-004 |
| BIZ-007 | Encrypted off-box backups | M | P1 | generations |
| BIZ-008 | Scheduled jobs & windows | S | P1 | core actions |
| BIZ-009 | Generations/diff/rollback/boot-env | M | P1 | core |
| BIZ-010 | stable/lts channels | S | P1 | build pipeline |
| BIZ-011 | VM/cloud/SBC images | S | P1 | image build |
| BIZ-012 | GeoIP & feeds | S–M | P1 | alias/set engine |
| BIZ-013 | Zero-touch provisioning | M | P2 | BIZ-014 |
| BIZ-014 | sensr-fleet + agent | XL | P2 | BIZ-004/005/006/009 |
| BIZ-015 | Templates / config-as-code | L | P2 | BIZ-014, BIZ-009 |
| BIZ-016 | Central certs & ACME | M | P2 | BIZ-014 |
| BIZ-017 | Fleet alerting | M | P2 | BIZ-014 |
| BIZ-018 | SD-WAN orchestration | XL | P3 | WireGuard, multi-WAN, FRR, BIZ-015 |
| BIZ-019 | WAF / reverse proxy | M / XL | P3 | trust store, BIZ-001 |
| BIZ-020 | Authoritative DNS + RFC2136 | L | P3 | DHCP, resolver |
| BIZ-021 | Central logging & reports | L–XL | P3/P4 | BIZ-014, BIZ-005 |
| BIZ-022 | User self-service portal | M | P3 | VPN, BIZ-001/003/004 |
| BIZ-023 | Remote console | M | P3 | BIZ-014, BIZ-004/005 |
| BIZ-024 | Captive portal / VPN SSO | M | P3 | captive portal, BIZ-001/002 |
| BIZ-025 | Multi-tenant MSP mode | L | P4 | BIZ-004/014/015/017/021 |
| BIZ-026 | Compliance & posture reports | M–L | P4 | BIZ-005, BIZ-021 |
| BIZ-027 | Change approval workflow | M | P4 | BIZ-015, BIZ-008 |
| BIZ-028 | HA / hosted controller | M | P4 | BIZ-014 |
| BIZ-029 | Proxy category policies | L | P4 | BIZ-012, BIZ-019 |
| BIZ-030 | Security evaluation (LINCE-like) | L (€) | P4 | BIZ-010 |
| BIZ-031 | ZTNA-lite app gateway | M | P4 | BIZ-019, BIZ-001/016 |
| BIZ-032 | Fleet threat-intel feeds | M | P4 | BIZ-012, BIZ-015 |

Rough totals: P1 ≈ 4–5 engineer-months, P2 ≈ 8–10, P3 ≈ 10–14 (less if WAF stays on nginx+ModSecurity), P4 ≈ 8–12 plus certification budget.

---

## 4. Licensing and packaging stance

### 4.1 Constraints

- **Trademarks.** "OPNsense®" is a registered trademark of Deciso B.V. (US filing 2018; `docs:legal.rst`; https://opnsense.org/about/legal-notices). The policy allows using the name/logo to *promote OPNsense-based products*, and requires written permission for derivative names/logos. sensr is not OPNsense-based (it is a from-scratch Rust implementation on NixOS), so sensr must **not** use "OPNsense" in its name, logo, domain, package names or marketing beyond factual nominative statements ("inspired by", "config import from OPNsense", "feature parity with OPNsense Business Edition"). "pfSense®" is Netgate's mark; avoid any "-sense" suffix branding that could be confused with either. Run a trademark search on "sensr" in EU/US (classes 9 and 42) before public launch.
- **Code.** OPNsense core/plugins are BSD-2-Clause; the docs are BSD-2-Clause too. A Rust rewrite reuses no code, but behaviour, field names and documentation structure may be consulted freely; keep attribution if any text is quoted. Deciso's commercial plugins (OPNcentral, OPNWAF, OPNDNS, OPNBEcore) are closed source and were only studied through their public documentation. Do not copy OPNsense UI assets, logos or screenshots into sensr.
- **Ecosystem.** NixOS and the Rust crate ecosystem are overwhelmingly MIT/Apache-2.0; a copyleft core would complicate packaging in nixpkgs and reuse of sensr crates.

### 4.2 Options

| Option | What is open | What is paid | Pros | Cons |
|---|---|---|---|---|
| **A. Fully open, services revenue** | Everything incl. fleet/MSP (Apache-2.0 OR MIT) | Support, hosted fleet controller, hardware, consulting | Max trust and contributions; no licence-enforcement code; nixpkgs-friendly | Competitors can resell the fleet unchanged; revenue depends on ops/support capacity |
| **B. Open-core** | Node software open; `sensr-fleet`, MSP mode, SD-WAN orchestration, compliance reports under BSL/commercial | Fleet/MSP licence per managed node | Clear monetisation like Nexus ($49/node/yr) | Community backlash (pfSense Plus precedent); forks of the fleet; licence-key plumbing; weaker contributions to the paid parts |
| **C. "Business channel" (OPNsense model)** | All code open | *Access* to the `lts` channel's signed binary cache and images, certification reports, GeoIP/threat/category data feeds, support, hosted controller | Code stays 100 % open; pays for exactly the things that cost money (QA, certification, data, infra); proven by Deciso at €149/node/yr | Anyone can rebuild `lts` from source (acceptable: that is the point); revenue ceiling similar to Deciso's |

### 4.3 Recommendation

Adopt **C with elements of A**:

1. License all sensr code **Apache-2.0 OR MIT** (dual, Rust convention), including `sensr-fleet`. Add a CLA-free DCO. Publish SBOMs and reproducible-build attestations from day one; they are the evidence base for BIZ-030.
2. Monetise: (a) `sensr lts` channel — signed, slower, security-backported, independently evaluated; the *source* is public, the *binary cache + images + evaluation reports* are the subscription; (b) **sensr Cloud** hosted fleet controller (BIZ-014/025/028) per managed node per year; (c) data subscriptions (paid GeoIP/category/IDS feeds via BIZ-012, resold or partnered); (d) support tiers (business / reseller, mirroring Deciso's €329/€699 price points); (e) optional certified hardware with ZTP seed pre-loaded.
3. Keep *every* feature in this document buildable and runnable by the community; differentiate on reliability, hosting and evidence, not on withheld code. This also keeps us clear of any "Business Edition"-style fragmentation of the config model, which is what made OPNcentral provisioning fragile.
4. Branding: product name **sensr**, own logo, own colour scheme; a "Compatibility" page may state factual relationships to OPNsense/pfSense with ® marks and the owners named. Never "sensr for OPNsense", "OPNsense in Rust" or similar in titles, repos or package names.
5. Re-evaluate open-core (option B) only if hosted revenue proves insufficient after P3; if ever adopted, scope it to the *hosted multi-tenant* tier, never to node features or to the single-tenant fleet.

---

## 5. Sources

Local OPNsense docs repo (`source/` tree): `be.rst`, `BE_releases.rst`, `releases/BE_19.1.rst` … `releases/BE_26.10.rst`, `vendor/deciso/opncentral.rst`, `vendor/deciso/opnwaf.rst`, `vendor/deciso/opndns.rst`, `vendor/deciso/oidc.rst`, `vendor/deciso/userportal.rst`, `vendor/deciso/scheduled_jobs.rst`, `manual/opnproxy.rst`, `security.rst` (LINCE), `support.rst`, `legal.rst`.

Web:
- https://docs.opnsense.org/be.html · https://docs.opnsense.org/BE_releases.html · https://docs.opnsense.org/vendor/deciso/opncentral.html · …/opnwaf.html · …/opndns.html · …/oidc.html · …/userportal.html · …/scheduled_jobs.html · https://docs.opnsense.org/security.html
- https://shop.opnsense.com/product/opnsense-business-edition/ · https://shop.opnsense.com/product/opnsense-business-edition-3yr/ · https://shop.opnsense.com/product/opnsense-business-support-subscription/ · https://shop.opnsense.com/product/business-support-package-no-subscription/ · https://www.deciso.com/?p=5288
- https://www.thomas-krenn.com/en/wiki/Additional_features_of_the_OPNsense_Business_Edition
- https://www.deciso.com/opnsense-business-edition-24-4-released/ · https://www.deciso.com/opnsense-business-edition-25-10-elevating-enterprise-control-with-smarter-security-seamless-identity-and-scheduled-automation/ · https://deciso.com/wp-content/uploads/2025/04/Press-release-Deciso_OPNsense_BE_25_4.pdf · https://alternativeto.net/news/2026/4/opnsense-business-edition-26-4-adds-openvpn-custom-configs-improved-openid-connect-and-more/
- LINCE reports: https://docs.opnsense.org/_downloads/f32b1732c6ac7038d8591ccbe7a07a88/BE24.04-STIC_OPNSENSE_CQ-ETR-v1.0.pdf · https://wiki.opnsense.org/_downloads/a8b021f788748b9a2258f186bc5d5f39/BE24.10-STIC_OPNSENSE_HIGH-ETR-v1.0.pdf · https://wiki.opnsense.org/_downloads/1192d82f5a5746287dca94a67976345a/BE26.4-STIC_OPNSENSE_IAD-2604-ETR-v1.0.pdf
- Netgate: https://www.netgate.com/nexus · https://docs.netgate.com/pfsense/en/latest/mim/index.html · https://docs.netgate.com/pfsense/en/latest/mim/registration.html · https://docs.netgate.com/pfsense/en/latest/releases/26-07.html · https://www.netgate.com/blog/announcing-pfsense-plus · https://forum.netgate.com/topic/199943/announcing-netgate-nexus-multi-instance-management-for-pfsense-plus
- Sophos: https://www.sophos.com/en-us/products/next-gen-firewall/ecosystem-central · https://www.sophos.com/en-us/partner-news/why-msps-need-a-firewall-vendor-built-for-their-world
- Fortinet: https://docs.fortinet.com/document/fortimanager/7.2.4/administration-guide/753593 · https://help.fortinet.com/fmgr/fmgr-admin/FMG-437-Online-Help/300_Management_Theory.04.19.html
- Arista/Untangle: https://www.untangle.com/wp-content/uploads/Arista-ETM-MSPs-Data-Sheet.pdf · https://support.edge.arista.com/hc/en-us/articles/360004334054-What-is-Command-Center-
- Trademark: https://opnsense.org/about/legal-notices · https://docs.opnsense.org/legal.html · https://trademarks.justia.com/owners/deciso-group-b-v-6180858
