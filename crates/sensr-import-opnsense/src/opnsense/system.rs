//! `system`: identity, DNS servers, time, IPv6, users and groups, SSH, and the
//! global NAT reflection switches that legacy OPNsense keeps here.

use std::collections::HashMap;

use base64::Engine as _;
use sensr_schema::Document;
use sensr_schema::fields::{GroupName, Host, Secret, SshPublicKey};
use sensr_schema::models::system::{ApiKey, Group, User};

use super::common::{description, item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct SystemMapper;

impl Mapper<Document> for SystemMapper {
    fn name(&self) -> &'static str {
        "system"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["system"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let sys = &mut out.system;
        if let Some(c) = s.child("hostname") {
            ctx.consume(c);
            if let Some(h) = parse_or_warn(ctx, c, &c.text(), "host name") {
                sys.hostname = h;
            }
        }
        if let Some(c) = s.child("domain") {
            ctx.consume(c);
            if let Some(d) = parse_or_warn(ctx, c, &c.text(), "domain") {
                sys.domain = d;
            }
        }
        for c in ctx.children(s, "dnsserver") {
            let t = c.text();
            if t.trim().is_empty() {
                continue;
            }
            if let Some(ip) = parse_or_warn(ctx, c, &t, "DNS server") {
                sys.dns_servers.push(ip);
            }
        }
        sys.dns_allow_override = ctx.flag(s, "dnsallowoverride");
        if let Some(c) = s.child("timezone") {
            ctx.consume(c);
            if let Some(tz) = parse_or_warn(ctx, c, &c.text(), "time zone") {
                sys.timezone = tz;
            }
        }
        if let Some(c) = s.child("timeservers") {
            ctx.consume(c);
            for name in list(&c.text(), &[' ', ',']) {
                if let Some(h) = parse_or_warn::<Host>(ctx, c, &name, "time server") {
                    sys.time_servers.push(h);
                }
            }
        }
        sys.ipv6_allow = ctx.flag(s, "ipv6allow");
        // Per-server gateway binding: "none" (no binding) is all sensr supports yet.
        for n in 1..=8 {
            let name = format!("dns{n}gw");
            ctx.defaults(s, &[(name.as_str(), "none")]);
        }

        // Users first, so group membership (by uid) can be attached to them.
        let mut uid_to_user = HashMap::new();
        for u in ctx.children(s, "user") {
            if let Some((uid, id, user)) = map_user(u, ctx) {
                uid_to_user.insert(uid, id);
                out.system.users.insert(id, user);
            } else {
                ctx.release(u);
            }
        }
        for g in ctx.children(s, "group") {
            if !map_group(g, ctx, out, &uid_to_user) {
                ctx.release(g);
            }
        }
        // Pre-MVC configs name a user's primary group on the user itself.
        for u in s.children_named("user") {
            let Some(gn) = u.child("groupname") else {
                continue;
            };
            ctx.consume(gn);
            let Some(name) = parse_or_warn::<GroupName>(ctx, gn, &gn.text(), "group name") else {
                continue;
            };
            let uid = u
                .child("uid")
                .and_then(|e| e.text().trim().parse::<u32>().ok());
            let user = uid
                .and_then(|uid| uid_to_user.get(&uid))
                .and_then(|id| out.system.users.get_mut(id));
            match user {
                Some(user) if out.system.groups.values().any(|g| g.name == name) => {
                    if !user.groups.contains(&name) {
                        user.groups.push(name);
                    }
                }
                _ => ctx.warn(
                    gn,
                    Severity::Invalid,
                    format!("group {name} not imported for this user"),
                ),
            }
        }

        if let Some(ssh) = ctx.child(s, "ssh") {
            map_ssh(ssh, ctx, out);
        }

        // Legacy global NAT reflection switches (Firewall › Settings › Advanced).
        if let Some(v) = ctx.text(s, "enablenatreflectionhelper") {
            out.nat.reflection.source_nat = v.trim() == "yes";
        }
        if let Some(v) = ctx.text(s, "disablenatreflection") {
            out.nat.reflection.port_forwards = v.trim() != "yes";
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[
            (
                "system/user/email",
                "user e-mail addresses are not modelled yet",
            ),
            ("system/user/comment", "user comments are not modelled yet"),
            ("system/user/landing_page", "web GUI landing page"),
            ("system/user/dashboard", "web GUI dashboard layout"),
            ("system/user/menu_favorites", "web GUI menu favourites"),
            ("system/user/language", "web GUI language"),
            (
                "system/user/pwd_changed_at",
                "password age bookkeeping; sensr tracks its own",
            ),
            (
                "system/ssh/noauto",
                "install-media SSH autostart; not applicable",
            ),
        ]
    }
}

fn map_user<'doc>(
    u: &'doc Element,
    ctx: &mut MapContext<'doc>,
) -> Option<(u32, sensr_schema::Uuid, User)> {
    let id = item_uuid(ctx, u);
    let name_el = ctx.child(u, "name")?;
    let name = parse_or_warn(ctx, name_el, &name_el.text(), "user name")?;
    let uid_el = ctx.child(u, "uid")?;
    let uid: u32 = parse_or_warn(ctx, uid_el, &uid_el.text(), "uid")?;
    let descr = ctx.text(u, "descr");
    let mut user = User {
        name,
        uid,
        description: description(ctx, u, descr),
        disabled: ctx.flag(u, "disabled"),
        password_hash: ctx.non_empty(u, "password").map(Secret::new),
        authorized_keys: Vec::new(),
        groups: Vec::new(),
        shell: ctx.non_empty(u, "shell"),
        api_keys: Vec::new(),
    };
    if let Some(k) = u.child("apikeys") {
        ctx.consume(k);
        // One `key|crypted-secret` per line (Auth/User.xml ApiKeyField).
        for line in list(&k.text(), &['\n']) {
            match line.split_once('|') {
                Some((key, hash))
                    if !key.is_empty() && hash.starts_with('$') && !hash.contains('|') =>
                {
                    user.api_keys.push(ApiKey {
                        key: key.to_owned(),
                        secret_hash: Secret::new(hash.to_owned()),
                    });
                }
                _ => ctx.warn(
                    k,
                    Severity::Invalid,
                    "API key line is not key|crypted-secret; not imported",
                ),
            }
        }
    }
    if let Some(keys_el) = u.child("authorizedkeys") {
        ctx.consume(keys_el);
        let raw = keys_el.text();
        if !raw.trim().is_empty() {
            match base64::engine::general_purpose::STANDARD.decode(raw.trim()) {
                Ok(bytes) => {
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some(k) =
                            parse_or_warn::<SshPublicKey>(ctx, keys_el, line, "SSH key")
                        {
                            user.authorized_keys.push(k);
                        }
                    }
                }
                Err(e) => ctx.warn(
                    keys_el,
                    Severity::Invalid,
                    format!("authorized keys are not base64: {e}"),
                ),
            }
        }
    }
    // `scope` (system/user) is implied by the uid; the rest are empty by default.
    ctx.defaults(
        u,
        &[
            ("scope", "system"),
            ("scope", "user"),
            ("expires", ""),
            ("otp_seed", ""),
            ("priv", ""),
        ],
    );
    Some((uid, id, user))
}

fn map_group<'doc>(
    g: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &mut Document,
    uid_to_user: &HashMap<u32, sensr_schema::Uuid>,
) -> bool {
    let id = item_uuid(ctx, g);
    let Some(name_el) = ctx.child(g, "name") else {
        return false;
    };
    let Some(name) = parse_or_warn::<GroupName>(ctx, name_el, &name_el.text(), "group name") else {
        return false;
    };
    let Some(gid_el) = ctx.child(g, "gid") else {
        return false;
    };
    let Some(gid) = parse_or_warn::<u32>(ctx, gid_el, &gid_el.text(), "gid") else {
        return false;
    };
    let descr = ctx.text(g, "description");
    let mut privileges = Vec::new();
    for p in ctx.children(g, "priv") {
        privileges.extend(list(&p.text(), &[',', '\n']));
    }
    for m in ctx.children(g, "member") {
        for uid in list(&m.text(), &[',', '\n']) {
            let found = uid.parse::<u32>().ok().and_then(|u| uid_to_user.get(&u));
            match found.and_then(|uuid| out.system.users.get_mut(uuid)) {
                Some(user) => user.groups.push(name.clone()),
                None => ctx.warn(
                    m,
                    Severity::Invalid,
                    format!("member uid {uid} is not a known user"),
                ),
            }
        }
    }
    ctx.defaults(
        g,
        &[
            ("scope", "system"),
            ("scope", "user"),
            ("source_networks", ""),
        ],
    );
    let group = Group {
        name,
        gid,
        description: description(ctx, g, descr),
        privileges,
    };
    out.system.groups.insert(id, group);
    true
}

fn map_ssh<'doc>(ssh: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let cfg = &mut out.system.ssh;
    cfg.enabled = ctx.flag(ssh, "enabled");
    if let Some(p) = ctx.parse(ssh, "port") {
        cfg.port = p;
    }
    cfg.permit_root_login = ctx.flag(ssh, "permitrootlogin");
    cfg.password_auth = ctx.flag(ssh, "passwordauth");
    if let Some(c) = ssh.child("group") {
        ctx.consume(c);
        let t = c.text();
        if !t.trim().is_empty() {
            cfg.group = parse_or_warn(ctx, c, &t, "SSH group");
        }
    }
    if let Some(c) = ssh.child("interfaces") {
        ctx.consume(c);
        for i in list(&c.text(), &[',']) {
            if let Some(id) = parse_or_warn(ctx, c, &i, "interface") {
                cfg.interfaces.push(id);
            }
        }
    }
    // Crypto overrides: empty means the daemon's defaults, which is what sensr uses.
    ctx.defaults(
        ssh,
        &[
            ("kex", ""),
            ("ciphers", ""),
            ("macs", ""),
            ("keys", ""),
            ("keysig", ""),
            ("rekeylimit", ""),
        ],
    );
}
