//! `ntpd`: Services › Network Time. The servers themselves are
//! `system/timeservers` (imported by the system mapper); this section holds
//! their flags and how the firewall serves time.
//!
//! OPNsense runs ntpd whenever time servers are configured and serves every
//! client unless `noserve` is set (`ntpd.inc`); `clientmode` sets the clock
//! once and exits, so it serves nothing either. `interface` limits the
//! sockets to those interfaces' addresses.

use sensr_schema::Document;
use sensr_schema::fields::Host;
use sensr_schema::models::ntp::NtpServerOptions;

use super::common::{interface_id, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as Tree, Element};

pub struct NtpdMapper;

/// The per-server flag lists, each a space-separated list of server names.
const FLAG_LISTS: &[&str] = &["prefer", "noselect", "iburst", "ispool"];

impl Mapper<Document> for NtpdMapper {
    fn name(&self) -> &'static str {
        "ntpd"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["ntpd"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let noserve = ctx.flag(s, "noserve");
        let clientmode = ctx.flag(s, "clientmode");
        if clientmode {
            ctx.warn(
                s,
                Severity::Info,
                "client mode (set the clock once, then exit) is imported as a time client \
                 that keeps the clock in sync and serves nobody",
            );
        }
        let ntp = &mut out.ntp;
        ntp.serve = !noserve && !clientmode;
        ntp.allow_query = ctx.flag(s, "query");
        if let Some(o) = ctx.child(s, "orphan") {
            let t = o.text();
            if !t.trim().is_empty() {
                ntp.orphan_stratum = parse_or_warn(ctx, o, &t, "orphan stratum");
            }
        }
        if let Some(i) = ctx.child(s, "interface") {
            for name in list(&i.text(), &[',']) {
                match interface_id(out, &name) {
                    Some(id) => out.ntp.listen_interfaces.push(id),
                    None => ctx.warn(
                        i,
                        Severity::Degraded,
                        format!(
                            "NTP listen interface {name:?} is not imported (only assigned \
                             interfaces are; addresses and virtual IPs are not), so this \
                             socket is not bound"
                        ),
                    ),
                }
            }
        }
        for field in FLAG_LISTS {
            let Some(e) = ctx.child(s, field) else {
                continue;
            };
            for name in list(&e.text(), &[' ', ',']) {
                let Some(host) = parse_or_warn::<Host>(ctx, e, &name, "time server") else {
                    continue;
                };
                // ntpd.inc only consults the flags of configured servers.
                if !out.system.time_servers.contains(&host) {
                    ctx.warn(
                        e,
                        Severity::Info,
                        format!(
                            "{host} is not a configured time server; its {field} flag is dropped"
                        ),
                    );
                    continue;
                }
                let servers = &mut out.ntp.servers;
                let i = match servers.iter().position(|o| o.host == host) {
                    Some(i) => i,
                    None => {
                        servers.push(NtpServerOptions {
                            host: host.clone(),
                            prefer: false,
                            no_select: false,
                            iburst: false,
                            pool: false,
                            nts: false,
                        });
                        servers.len() - 1
                    }
                };
                let o = &mut servers[i];
                match *field {
                    "prefer" => o.prefer = true,
                    "noselect" => o.no_select = true,
                    "iburst" => o.iburst = true,
                    _ => o.pool = true,
                }
            }
        }
        // Keep the flags in `system.time_servers` order, as the GUI lists them.
        let order = &out.system.time_servers;
        out.ntp
            .servers
            .sort_by_key(|o| order.iter().position(|h| *h == o.host));
        // Access restrictions that only weaken ntpd's defaults (the inverted
        // kod/limited/nomodify/notrap/nopeer checkboxes), statistics, logging,
        // the leap-second file and custom options have no ntpd-rs equivalent;
        // they are accepted unset only, so a set one is reported.
        ctx.defaults(
            s,
            &[
                ("maxclock", "10"),
                ("kod", ""),
                ("limited", ""),
                ("nomodify", ""),
                ("notrap", ""),
                ("nopeer", ""),
                ("noquery", ""),
                ("statsgraph", ""),
                ("logpeer", ""),
                ("logsys", ""),
                ("clockstats", ""),
                ("loopstats", ""),
                ("peerstats", ""),
                ("leapsec", ""),
                ("custom_options", ""),
            ],
        );
    }

    fn finish<'doc>(&self, doc: &'doc Tree, _ctx: &mut MapContext<'doc>, out: &mut Document) {
        // No `ntpd` section: OPNsense still runs ntpd with its defaults when
        // time servers are set, and it serves.
        if doc.root.child("ntpd").is_none() && !out.system.time_servers.is_empty() {
            out.ntp.serve = true;
        }
    }
}
