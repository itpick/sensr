//! Default gateway selection per address family (OPNsense
//! `Gateways::getDefaultGW` driven by `StaticRoute::staticRoutes`).

use crate::{Family, Status};

/// A gateway as the default route selection sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultCandidate<'a> {
    /// Gateway name.
    pub name: &'a str,
    /// Address family.
    pub family: Family,
    /// Disabled gateways are never chosen.
    pub enabled: bool,
    /// Marked as default gateway (`defaultgw`): sorts before all unmarked
    /// gateways.
    pub default_route: bool,
    /// Lower wins among equally marked gateways (0..=255).
    pub priority: u8,
    /// The next-hop address is known (a dynamic gateway may still wait for
    /// DHCP or a router advertisement).
    pub has_address: bool,
    /// Configured force-down (`force_down`).
    pub force_down: bool,
    /// Current monitor status (`Online` for unmonitored gateways).
    pub status: Status,
}

/// Chooses the default gateway for `family`.
///
/// Every gateway of the family is a candidate. They are ordered like
/// upstream's sort key: gateways marked `default_route` first, then by
/// ascending `priority`, then in the given (configuration) order. The first
/// one that is enabled, not forced down and has an address wins.
///
/// With `switching` (System > General "Gateway switching") gateways whose
/// status [is down](Status::is_down) are skipped as well, so traffic fails
/// over to the next candidate. Without it the monitor is ignored and the
/// configured order alone decides, even when that gateway is down. Pass
/// `switching = false` while the system is booting, as upstream does.
pub fn select_default_gateway<'a>(
    candidates: &[DefaultCandidate<'a>],
    family: Family,
    switching: bool,
) -> Option<&'a str> {
    let mut order: Vec<(usize, &DefaultCandidate<'a>)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.family == family)
        .collect();
    order.sort_by_key(|(i, c)| (!c.default_route, c.priority, *i));
    order
        .into_iter()
        .map(|(_, c)| c)
        .find(|c| {
            c.enabled
                && !c.force_down
                && c.status != Status::ForceDown
                && c.has_address
                && !(switching && c.status.is_down())
        })
        .map(|c| c.name)
}

/// Covers: SYS-GW-002
#[cfg(test)]
mod tests {
    use super::*;
    use Status::*;

    fn c(name: &str, default_route: bool, priority: u8, status: Status) -> DefaultCandidate<'_> {
        DefaultCandidate {
            name,
            family: Family::Inet,
            enabled: true,
            default_route,
            priority,
            has_address: true,
            force_down: false,
            status,
        }
    }

    #[test]
    fn selection_table() {
        struct Case {
            name: &'static str,
            gws: Vec<DefaultCandidate<'static>>,
            switching: bool,
            want: Option<&'static str>,
        }
        let cases = [
            Case {
                name: "marked default wins over better priority",
                gws: vec![c("a", false, 1, Online), c("b", true, 200, Online)],
                switching: true,
                want: Some("b"),
            },
            Case {
                name: "lowest priority among marked",
                gws: vec![c("a", true, 20, Online), c("b", true, 10, Online)],
                switching: true,
                want: Some("b"),
            },
            Case {
                name: "equal priority keeps configuration order",
                gws: vec![c("a", true, 10, Online), c("b", true, 10, Online)],
                switching: true,
                want: Some("a"),
            },
            Case {
                name: "switching skips a down default",
                gws: vec![c("a", true, 1, Down), c("b", false, 254, Online)],
                switching: true,
                want: Some("b"),
            },
            Case {
                name: "without switching the configured default stays though down",
                gws: vec![c("a", true, 1, Down), c("b", false, 254, Online)],
                switching: false,
                want: Some("a"),
            },
            Case {
                name: "switching skips pending (monitored, no data yet)",
                gws: vec![c("a", true, 1, Pending), c("b", true, 2, Online)],
                switching: true,
                want: Some("b"),
            },
            Case {
                name: "degraded is not down: delay/loss keep the default",
                gws: vec![c("a", true, 1, DelayLoss), c("b", true, 2, Online)],
                switching: true,
                want: Some("a"),
            },
            Case {
                name: "force down is skipped even without switching",
                gws: vec![
                    DefaultCandidate {
                        force_down: true,
                        ..c("a", true, 1, ForceDown)
                    },
                    c("b", true, 2, Down),
                ],
                switching: false,
                want: Some("b"),
            },
            Case {
                name: "disabled and address-less gateways are skipped",
                gws: vec![
                    DefaultCandidate {
                        enabled: false,
                        ..c("a", true, 1, Online)
                    },
                    DefaultCandidate {
                        has_address: false,
                        ..c("b", true, 2, Online)
                    },
                    c("c", false, 255, Online),
                ],
                switching: false,
                want: Some("c"),
            },
            Case {
                name: "all down with switching: none",
                gws: vec![c("a", true, 1, Down), c("b", false, 2, ForceDown)],
                switching: true,
                want: None,
            },
            Case {
                name: "other family ignored",
                gws: vec![DefaultCandidate {
                    family: Family::Inet6,
                    ..c("v6", true, 1, Online)
                }],
                switching: true,
                want: None,
            },
        ];
        for case in cases {
            assert_eq!(
                select_default_gateway(&case.gws, Family::Inet, case.switching),
                case.want,
                "{}",
                case.name
            );
        }
    }
}
