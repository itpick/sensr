//! Tags that legacy OPNsense code always reads as lists (`listtags()` in
//! `src/etc/inc/config.inc`), even when only one occurrence is present.

/// The always-list tag names, sorted for binary search.
pub const LIST_TAGS: &[&str] = &[
    "acls",
    "alias",
    "aliasurl",
    "allowedhostname",
    "allowedip",
    "authserver",
    "bridged",
    "build_port_path",
    "ca",
    "cacert",
    "cert",
    "clone",
    "columnitem",
    "config",
    "container",
    "crl",
    "dhcp_ranges",
    "disk",
    "dnsserver",
    "dnsupdate",
    "domainoverrides",
    "element",
    "encryption-algorithm-option",
    "field",
    "fieldname",
    "gateway_group",
    "gateway_item",
    "gif",
    "gre",
    "group",
    "hash-algorithm-option",
    "hosts",
    "ifgroupentry",
    "igmpentry",
    "interface_array",
    "item",
    "key",
    "lagg",
    "lbpool",
    "member",
    "menu",
    "mobilekey",
    "monitor_type",
    "mount",
    "npt",
    "ntpserver",
    "onetoone",
    "openvpn-client",
    "openvpn-csc",
    "openvpn-server",
    "option",
    "package",
    "pages",
    "passthrumac",
    "phase1",
    "phase2",
    "pipe",
    "pool",
    "ppp",
    "pppoe",
    "priv",
    "proxyarpnet",
    "radnsserver",
    "roll",
    "route",
    "row",
    "rrddatafile",
    "rule",
    "schedule",
    "servernat",
    "servers",
    "serversdisabled",
    "service",
    "staticmap",
    "subqueue",
    "tab",
    "timerange",
    "tunnel",
    "user",
    "vip",
    "virtual_server",
    "vlan",
    "widget",
    "winsserver",
    "wolentry",
];

/// Whether `tag` is always a list for legacy code.
pub fn is_list_tag(tag: &str) -> bool {
    LIST_TAGS.binary_search(&tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(LIST_TAGS.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(LIST_TAGS.len(), 85);
    }

    #[test]
    fn lookups() {
        assert!(is_list_tag("rule"));
        assert!(is_list_tag("item"));
        assert!(is_list_tag("openvpn-csc"));
        assert!(!is_list_tag("interfaces"));
        assert!(!is_list_tag("Rule"));
    }
}
