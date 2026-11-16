//! Network-aware configurable fields (OPNsense `HostnameField`,
//! `NetworkField`, `IPPortField`, `MacAddressField`) and the address
//! predicates they share.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::field::{Ctx, FieldType};
use super::well_known;
use crate::validation::{FieldError, ValidatorKind};

/// Which address families a field accepts (`AddressFamily`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddressFamily {
    /// Both.
    #[default]
    Any,
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

impl AddressFamily {
    fn admits(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::Any, _) | (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}

/// An IPv4 or IPv6 address literal (no zone, no brackets).
pub fn is_ip(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// An IPv4 address literal.
pub fn is_ipv4(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok()
}

/// An IPv6 address literal.
pub fn is_ipv6(s: &str) -> bool {
    s.parse::<Ipv6Addr>().is_ok()
}

/// `address/len` with a valid address and a length that fits its family;
/// host bits may be set (OPNsense `Util::isSubnet`).
pub fn is_subnet(s: &str) -> bool {
    let Some((addr, len)) = s.split_once('/') else {
        return false;
    };
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return false;
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    !len.is_empty()
        && len.len() <= 3
        && len.bytes().all(|b| b.is_ascii_digit())
        && len.parse::<u8>().is_ok_and(|l| l <= max)
}

/// [`is_subnet`] with no host bits set (`Util::isSubnetStrict`).
pub fn is_subnet_strict(s: &str) -> bool {
    is_subnet(s)
        && s.parse::<ipnet::IpNet>()
            .is_ok_and(|n| n.addr() == n.network())
}

/// A port number or service name, or with ranges `a:b` (`a < b`)
/// (OPNsense `Util::isPort`).
pub fn is_port(s: &str, allow_range: bool) -> bool {
    let one = |p: &str| {
        let numeric = !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && !(p.len() > 1 && p.starts_with('0'))
            && p.parse::<u16>().is_ok_and(|n| n > 0);
        numeric || well_known::service_port(p).is_some()
    };
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [p] => one(p),
        [a, b] if allow_range => {
            one(a) && one(b) && {
                let num = |x: &str| {
                    x.parse::<u32>()
                        .ok()
                        .or_else(|| well_known::service_port(x).map(u32::from))
                };
                num(a) < num(b)
            }
        }
        _ => false,
    }
}

/// PHP `FILTER_VALIDATE_DOMAIN`: every label 1-63 bytes, the name at most
/// 253 (an optional trailing dot is allowed). With `hostname`, labels are
/// letters, digits and inner hyphens.
pub fn is_domain(s: &str, hostname: bool) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    s.split('.').all(|l| {
        (1..=63).contains(&l.len())
            && (!hostname
                || (l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !l.starts_with('-')
                    && !l.ends_with('-')))
    })
}

fn split_list<'a>(as_list: bool, sep: &'a str, value: &'a str) -> Vec<&'a str> {
    if as_list {
        value.split(sep).collect()
    } else {
        vec![value]
    }
}

fn list_values(as_list: bool, sep: &str, value: &str) -> Vec<String> {
    split_list(as_list, sep, value)
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn list_join(sep: &str, values: &[&str]) -> String {
    values
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(sep)
}

/// Host names, domains and (optionally) addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostnameField {
    /// `IpAllowed` (default on).
    pub ip_allowed: bool,
    /// `HostWildcardAllowed`: a bare `*`.
    pub host_wildcard: bool,
    /// `FqdnWildcardAllowed`: `*.example.org`.
    pub fqdn_wildcard: bool,
    /// `ZoneRootAllowed`: `@` and `@.sub`.
    pub zone_root: bool,
    /// `IsDNSName`: any label characters (`_srv`), not just host names.
    pub dns_name: bool,
    /// `AsList`.
    pub as_list: bool,
    /// `FieldSeparator`.
    pub separator: String,
}

impl Default for HostnameField {
    fn default() -> Self {
        Self {
            ip_allowed: true,
            host_wildcard: false,
            fqdn_wildcard: false,
            zone_root: false,
            dns_name: false,
            as_list: false,
            separator: ",".into(),
        }
    }
}

impl HostnameField {
    /// True if one entry is acceptable.
    pub fn accepts(&self, entry: &str) -> bool {
        let is_ip = is_ip(entry);
        let mut v = entry;
        if (self.fqdn_wildcard && v.starts_with("*.")) || (self.zone_root && v.starts_with("@.")) {
            v = &v[2..];
        }
        if self.zone_root && v == "@" {
            return true;
        }
        if self.host_wildcard && v == "*" {
            return true;
        }
        if self.ip_allowed && is_ip {
            return true;
        }
        is_domain(v, !self.dns_name)
            && !is_ip
            && !v.contains(|c: char| c.is_whitespace() || c == '/' || c == '*')
    }
}

impl FieldType for HostnameField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        split_list(self.as_list, &self.separator, value)
            .into_iter()
            .find(|e| !self.accepts(e))
            .map(|bad| {
                vec![FieldError::callback(
                    ctx.msg("[%s] is not a valid IP address or hostname.", bad),
                )]
            })
            .unwrap_or_default()
    }

    fn on_set(&self, value: String) -> String {
        value.trim().to_owned()
    }

    fn values(&self, value: &str) -> Vec<String> {
        list_values(self.as_list, &self.separator, value)
    }

    fn join(&self, values: &[&str]) -> String {
        list_join(&self.separator, values)
    }

    fn is_list(&self) -> bool {
        self.as_list
    }
}

/// Addresses and networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkField {
    /// `NetMaskRequired`.
    pub net_mask_required: bool,
    /// `NetMaskAllowed` (default on).
    pub net_mask_allowed: bool,
    /// `WildcardEnabled`: `any` passes (default on).
    pub wildcard: bool,
    /// `AddressFamily`.
    pub family: AddressFamily,
    /// `Strict`: networks must have no host bits set.
    pub strict: bool,
    /// `AsList`.
    pub as_list: bool,
    /// `FieldSeparator`.
    pub separator: String,
}

impl Default for NetworkField {
    fn default() -> Self {
        Self {
            net_mask_required: false,
            net_mask_allowed: true,
            wildcard: true,
            family: AddressFamily::Any,
            strict: false,
            as_list: false,
            separator: ",".into(),
        }
    }
}

impl NetworkField {
    /// True if one entry is acceptable.
    pub fn accepts(&self, entry: &str) -> bool {
        let addr = match entry.split_once('/') {
            Some(_) if !self.net_mask_allowed => return false,
            Some((addr, len)) => {
                if len.contains('/') || len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
                    return false;
                }
                let max = if addr.contains(':') { 128 } else { 32 };
                if len.len() > 3 || len.parse::<u8>().map_or(true, |l| l > max) {
                    return false;
                }
                if self.strict && !is_subnet_strict(entry) {
                    return false;
                }
                addr
            }
            None if self.net_mask_required => return false,
            None => entry,
        };
        addr.parse::<IpAddr>()
            .is_ok_and(|ip| self.family.admits(ip))
    }
}

impl FieldType for NetworkField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        if self.wildcard && value == "any" {
            return Vec::new();
        }
        if split_list(self.as_list, &self.separator, value)
            .into_iter()
            .all(|e| self.accepts(e))
        {
            Vec::new()
        } else {
            vec![ctx.err(
                ValidatorKind::Callback,
                "Please specify a valid network segment or IP address.",
            )]
        }
    }

    fn on_set(&self, value: String) -> String {
        value.trim().to_lowercase()
    }

    fn values(&self, value: &str) -> Vec<String> {
        list_values(self.as_list, &self.separator, value)
    }

    fn join(&self, values: &[&str]) -> String {
        list_join(&self.separator, values)
    }

    fn is_list(&self) -> bool {
        self.as_list
    }
}

/// `address:port` combinations (`[v6]:port` for IPv6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpPortField {
    /// `AddressFamily`.
    pub family: AddressFamily,
    /// `PortOptional`: a bare address (or host name) is also fine.
    pub port_optional: bool,
    /// `HostnameAllowed`: `host:port`.
    pub hostname_allowed: bool,
    /// `AsList` (comma-separated).
    pub as_list: bool,
}

impl IpPortField {
    /// True if one entry is acceptable.
    pub fn accepts(&self, v: &str) -> bool {
        let parts: Vec<&str> = v.split(':').collect();
        if self.family != AddressFamily::V6 {
            if parts.len() == 2 && is_ipv4(parts[0]) && is_port(parts[1], true) {
                return true;
            }
            if self.port_optional && is_ipv4(v) {
                return true;
            }
        }
        if self.hostname_allowed {
            if parts.len() == 2 && is_port(parts[1], true) && is_domain(parts[0], true) {
                return true;
            }
            if self.port_optional && is_domain(v, true) {
                return true;
            }
        }
        if self.family != AddressFamily::V4 {
            if let Some(rest) = v.strip_prefix('[')
                && let Some((addr, tail)) = rest.split_once(']')
                && is_ipv6(addr)
                && tail.contains(':')
                && is_port(tail.trim_matches([':', ' ']), true)
            {
                return true;
            }
            if self.port_optional && is_ipv6(v) {
                return true;
            }
        }
        false
    }
}

impl FieldType for IpPortField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        split_list(self.as_list, ",", value)
            .into_iter()
            .find(|e| !self.accepts(e))
            .map(|bad| {
                vec![FieldError::callback(format!(
                    "\"{bad}\" is invalid. {}",
                    ctx.msg("Invalid IP-port combination.", bad)
                ))]
            })
            .unwrap_or_default()
    }

    fn on_set(&self, value: String) -> String {
        value.trim().to_owned()
    }

    fn values(&self, value: &str) -> Vec<String> {
        list_values(self.as_list, ",", value)
    }

    fn join(&self, values: &[&str]) -> String {
        list_join(",", values)
    }

    fn is_list(&self) -> bool {
        self.as_list
    }
}

/// MAC addresses (`aa:bb:..`, `aa-bb-..` or Cisco `aabb.ccdd.eeff`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MacAddressField {
    /// `AsList` (comma-separated).
    pub as_list: bool,
}

impl FieldType for MacAddressField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        if split_list(self.as_list, ",", value)
            .into_iter()
            .all(|m| m.parse::<super::MacAddr>().is_ok())
        {
            Vec::new()
        } else {
            vec![ctx.err(ValidatorKind::Callback, "Invalid MAC address.")]
        }
    }

    fn on_set(&self, value: String) -> String {
        value.trim().to_owned()
    }

    fn values(&self, value: &str) -> Vec<String> {
        list_values(self.as_list, ",", value)
    }

    fn join(&self, values: &[&str]) -> String {
        list_join(",", values)
    }

    fn is_list(&self) -> bool {
        self.as_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::field::Field;
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;
    use proptest::prelude::*;

    #[test]
    fn predicates() {
        assert!(is_subnet("192.168.0.1/24") && is_subnet("2001::/32"));
        assert!(
            !is_subnet("192.168.0.1/64")
                && !is_subnet("2001::/300")
                && !is_subnet("1.2.3.4/")
                && !is_subnet("1.2.3.4/-1")
        );
        assert!(is_subnet_strict("192.168.1.0/24") && !is_subnet_strict("192.168.1.1/24"));
        assert!(is_port("80", true) && is_port("https", true) && is_port("80:90", true));
        assert!(
            !is_port("90:80", true)
                && !is_port("80:90", false)
                && !is_port("0", true)
                && !is_port("080", true)
        );
        assert!(is_domain("a.b-c.org", true) && is_domain("example.org.", true));
        assert!(
            !is_domain("-a.org", true) && !is_domain("a..b", true) && is_domain("_x.org", false)
        );
    }

    mod hostname {
        use super::*;

        fn f() -> Field<HostnameField> {
            Field::new(HostnameField::default())
        }

        #[test]
        fn constructs_t0135() {
            let _ = f();
        }

        #[test]
        fn generic_t0136() {
            assert!(!f().is_container() && !f().is_list());
        }

        #[test]
        fn required_empty_t0137() {
            let mut f = f().required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0138() {
            let mut f = f().required();
            f.set_value("test.opnsense.org");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn dns_name_values_t0139() {
            let mut f = f();
            f.kind.dns_name = true;
            for v in ["test", "test.opnsense.org", "_test.opnsense.org"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn zone_root_t0140() {
            let mut f = f();
            f.kind.zone_root = true;
            for v in ["@", "@.test"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
            f.kind.zone_root = false;
            for v in ["@", "@.test"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn wildcards_t0141() {
            let mut f = f();
            for v in ["*", "*.opnsense.org"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
            f.kind.host_wildcard = true;
            f.kind.fqdn_wildcard = true;
            for v in ["*", "*.opnsense.org"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn as_list_separator_t0142() {
            let mut f = f();
            f.set_value("test|test.opnsense.org");
            assert!(!validate(&f).is_empty());
            assert!(!f.is_list());
            f.kind.as_list = true;
            f.kind.separator = "|".into();
            f.set_value("test|test.opnsense.org");
            assert!(validate(&f).is_empty());
            assert_eq!(f.values(), ["test", "test.opnsense.org"]);
        }

        #[test]
        fn invalid_values_t0143() {
            let mut f = f();
            for v in ["!2121", "x2&x", "_88766-1234", "@", "*.test", "@.test"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn ip_allowed_toggle_t0144() {
            let mut f = f();
            f.kind.ip_allowed = false;
            f.set_value("192.168.1.1");
            assert!(!validate(&f).is_empty());
            f.kind.ip_allowed = true;
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0145() {
            assert!(!f().is_container());
        }
    }

    mod network {
        use super::*;

        fn f(mask_required: bool, family: AddressFamily, strict: bool) -> Field<NetworkField> {
            Field::new(NetworkField {
                net_mask_required: mask_required,
                family,
                strict,
                ..NetworkField::default()
            })
        }

        #[test]
        fn constructs_t0211() {
            let _ = Field::new(NetworkField::default());
        }

        #[test]
        fn generic_t0212() {
            let f = Field::new(NetworkField::default());
            assert!(!f.is_container() && !f.is_list());
        }

        #[test]
        fn required_empty_t0213() {
            let mut f = Field::new(NetworkField::default()).required();
            f.set_value("");
            assert_eq!(f.count(), 0);
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0214() {
            let mut f = Field::new(NetworkField::default()).required();
            f.set_value("192.168.1.1");
            assert_eq!(f.count(), 1);
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn v4_with_mask_t0215() {
            let mut f = f(true, AddressFamily::V4, false);
            for v in ["192.168.1.1/24", "10.0.0.1/24"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn multi_newline_separator_t0216() {
            let value = "192.168.1.1\n2000::1";
            let mut f = Field::new(NetworkField {
                as_list: true,
                separator: "\n".into(),
                ..NetworkField::default()
            });
            f.set_value(value);
            assert_eq!(f.count(), 2);
            assert!(validate(&f).is_empty());
            assert!(f.is_equal(value));
            assert_eq!(f.values(), ["192.168.1.1", "2000::1"]);
            f.set_values::<&str>(&[]);
            assert!(f.values().is_empty());
            f.set_values(&["", ""]);
            assert!(f.values().is_empty());
            f.set_values(&["", "192.168.1.1", "2000::1"]);
            assert!(validate(&f).is_empty());
            assert!(f.is_equal(value));
            assert_eq!(f.values(), ["192.168.1.1", "2000::1"]);
        }

        #[test]
        fn v6_with_mask_t0217() {
            let mut f = f(true, AddressFamily::V6, false);
            for v in ["2000::1/128", "fe80::5a8c:fcff:0001:ffe2/64"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn v4_bad_t0218() {
            let mut f = f(true, AddressFamily::V4, false);
            for v in ["192.168.1.1", "2000::1", "A"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn v6_bad_t0219() {
            let mut f = f(true, AddressFamily::V6, false);
            for v in ["192.168.1.1", "2000::1", "A"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn strict_ok_t0220() {
            let mut f = f(true, AddressFamily::Any, true);
            for v in ["192.168.1.0/24", "2000::0/64"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn strict_host_bits_rejected_t0221() {
            let mut f = f(true, AddressFamily::Any, true);
            for v in ["192.168.1.1/24", "2000::1:1/64"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        proptest! {
            /// Strict accepts a v4 network exactly when it is the network
            /// address of its prefix.
            #[test]
            fn prop_strict_iff_network_address_t0221(a in any::<u32>(), len in 0u8..=32) {
                let net = ipnet::Ipv4Net::new(Ipv4Addr::from(a), len).unwrap();
                let mut f = f(true, AddressFamily::Any, true);
                f.set_value(net.to_string());
                prop_assert_eq!(validate(&f).is_empty(), net.addr() == net.network());
            }
        }

        #[test]
        fn not_container_t0222() {
            assert!(!Field::new(NetworkField::default()).is_container());
        }

        #[test]
        fn any_wildcard_and_mask_disallowed() {
            let mut f = Field::new(NetworkField::default());
            f.set_value("ANY");
            assert!(validate(&f).is_empty(), "lower-cased and wildcarded");
            f.kind.net_mask_allowed = false;
            f.set_value("10.0.0.0/8");
            assert!(!validate(&f).is_empty());
        }
    }

    mod ip_port {
        use super::*;

        fn f() -> Field<IpPortField> {
            Field::new(IpPortField::default())
        }

        #[test]
        fn constructs_t0164() {
            let _ = f();
        }

        #[test]
        fn generic_t0165() {
            assert!(!f().is_container() && !f().is_list());
        }

        #[test]
        fn required_empty_t0166() {
            let mut f = f().required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn optional_empty_ok_t0167() {
            let mut f = f();
            f.set_value("");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn required_set_t0168() {
            let mut f = f().required();
            f.set_value("127.0.0.1:2056");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn v4_ok_t0169() {
            let mut f = f();
            f.set_value("127.0.0.1:2056");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn v4_list_ok_t0170() {
            let mut f = f();
            f.kind.as_list = true;
            f.set_value("127.0.0.1:2056,192.168.1.1:1111");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn v6_ok_t0171() {
            let mut f = f();
            f.set_value("[::1]:2056");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn v6_list_ok_t0172() {
            let mut f = f();
            f.kind.as_list = true;
            f.set_value("[::1]:2056,[fe80::]:1111");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn garbage_rejected_t0173() {
            let mut f = f();
            f.set_value("abcdefg");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn hostname_rules_t0174() {
            let mut f = f();
            f.set_value("abcdefg:123");
            f.kind.hostname_allowed = true;
            assert!(validate(&f).is_empty());
            f.set_value("abcdefg:123,b.c.d:332");
            assert!(!validate(&f).is_empty());
            f.kind.as_list = true;
            assert!(validate(&f).is_empty());
            f.set_value("abcdefg:123,b.c.d:332,foobar");
            assert!(!validate(&f).is_empty());
            f.kind.port_optional = true;
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn port_optional_bracket_rules_t0175() {
            let mut f = Field::new(IpPortField {
                as_list: true,
                port_optional: true,
                hostname_allowed: true,
                ..IpPortField::default()
            });
            f.set_value("abcdeg,127.0.0.1,::1");
            assert!(validate(&f).is_empty());
            f.set_value("[::1]:123");
            assert!(validate(&f).is_empty());
            for bad in ["[::1]", "[foobar]", "[foobar]:123"] {
                f.set_value(bad);
                assert!(!validate(&f).is_empty(), "{bad}");
            }
            f.set_value("foobar:123");
            assert!(validate(&f).is_empty());
            f.kind.hostname_allowed = false;
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn v4_list_garbage_rejected_t0176() {
            let mut f = f();
            f.kind.as_list = true;
            f.set_value("127.0.0.1:2056,abcdefg");
            assert_eq!(validate_err(&f), Err(Callback));
            assert_eq!(
                f.validate()[0].message,
                "\"abcdefg\" is invalid. Invalid IP-port combination."
            );
        }

        #[test]
        fn v6_no_port_rejected_t0177() {
            let mut f = f();
            f.set_value("[::1]");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn v6_list_no_port_rejected_t0178() {
            let mut f = f();
            f.kind.as_list = true;
            f.set_value("[::1]:2056,[fe80::]");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn family_v4_only_t0179() {
            let mut f = f();
            f.kind.family = AddressFamily::V4;
            f.set_value("[::1]:2056");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn family_v6_only_t0180() {
            let mut f = f();
            f.kind.family = AddressFamily::V6;
            f.set_value("192.168.1.1:1111");
            assert_eq!(validate_err(&f), Err(Callback));
        }
    }

    #[test]
    fn mac_address_field() {
        let mut f = Field::new(MacAddressField { as_list: true });
        f.set_value(" 00:11:22:33:44:55,00-11-22-33-44-56,0011.2233.4457 ");
        assert!(validate(&f).is_empty());
        f.set_value("00:11:22:33:44");
        assert_eq!(validate(&f), [Callback]);
    }
}
