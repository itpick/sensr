//! Identifier-like text fields: alias, interface, device, user and object
//! names, time zones and descriptions.

use std::fmt;
use std::str::FromStr;

use super::string_serde;
use super::well_known;
use crate::validation::FieldError;

/// Defines a `String` newtype with a validating `FromStr`.
macro_rules! name_type {
    ($(#[$doc:meta])* $name:ident, |$s:ident| $check:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// The value as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = FieldError;
            fn from_str($s: &str) -> Result<Self, Self::Err> {
                let check: Result<(), FieldError> = $check;
                check.map(|()| Self($s.to_owned()))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        string_serde!($name);
    };
}

fn ensure(ok: bool, msg: &str) -> Result<(), FieldError> {
    if ok {
        Ok(())
    } else {
        Err(FieldError::syntax(msg))
    }
}

/// Words with a meaning of their own in pf or nftables rule syntax, which an
/// alias may not shadow. Kept sorted for binary search.
const RESERVED_ALIAS_WORDS: &[&str] = &[
    "af-to",
    "all",
    "allow-opts",
    "altq",
    "anchor",
    "antispoof",
    "any",
    "binat",
    "binat-anchor",
    "binat-to",
    "bitmask",
    "block",
    "block-policy",
    "buckets",
    "cbq",
    "code",
    "codelq",
    "counter",
    "debug",
    "define",
    "divert-reply",
    "divert-to",
    "drop",
    "dup-to",
    "ether",
    "fairq",
    "fastroute",
    "file",
    "fingerprints",
    "flags",
    "floating",
    "flush",
    "for",
    "fragment",
    "from",
    "global",
    "group",
    "hfsc",
    "hogs",
    "hostid",
    "icmp-type",
    "icmp6-type",
    "if-bound",
    "in",
    "include",
    "inet",
    "inet6",
    "interval",
    "keep",
    "label",
    "limit",
    "linkshare",
    "load",
    "log",
    "loginterface",
    "map",
    "match",
    "max",
    "max-mss",
    "max-src-conn",
    "max-src-conn-rate",
    "max-src-nodes",
    "max-src-states",
    "min-ttl",
    "modulate",
    "nat",
    "nat-anchor",
    "nat-to",
    "no",
    "no-df",
    "no-route",
    "no-sync",
    "nos",
    "on",
    "optimization",
    "os",
    "out",
    "overload",
    "pass",
    "persist",
    "port",
    "prio",
    "priq",
    "probability",
    "proto",
    "qlimit",
    "queue",
    "quick",
    "random",
    "random-id",
    "rdr",
    "rdr-anchor",
    "rdr-to",
    "realtime",
    "reassemble",
    "reject",
    "reply-to",
    "require-order",
    "return",
    "return-icmp",
    "return-icmp6",
    "return-rst",
    "round-robin",
    "route",
    "route-to",
    "rtable",
    "rule",
    "ruleset-optimization",
    "scrub",
    "self",
    "set",
    "set-tos",
    "skip",
    "sloppy",
    "source-hash",
    "source-track",
    "state",
    "state-defaults",
    "state-policy",
    "static-port",
    "sticky-address",
    "synproxy",
    "table",
    "tag",
    "tagged",
    "tbrsize",
    "timeout",
    "to",
    "tos",
    "ttl",
    "upperlimit",
    "urpf-failed",
    "user",
    "vmap",
];

name_type!(
    /// A firewall alias name: a letter or single underscore, then up to 31
    /// letters, digits or underscores; not a rule keyword, service or protocol
    /// name (OPNsense `AliasNameField`).
    AliasName,
    |s| {
        let mut chars = s.chars();
        let syntax = match (chars.next(), chars.next()) {
            (Some(a), None) => a.is_ascii_alphabetic(),
            (Some(a), Some(b)) => {
                (a.is_ascii_alphabetic() || (a == '_' && b != '_'))
                    && (b.is_ascii_alphanumeric() || b == '_')
                    && s.len() <= 31
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
            }
            _ => false,
        };
        if !syntax {
            Err(FieldError::syntax(
                "The name must start with a letter or single underscore, be less than 32 characters and only consist of alphanumeric characters or underscores.",
            ))
        } else if RESERVED_ALIAS_WORDS.binary_search(&s).is_ok() {
            Err(FieldError::callback(format!(
                "The name cannot be the internally reserved keyword \"{s}\"."
            )))
        } else if well_known::service_port(s).is_some() || well_known::protocol_number(s).is_some()
        {
            Err(FieldError::callback(
                "Reserved protocol or service names may not be used.",
            ))
        } else {
            Ok(())
        }
    }
);

name_type!(
    /// A logical interface identifier (`wan`, `lan`, `opt1`, `guest`): lower
    /// case letter first, then lower case letters, digits or underscores, at
    /// most 32 characters. This is the key rules and services refer to; the
    /// kernel device is a separate [`DeviceName`].
    InterfaceId,
    |s| ensure(
        (1..=32).contains(&s.len())
            && s.starts_with(|c: char| c.is_ascii_lowercase())
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_'),
        "An interface identifier must start with a lower case letter and contain only lower case letters, digits and underscores.",
    )
);

name_type!(
    /// A kernel network device name (`eth0`, `enp1s0`, `wg0`, `igb0` when
    /// imported): 1 to 15 bytes (Linux `IFNAMSIZ`), no `/`, `:` or white space,
    /// not `.` or `..`.
    DeviceName,
    |s| ensure(
        (1..=15).contains(&s.len())
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|c| c.is_ascii_graphic() && c != b'/' && c != b':'),
        "A device name must be 1 to 15 characters without slashes, colons or spaces.",
    )
);

name_type!(
    /// A local user name: 1 to 32 letters, digits, `.`, `-` or `_`, not
    /// starting with `-` (a Linux account name as well as an OPNsense one).
    Username,
    |s| ensure(
        (1..=32).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
        "A username must contain a maximum of 32 alphanumeric characters.",
    )
);

name_type!(
    /// A local group name; same alphabet as [`Username`].
    GroupName,
    |s| ensure(
        (1..=32).contains(&s.len())
            && !s.starts_with('-')
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
        "A group name must contain a maximum of 32 alphanumeric characters.",
    )
);

name_type!(
    /// A gateway or gateway group name: 1 to 32 letters, digits, `_` or `-`
    /// (OPNsense `Routing/Gateways.xml`).
    GatewayName,
    |s| ensure(
        (1..=32).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')),
        "A valid gateway name must be specified. The name may only consist of the characters \"a-zA-Z0-9_\" and must be less than 32 characters long.",
    )
);

name_type!(
    /// A WireGuard instance or peer name: 1 to 64 letters, digits, `.`, `_`
    /// or `-`.
    WgName,
    |s| ensure(
        (1..=64).contains(&s.len())
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
        "Should be a string between 1 and 64 characters. Allowed characters are alphanumeric characters, dash and underscores.",
    )
);

name_type!(
    /// An IANA time zone name (`Etc/UTC`, `Europe/Amsterdam`,
    /// `America/Argentina/Buenos_Aires`) or `UTC`. Syntax only: whether the
    /// zone exists is checked against tzdata at apply time.
    Timezone,
    |s| ensure(
        !s.is_empty()
            && s.len() <= 64
            && s.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.starts_with(|c: char| c.is_ascii_alphabetic())
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'+'))
            }),
        "Please select a valid time zone.",
    )
);

name_type!(
    /// A free-text description: 1 to 255 characters on one line, no control
    /// characters (OPNsense `DescriptionField`).
    Description,
    |s| ensure(
        (1..=255).contains(&s.chars().count()) && !s.chars().any(char::is_control),
        "Description should be a string between 1 and 255 characters.",
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_words_sorted() {
        let mut sorted = RESERVED_ALIAS_WORDS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, RESERVED_ALIAS_WORDS);
    }

    #[test]
    fn alias_names() {
        for ok in [
            "a",
            "LAN_hosts",
            "_x1",
            "web_servers",
            &format!("a{}", "b".repeat(30)),
        ] {
            assert!(ok.parse::<AliasName>().is_ok(), "{ok}");
        }
        for bad in [
            "",
            "_",
            "__x",
            "1abc",
            "a-b",
            "a b",
            &format!("a{}", "b".repeat(31)),
        ] {
            assert!(bad.parse::<AliasName>().is_err(), "{bad}");
        }
        let e = "any".parse::<AliasName>().unwrap_err();
        assert_eq!(
            e.message,
            "The name cannot be the internally reserved keyword \"any\"."
        );
        assert!(
            "http".parse::<AliasName>().is_err(),
            "service names are reserved"
        );
        assert!(
            "tcp".parse::<AliasName>().is_err(),
            "protocol names are reserved"
        );
    }

    #[test]
    fn interface_ids_and_devices() {
        assert!("opt1".parse::<InterfaceId>().is_ok());
        assert!("Lan".parse::<InterfaceId>().is_err());
        assert!("1lan".parse::<InterfaceId>().is_err());
        assert!("enp1s0".parse::<DeviceName>().is_ok());
        assert!("vlan0.100".parse::<DeviceName>().is_ok());
        for bad in ["", "a/b", "eth 0", "eth0:1", "abcdefghijklmnop", ".."] {
            assert!(bad.parse::<DeviceName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn users_timezones_descriptions() {
        assert!("root".parse::<Username>().is_ok());
        assert!("-x".parse::<Username>().is_err());
        assert!("Etc/UTC".parse::<Timezone>().is_ok());
        assert!("America/Argentina/Buenos_Aires".parse::<Timezone>().is_ok());
        assert!("Etc/GMT+5".parse::<Timezone>().is_ok());
        assert!("../etc/passwd".parse::<Timezone>().is_err());
        assert!(
            "Default allow LAN to any rule"
                .parse::<Description>()
                .is_ok()
        );
        assert!("two\nlines".parse::<Description>().is_err());
        assert!("".parse::<Description>().is_err());
        assert!("x".repeat(256).parse::<Description>().is_err());
    }
}
