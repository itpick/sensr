//! Field types.
//!
//! Two layers:
//!
//! - **Newtypes** (`Hostname`, `MacAddr`, `Port`, `NetOrAlias`, ...): parsed,
//!   validated values that cannot hold invalid data. Every one implements
//!   `FromStr` (never panics; property-tested), `Display` (the canonical text
//!   form, which `FromStr` accepts back) and serde as that string, so the
//!   JSON document stays readable and diffable. Models are built from these.
//! - **Configurable fields** ([`Field<T>`] over `*Field` kinds such as
//!   [`PortField`], [`TextField`], [`OptionField`]): raw text with OPNsense's
//!   per-field options and validation semantics, for importer, compat API
//!   and form validation.

mod countries;
mod csv_list;
pub mod field;
mod hostname;
mod keys;
mod mac;
mod misc;
mod names;
mod net;
mod numbers;
mod option;
mod port;
mod protocol;
mod secret;
mod text;
pub mod well_known;

pub use countries::{COUNTRIES, country_name};
pub use csv_list::CsvListField;
pub use field::{ChangeCase, Ctx, Field, FieldType, Mask};
pub use hostname::{DomainName, Host, HostOverrideName, Hostname};
pub use keys::{SshPublicKey, WgKey};
pub use mac::MacAddr;
pub use misc::{CountryCode, HexBytes, HttpUrl};
pub use names::{
    AliasName, Description, DeviceName, GroupName, InterfaceId, Timezone, Username, WgName,
};
pub use net::{AddressRange, IpFamily, NetOrAlias};
pub use numbers::{AutoNumberField, BooleanField, IntegerField, NumericField};
pub use option::{CountryField, OptionEntry, OptionField, OptionList};
pub use port::{Port, PortField, PortRange, PortSpec};
pub use protocol::{Protocol, ProtocolField};
pub use secret::{REDACTED, Secret, redacted};
pub use text::{Base64Field, EmailField, TextField, UpdateOnlyTextField, is_email};

/// Implements `Serialize`/`Deserialize` through `Display`/`FromStr`.
macro_rules! string_serde {
    ($t:ty) => {
        impl ::serde::Serialize for $t {
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $t {
            fn deserialize<D: ::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <::std::borrow::Cow<'de, str> as ::serde::Deserialize>::deserialize(d)?;
                s.parse().map_err(::serde::de::Error::custom)
            }
        }
    };
}
pub(crate) use string_serde;

#[cfg(test)]
mod never_panic {
    //! Every `FromStr` in this module must reject garbage without panicking,
    //! and every accepted value must survive a Display/FromStr round trip.

    use super::*;
    use proptest::prelude::*;
    use std::fmt::Display;
    use std::str::FromStr;

    fn roundtrip<T: FromStr + Display + PartialEq + std::fmt::Debug>(s: &str) {
        if let Ok(v) = s.parse::<T>() {
            let again: T = v
                .to_string()
                .parse()
                .unwrap_or_else(|_| panic!("canonical form of {s:?} ({v}) must parse"));
            assert_eq!(v, again);
        }
    }

    proptest! {
        #[test]
        fn prop_from_str_never_panics(s in "\\PC{0,80}") {
            roundtrip::<Hostname>(&s);
            roundtrip::<DomainName>(&s);
            roundtrip::<Host>(&s);
            roundtrip::<HostOverrideName>(&s);
            roundtrip::<MacAddr>(&s);
            roundtrip::<AliasName>(&s);
            roundtrip::<InterfaceId>(&s);
            roundtrip::<DeviceName>(&s);
            roundtrip::<Username>(&s);
            roundtrip::<GroupName>(&s);
            roundtrip::<WgName>(&s);
            roundtrip::<Timezone>(&s);
            roundtrip::<Description>(&s);
            roundtrip::<NetOrAlias>(&s);
            roundtrip::<AddressRange>(&s);
            roundtrip::<Port>(&s);
            roundtrip::<PortRange>(&s);
            roundtrip::<PortSpec>(&s);
            roundtrip::<Protocol>(&s);
            roundtrip::<WgKey>(&s);
            roundtrip::<SshPublicKey>(&s);
            roundtrip::<HttpUrl>(&s);
            roundtrip::<CountryCode>(&s);
            roundtrip::<HexBytes>(&s);
        }

        #[test]
        fn prop_structured_inputs_never_panic(
            a in "[0-9a-fA-F:./\\-]{0,40}",
            b in "(alias|net|addr):[a-z0-9_]{0,12}",
        ) {
            roundtrip::<NetOrAlias>(&a);
            roundtrip::<NetOrAlias>(&b);
            roundtrip::<MacAddr>(&a);
            roundtrip::<AddressRange>(&a);
            roundtrip::<PortSpec>(&a);
            roundtrip::<PortSpec>(&b);
        }
    }
}
