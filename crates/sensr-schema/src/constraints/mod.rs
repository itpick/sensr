//! Cross-field and cross-item constraints (OPNsense counterpart:
//! `Base/Constraints/*`).
//!
//! Each constraint is a pure function over the values involved, so the
//! derive macro, hand-written model validation and the compat layer all use
//! the same rules. Values are anything implementing [`ConstraintValue`]:
//! raw text (OPNsense semantics: `""` is unset, `""` and `"0"` are empty),
//! `bool`, numbers, `Option<T>` (`None` is unset) and the field newtypes.
//!
//! OPNsense takes the message from the model's `ValidationMessage`; callers
//! pass theirs. The constants here are the defaults sensr uses.

mod all_or_none;
mod compared;
mod depend;
mod set;
mod set_if;
mod single_select;
mod unique;

pub use all_or_none::all_or_none;
pub use compared::{Comparison, compared};
pub use depend::depend;
pub use set::set;
pub use set_if::set_if;
pub use single_select::single_select;
pub use unique::{UniqueOptions, unique};

/// A value as constraints see it.
pub trait ConstraintValue {
    /// The value as text (`""` when unset).
    fn text(&self) -> String;

    /// OPNsense `isSet()`: the text is non-empty.
    fn is_set(&self) -> bool {
        !self.text().is_empty()
    }

    /// OPNsense `isEmpty()` (PHP `empty()`): unset, `"0"` or false.
    /// (Named apart from `str::is_empty`, which means something else.)
    fn is_blank(&self) -> bool {
        let t = self.text();
        t.is_empty() || t == "0"
    }

    /// The value as a number, if it is one.
    fn as_f64(&self) -> Option<f64> {
        let t = self.text();
        crate::fields::numbers_is_numeric(&t)
            .then(|| t.trim().parse().ok())
            .flatten()
    }
}

impl ConstraintValue for str {
    fn text(&self) -> String {
        self.to_owned()
    }
}

impl ConstraintValue for String {
    fn text(&self) -> String {
        self.clone()
    }
}

impl ConstraintValue for bool {
    fn text(&self) -> String {
        if *self { "1".into() } else { "0".into() }
    }
}

macro_rules! numeric_value {
    ($($t:ty),*) => {$(
        impl ConstraintValue for $t {
            fn text(&self) -> String {
                self.to_string()
            }
        }
    )*};
}
numeric_value!(u8, u16, u32, u64, i32, i64, f64);

impl<T: ConstraintValue> ConstraintValue for Option<T> {
    fn text(&self) -> String {
        self.as_ref().map(ConstraintValue::text).unwrap_or_default()
    }
}

impl<T: ConstraintValue + ?Sized> ConstraintValue for &T {
    fn text(&self) -> String {
        (**self).text()
    }
}

impl<T: ConstraintValue> ConstraintValue for Vec<T> {
    /// Lists join with commas, as OPNsense stores them.
    fn text(&self) -> String {
        self.iter()
            .map(ConstraintValue::text)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Implements [`ConstraintValue`] through `Display` for field newtypes.
macro_rules! display_value {
    ($($t:ty),*) => {$(
        impl ConstraintValue for $t {
            fn text(&self) -> String {
                self.to_string()
            }
        }
    )*};
}
display_value!(
    crate::fields::Hostname,
    crate::fields::DomainName,
    crate::fields::Host,
    crate::fields::MacAddr,
    crate::fields::Port,
    crate::fields::PortRange,
    crate::fields::PortSpec,
    crate::fields::Protocol,
    crate::fields::NetOrAlias,
    crate::fields::AliasName,
    crate::fields::InterfaceId,
    crate::fields::DeviceName,
    crate::fields::Username,
    crate::fields::WgName,
    crate::fields::WgKey,
    crate::fields::Description,
    crate::fields::HexBytes,
    ipnet::IpNet,
    ipnet::Ipv4Net,
    ipnet::Ipv6Net,
    std::net::IpAddr,
    std::net::Ipv4Addr,
    std::net::Ipv6Addr
);

/// Default messages.
pub mod messages {
    /// [`super::unique`].
    pub const UNIQUE: &str = "This value must be unique.";
    /// [`super::all_or_none`].
    pub const ALL_OR_NONE: &str = "All fields should contain data or none of them.";
    /// [`super::single_select`].
    pub const SINGLE_SELECT: &str = "Only one option could be selected.";
    /// [`super::set`] and [`super::depend`].
    pub const REQUIRED_WITH: &str = "This field is required when the related field is set.";
    /// [`super::set_if`].
    pub const REQUIRED_IF: &str = "This field is required.";
    /// [`super::compared`].
    pub const COMPARED: &str = "The value is out of range compared to the related field.";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_semantics() {
        assert!(!"".is_set() && "".is_blank());
        assert!("0".is_set() && "0".is_blank());
        assert!(!false.is_set() || false.is_blank());
        assert!(!None::<u16>.is_set());
        assert_eq!(Some(5u16).as_f64(), Some(5.0));
        assert_eq!("x".as_f64(), None);
        assert_eq!(vec!["a", "b"].text(), "a,b");
    }
}
