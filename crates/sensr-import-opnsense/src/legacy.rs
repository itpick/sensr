//! Translators for legacy XML shapes that current OPNsense models flatten on load.

use crate::tree::Element;

/// A legacy `<aliases><item><host/><domain/><description/></item>…</aliases>` list
/// flattened the way Dnsmasq's `HostnameField` (`LegacyXML="Y"`) does it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostAliases {
    /// `host.domain` (or just `domain` without a host), in document order.
    pub fqdns: Vec<String>,
    /// `[fqdn] description` for every item that had a description.
    pub comments: Vec<String>,
}

/// PHP's `empty()` on a string: `""` and `"0"` are both empty. Kept so an imported
/// `<host>0</host>` behaves exactly as it did on OPNsense.
fn php_empty(s: &str) -> bool {
    s.is_empty() || s == "0"
}

/// Flatten the legacy alias items under `aliases`. Items without a domain are skipped,
/// as upstream does.
pub fn flatten_host_aliases(aliases: &Element) -> HostAliases {
    let mut out = HostAliases::default();
    for item in aliases.children_named("item") {
        let field = |name: &str| item.child(name).map(Element::text).unwrap_or_default();
        let domain = field("domain");
        if php_empty(&domain) {
            continue;
        }
        let host = field("host");
        let fqdn = if php_empty(&host) {
            domain
        } else {
            format!("{host}.{domain}")
        };
        let description = field("description");
        if !php_empty(&description) {
            out.comments.push(format!("[{fqdn}] {description}"));
        }
        out.fqdns.push(fqdn);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;

    // T-0305: Dnsmasq HostnameFieldTest::testLegacyXML.
    #[test]
    fn legacy_alias_xml_joined_t0305() {
        let doc = parse(
            "<aliases><item><host>www</host><domain>example.com</domain>\
             <description>desc</description></item></aliases>",
        )
        .unwrap();
        let flat = flatten_host_aliases(&doc.root);
        assert!(flat.fqdns.join(",").contains("www.example.com"));
        assert_eq!(flat.comments, ["[www.example.com] desc"]);
    }

    #[test]
    fn hostless_and_domainless_items() {
        let doc = parse(
            "<aliases><item><domain>example.net</domain></item>\
             <item><host>x</host></item>\
             <item><host>0</host><domain>example.org</domain></item></aliases>",
        )
        .unwrap();
        assert_eq!(
            flatten_host_aliases(&doc.root).fqdns,
            ["example.net", "example.org"]
        );
    }
}
