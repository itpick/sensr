//! Reading and writing `config.xml` exactly the way OPNsense does.
//!
//! OPNsense loads the file with `simplexml_load_string(trim($xml), …, LIBXML_NOBLANKS)`
//! and saves it through a fresh `DOMDocument('1.0')` with `formatOutput = true`
//! (`Core/Config.php` `loadFromStream()` / `__toString()`). Reproducing both sides
//! gives two guarantees the importer relies on:
//!
//! - a file OPNsense wrote parses into the same tree libxml builds, including which
//!   whitespace-only text survives (libxml's "blank node" heuristic), and
//! - writing that tree back reproduces OPNsense's bytes, so a file OPNsense wrote
//!   round-trips byte-exactly (T-0002, T-0004) and a re-export can be diffed against
//!   the original.
//!
//! DOCTYPE declarations are rejected rather than parsed: OPNsense never writes one,
//! and refusing them rules out entity-expansion attacks on uploaded backups.

use std::fmt::Write as _;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use crate::tree::{Attribute, Document, Element, Node};

/// Deepest element nesting accepted; libxml's default limit, which OPNsense runs with.
pub const MAX_DEPTH: usize = 256;

/// Why a `config.xml` could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum XmlError {
    /// The input is not UTF-8.
    #[error("config is not valid UTF-8 (byte {0})")]
    NotUtf8(usize),
    /// The XML declaration names an encoding other than UTF-8.
    #[error("unsupported document encoding {0:?}; only UTF-8 is accepted")]
    UnsupportedEncoding(String),
    /// The document is empty (OPNsense: "empty file").
    #[error("empty config")]
    Empty,
    /// Malformed XML.
    #[error("malformed XML at byte {position}: {message}")]
    Syntax {
        /// Byte offset of the error in the (trimmed) input.
        position: u64,
        /// Parser message.
        message: String,
    },
    /// An entity other than the five XML predefined ones or a character reference.
    #[error("unknown entity &{name}; at byte {position}")]
    UnknownEntity {
        /// Entity name without `&` and `;`.
        name: String,
        /// Byte offset of the reference.
        position: u64,
    },
    /// A `<!DOCTYPE>` declaration.
    #[error("DOCTYPE declarations are not accepted")]
    DocType,
    /// Character data or a second element outside the document element.
    #[error("content outside the document element at byte {0}")]
    OutsideRoot(u64),
    /// No document element.
    #[error("no document element")]
    NoRoot,
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("elements nested deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

/// Parse a `config.xml` given as bytes (a leading UTF-8 BOM is ignored).
pub fn parse_bytes(input: &[u8]) -> Result<Document, XmlError> {
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    let s = std::str::from_utf8(input).map_err(|e| XmlError::NotUtf8(e.valid_up_to()))?;
    parse(s)
}

/// Parse a `config.xml`.
pub fn parse(input: &str) -> Result<Document, XmlError> {
    // OPNsense trims the whole file before handing it to libxml.
    let input = input.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');
    if input.is_empty() {
        return Err(XmlError::Empty);
    }
    let mut reader = Reader::from_str(input);
    let cfg = reader.config_mut();
    cfg.check_end_names = true;
    cfg.check_comments = true;
    cfg.expand_empty_elements = false;

    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut pending = PendingText::default();

    loop {
        let position = reader.buffer_position();
        let event = reader.read_event().map_err(|e| XmlError::Syntax {
            position: reader.error_position(),
            message: e.to_string(),
        })?;
        match event {
            Event::Text(t) => {
                if stack.is_empty() {
                    if !t.trim_ascii().is_empty() {
                        return Err(XmlError::OutsideRoot(position));
                    }
                    continue;
                }
                pending.push_raw(&t.xml10_content());
            }
            Event::GeneralRef(r) => {
                if stack.is_empty() {
                    return Err(XmlError::OutsideRoot(position));
                }
                let resolved = if r.is_char_ref() {
                    r.resolve_char_ref()
                        .map_err(|e| XmlError::Syntax {
                            position,
                            message: e.to_string(),
                        })?
                        .map(String::from)
                } else {
                    resolve_predefined_entity(&r).map(String::from)
                };
                match resolved {
                    Some(s) => pending.push_reference(&s),
                    None => {
                        return Err(XmlError::UnknownEntity {
                            name: r.to_string(),
                            position,
                        });
                    }
                }
            }
            Event::Start(start) => {
                let next = NextMarkup::Other;
                if let Some(parent) = stack.last_mut() {
                    pending.flush_into(parent, next);
                } else if root.is_some() {
                    return Err(XmlError::OutsideRoot(position));
                }
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlError::TooDeep);
                }
                stack.push(element_from_start(&start, position)?);
            }
            Event::Empty(start) => {
                let element = element_from_start(&start, position)?;
                match stack.last_mut() {
                    Some(parent) => {
                        pending.flush_into(parent, NextMarkup::Other);
                        parent.children.push(Node::Element(element));
                    }
                    None if root.is_none() => root = Some(element),
                    None => return Err(XmlError::OutsideRoot(position)),
                }
            }
            Event::End(_) => {
                let mut element = stack.pop().ok_or(XmlError::OutsideRoot(position))?;
                pending.flush_into(&mut element, NextMarkup::EndTag);
                match stack.last_mut() {
                    Some(parent) => parent.children.push(Node::Element(element)),
                    None => root = Some(element),
                }
            }
            Event::CData(c) => {
                let Some(parent) = stack.last_mut() else {
                    return Err(XmlError::OutsideRoot(position));
                };
                pending.flush_into(parent, NextMarkup::Other);
                parent
                    .children
                    .push(Node::CData(c.xml10_content().into_owned()));
            }
            Event::Comment(c) => {
                if let Some(parent) = stack.last_mut() {
                    pending.flush_into(parent, NextMarkup::Other);
                    parent
                        .children
                        .push(Node::Comment(c.xml10_content().into_owned()));
                }
                // Comments in the prolog/epilog are dropped: OPNsense never writes them back.
            }
            Event::PI(pi) => {
                if let Some(parent) = stack.last_mut() {
                    pending.flush_into(parent, NextMarkup::Other);
                    parent
                        .children
                        .push(Node::ProcessingInstruction(pi.into_inner().into_owned()));
                }
            }
            Event::Decl(decl) => {
                if let Some(enc) = decl.encoding() {
                    let enc = enc.map_err(|e| XmlError::Syntax {
                        position,
                        message: e.to_string(),
                    })?;
                    let lower = enc.to_ascii_lowercase();
                    if lower != "utf-8" && lower != "utf8" && lower != "us-ascii" {
                        return Err(XmlError::UnsupportedEncoding(enc.into_owned()));
                    }
                }
            }
            Event::DocType(_) => return Err(XmlError::DocType),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(XmlError::Syntax {
            position: input.len() as u64,
            message: "unexpected end of document".into(),
        });
    }
    root.map(|root| Document { root }).ok_or(XmlError::NoRoot)
}

fn element_from_start(start: &BytesStart<'_>, position: u64) -> Result<Element, XmlError> {
    let syntax = |message: String| XmlError::Syntax { position, message };
    let name = start.name().as_ref().to_owned();
    let mut attributes = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(|e| syntax(e.to_string()))?;
        let value =
            attr.normalized_value(XmlVersion::Implicit1_0)
                .map_err(|e| match e {
                    quick_xml::Error::Escape(
                        quick_xml::escape::EscapeError::UnrecognizedEntity(_, name),
                    ) => XmlError::UnknownEntity { name, position },
                    other => syntax(other.to_string()),
                })?;
        attributes.push(Attribute {
            name: attr.key.as_ref().to_owned(),
            value: value.into_owned(),
        });
    }
    Ok(Element {
        name,
        attributes,
        children: Vec::new(),
    })
}

/// What follows a run of character data (libxml looks one byte ahead).
#[derive(Clone, Copy, PartialEq, Eq)]
enum NextMarkup {
    /// `</…` — the end tag of the current element.
    EndTag,
    /// Any other markup: a start tag, comment, CDATA section or PI.
    Other,
}

/// Character data collected between two pieces of markup.
#[derive(Default)]
struct PendingText {
    text: String,
    /// Whether the run contained a reference; a reference is never "blank" to libxml.
    has_reference: bool,
}

impl PendingText {
    fn push_raw(&mut self, s: &str) {
        self.text.push_str(s);
    }

    fn push_reference(&mut self, s: &str) {
        self.text.push_str(s);
        self.has_reference = true;
    }

    /// Append the run to `parent`, unless libxml would discard it as an ignorable blank.
    fn flush_into(&mut self, parent: &mut Element, next: NextMarkup) {
        let text = std::mem::take(&mut self.text);
        let has_reference = std::mem::replace(&mut self.has_reference, false);
        if text.is_empty() {
            return;
        }
        let blank = !has_reference
            && text
                .bytes()
                .all(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
        if blank && is_ignorable_blank(parent, next) {
            return;
        }
        match parent.children.last_mut() {
            Some(Node::Text(prev)) => prev.push_str(&text),
            _ => parent.children.push(Node::Text(text)),
        }
    }
}

/// libxml's `areBlanks()` heuristic under `LIBXML_NOBLANKS` (no DTD, no `xml:space`):
/// whitespace is kept when it is the whole content of an element (`<x> </x>`) or sits
/// next to other character data, and dropped when it only separates markup.
fn is_ignorable_blank(parent: &Element, next: NextMarkup) -> bool {
    if parent.children.is_empty() && next == NextMarkup::EndTag {
        return false;
    }
    if matches!(parent.children.last(), Some(Node::Text(_))) {
        return false;
    }
    if matches!(parent.children.first(), Some(Node::Text(_))) {
        return false;
    }
    if parent
        .attributes
        .iter()
        .any(|a| a.name == "xml:space" && a.value == "preserve")
    {
        return false;
    }
    true
}

/// Serialise a document exactly as OPNsense's `Config::__toString()` does: an
/// `<?xml version="1.0"?>` line, a fresh attribute-less `<opnsense>` root holding the
/// original root's child elements (other root-level nodes are dropped), libxml
/// `formatOutput` indentation, and a trailing newline.
pub fn to_config_string(doc: &Document) -> String {
    let mut out = String::with_capacity(64 * 1024);
    out.push_str("<?xml version=\"1.0\"?>\n");
    let root = Element {
        name: "opnsense".into(),
        attributes: Vec::new(),
        children: doc
            .root
            .children
            .iter()
            .filter(|n| matches!(n, Node::Element(_)))
            .cloned()
            .collect(),
    };
    write_element(&mut out, &root, 0, true);
    out.push('\n');
    out
}

/// Serialise one element as libxml's `asXML()`/`saveXML($node)` does with formatting on,
/// without a declaration or trailing newline (e.g. `<lan/>`).
pub fn element_to_string(element: &Element) -> String {
    let mut out = String::new();
    write_element(&mut out, element, 0, true);
    out
}

fn write_element(out: &mut String, e: &Element, level: usize, format: bool) {
    out.push('<');
    out.push_str(&e.name);
    for a in &e.attributes {
        out.push(' ');
        out.push_str(&a.name);
        out.push_str("=\"");
        escape_attribute(out, &a.value);
        out.push('"');
    }
    if e.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    // libxml switches indentation off for any element holding character data, so mixed
    // content (and everything below it) is written exactly as stored.
    let format = format
        && !e
            .children
            .iter()
            .any(|n| matches!(n, Node::Text(_) | Node::CData(_)));
    if format {
        out.push('\n');
    }
    for child in &e.children {
        if format {
            indent(out, level + 1);
        }
        match child {
            Node::Element(c) => write_element(out, c, level + 1, format),
            Node::Text(t) => escape_text(out, t),
            Node::CData(t) => {
                out.push_str("<![CDATA[");
                out.push_str(t);
                out.push_str("]]>");
            }
            Node::Comment(t) => {
                out.push_str("<!--");
                out.push_str(t);
                out.push_str("-->");
            }
            Node::ProcessingInstruction(t) => {
                out.push_str("<?");
                out.push_str(t);
                out.push_str("?>");
            }
        }
        if format {
            out.push('\n');
        }
    }
    if format {
        indent(out, level);
    }
    out.push_str("</");
    out.push_str(&e.name);
    out.push('>');
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

/// Text escaping of libxml with no output encoding (`DOMDocument('1.0')`): markup
/// characters as entities, CR and every non-ASCII character as character references.
fn escape_text(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\r' => out.push_str("&#13;"),
            c if c.is_ascii() => out.push(c),
            c => {
                let _ = write!(out, "&#x{:X};", u32::from(c));
            }
        }
    }
}

/// Attribute escaping of libxml: as text, plus `"` and the whitespace characters that
/// attribute-value normalisation would otherwise turn into spaces.
fn escape_attribute(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c if c.is_ascii() => out.push(c),
            c => {
                let _ = write!(out, "&#x{:X};", u32::from(c));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;
    use crate::view::{Value, to_array};
    use pretty_assertions::assert_eq;

    fn reparse(s: &str) -> String {
        to_config_string(&parse(s).expect("parses"))
    }

    // T-0002: Core/ConfigTest::test_to_from_array.
    #[test]
    fn listtags_single_vs_repeated_children_t0002() {
        let doc = parse(&fixtures::read("opnsense/ConfigConfig/array.xml")).unwrap();

        // No force list: the lone sysctl/item flattens to its keys, the repeated
        // filter/rule becomes a list anyway.
        let plain = to_array(&doc.root, &|_| false);
        let item = plain.get("sysctl").and_then(|v| v.get("item")).unwrap();
        assert!(matches!(item, Value::Map(m) if m.len() == 2));
        let rules = plain.get("filter").and_then(|v| v.get("rule")).unwrap();
        assert!(matches!(rules, Value::List(l) if l.len() == 2));

        // Forcing item and rule: item becomes a one-element list, rule unchanged.
        let forced = to_array(&doc.root, &|n| n == "item" || n == "rule");
        let item = forced.get("sysctl").and_then(|v| v.get("item")).unwrap();
        assert!(matches!(item, Value::List(l) if l.len() == 1));
        let rules = forced.get("filter").and_then(|v| v.get("rule")).unwrap();
        assert!(matches!(rules, Value::List(l) if l.len() == 2));
    }

    // T-0002: array -> XML -> string is byte-exact, attributes (version, persisted_at,
    // description) included.
    #[test]
    fn roundtrip_array_fixture_byte_exact_t0002() {
        let original = fixtures::read("opnsense/ConfigConfig/array.xml");
        let doc = parse(&original).unwrap();
        let array = to_array(&doc.root, &|n| n == "item" || n == "rule");
        let rebuilt = crate::view::from_array("opnsense", &array);
        assert_eq!(
            to_config_string(&Document { root: rebuilt }),
            original,
            "fromArray(toArray()) must reproduce the file"
        );
        assert_eq!(reparse(&original), original);
        let unbound = doc.root.child("unbound").unwrap();
        assert_eq!(unbound.attribute("version"), Some("1.0.13"));
        assert_eq!(unbound.attribute("persisted_at"), Some("1762794040.38"));
    }

    // T-0003: Core/ConfigTest::testCanBeObject.
    #[test]
    fn load_object_fixture_t0003() {
        let doc = parse(&fixtures::read("opnsense/ConfigConfig/object.xml")).unwrap();
        assert_eq!(
            doc.root.path_text(&["dhcpdv6", "lan", "ramode"]).as_deref(),
            Some("disabled")
        );
    }

    // T-0004: Core/ConfigTest::test_to_from_object.
    #[test]
    fn remove_and_readd_child_roundtrip_t0004() {
        let original = fixtures::read("opnsense/ConfigConfig/object.xml");
        let mut doc = parse(&original).unwrap();
        let lan = doc
            .root
            .child_mut("dhcpdv6")
            .unwrap()
            .child_mut("lan")
            .unwrap();
        let ramode = lan.child("ramode").unwrap().text();
        assert_eq!(lan.remove_children("ramode"), 1);
        assert_eq!(element_to_string(lan), "<lan/>");
        lan.push_element(Element::with_text("ramode", ramode));
        assert_eq!(to_config_string(&doc), original);
    }

    // T-0320: service/tests/template.py TestConfigMethods::test_type.
    #[test]
    fn service_fixture_parses_t0320() {
        let doc = parse(&fixtures::read("opnsense/ServiceTests/config.xml")).unwrap();
        let array = to_array(&doc.root, &crate::listtags::is_list_tag);
        let Value::Map(map) = &array else {
            panic!("root must be an ordered map, got {array:?}")
        };
        // Ordered: keys come out in document order.
        let keys: Vec<&str> = map.iter().map(|(k, _)| k.as_str()).collect();
        let doc_order: Vec<&str> = doc.root.elements().map(|e| e.name.as_str()).collect();
        let mut dedup = doc_order.clone();
        dedup.dedup();
        assert_eq!(keys, dedup);
    }

    // T-0321: service/tests/template.py TestConfigMethods::test_interface.
    #[test]
    fn service_fixture_lan_ipaddr_t0321() {
        let doc = parse(&fixtures::read("opnsense/ServiceTests/config.xml")).unwrap();
        let array = to_array(&doc.root, &crate::listtags::is_list_tag);
        let lan = array.get("interfaces").and_then(|v| v.get("lan")).unwrap();
        assert!(lan.get("ipaddr").is_some(), "lan address missing");
    }

    #[test]
    fn blank_text_heuristic_matches_libxml() {
        // Indentation between elements is dropped, whitespace as an element's whole
        // content is kept, whitespace next to text is kept.
        let doc =
            parse("<opnsense>\n  <a> </a>\n  <b>x <c/> </b>\n  <d>\n  </d>\n</opnsense>").unwrap();
        let a = doc.root.child("a").unwrap();
        assert_eq!(a.children, vec![Node::Text(" ".into())]);
        let b = doc.root.child("b").unwrap();
        assert_eq!(b.children.len(), 3);
        assert_eq!(doc.root.children.len(), 3);
        assert_eq!(doc.root.child("d").unwrap().text(), "\n  ");
    }

    #[test]
    fn writer_escapes_like_libxml() {
        let root = Element::new("opnsense")
            .child_element(Element::with_text("t", "a<b>&c\"d'\r\u{e9}").attr("q", "x\"y\n\t&<>"));
        assert_eq!(
            to_config_string(&Document { root }),
            "<?xml version=\"1.0\"?>\n<opnsense>\n  <t q=\"x&quot;y&#10;&#9;&amp;&lt;&gt;\">a&lt;b&gt;&amp;c\"d'&#13;&#xE9;</t>\n</opnsense>\n"
        );
    }

    #[test]
    fn references_are_resolved_and_reescaped() {
        let s = "<?xml version=\"1.0\"?>\n<opnsense>\n  <x a=\"&#65;&amp;\">&#x41;&lt;&apos;&quot;</x>\n</opnsense>\n";
        let doc = parse(s).unwrap();
        let x = doc.root.child("x").unwrap();
        assert_eq!(x.text(), "A<'\"");
        assert_eq!(x.attribute("a"), Some("A&"));
        assert_eq!(
            to_config_string(&doc),
            "<?xml version=\"1.0\"?>\n<opnsense>\n  <x a=\"A&amp;\">A&lt;'\"</x>\n</opnsense>\n"
        );
    }

    #[test]
    fn root_is_renamed_and_loses_attributes_and_non_element_children() {
        let doc = parse("<pfsense a=\"1\"><!--c--><x/>text</pfsense>");
        // Text directly under the root next to an element is kept by libxml, so the
        // parse succeeds; the writer then drops it as OPNsense does.
        let doc = doc.unwrap();
        assert_eq!(doc.root.name, "pfsense");
        assert_eq!(
            to_config_string(&doc),
            "<?xml version=\"1.0\"?>\n<opnsense>\n  <x/>\n</opnsense>\n"
        );
    }

    #[test]
    fn mixed_content_is_written_unformatted() {
        let s = "<?xml version=\"1.0\"?>\n<opnsense>\n  <m>a<b><c/></b>z</m>\n  <n>\n    <!--note-->\n  </n>\n  <d><![CDATA[<x>]]></d>\n</opnsense>\n";
        assert_eq!(reparse(s), s);
    }

    #[test]
    fn rejects_doctype_unknown_entities_and_garbage() {
        assert!(matches!(
            parse("<!DOCTYPE x [<!ENTITY e \"boom\">]><opnsense>&e;</opnsense>"),
            Err(XmlError::DocType)
        ));
        assert!(matches!(
            parse("<opnsense>&nbsp;</opnsense>"),
            Err(XmlError::UnknownEntity { .. })
        ));
        assert!(matches!(parse("  \n"), Err(XmlError::Empty)));
        assert!(matches!(parse("<a></b>"), Err(XmlError::Syntax { .. })));
        assert!(matches!(parse("<a>"), Err(XmlError::Syntax { .. })));
        assert!(matches!(parse("<a/><b/>"), Err(XmlError::OutsideRoot(_))));
        assert!(matches!(
            parse("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>"),
            Err(XmlError::UnsupportedEncoding(_))
        ));
        assert!(matches!(
            parse_bytes(b"<a>\xff</a>"),
            Err(XmlError::NotUtf8(3))
        ));
        let deep = "<a>".repeat(MAX_DEPTH + 1) + &"</a>".repeat(MAX_DEPTH + 1);
        assert!(matches!(parse(&deep), Err(XmlError::TooDeep)));
    }

    #[test]
    fn bom_and_surrounding_whitespace_are_ignored() {
        let doc = parse_bytes(b"\xEF\xBB\xBF \n<opnsense><x>1</x></opnsense>\n\n").unwrap();
        assert_eq!(doc.root.path_text(&["x"]).as_deref(), Some("1"));
    }

    // Every upstream fixture and every corpus file: parse -> write is idempotent, and
    // files that OPNsense itself wrote (canonical form) are reproduced byte-exactly.
    #[test]
    fn every_fixture_roundtrips() {
        for (path, text) in fixtures::all_xml() {
            let once = reparse(&text);
            assert_eq!(reparse(&once), once, "{path}: writer output not stable");
            if fixtures::is_canonical(&path) {
                assert_eq!(once, text, "{path}: canonical fixture not byte-exact");
            }
        }
    }

    proptest::proptest! {
        // Parsing arbitrary input never panics, and anything that parses round-trips
        // through the writer to the same tree (modulo what OPNsense itself drops).
        #[test]
        fn prop_parse_never_panics(s in ".{0,200}") {
            let _ = parse(&s);
        }

        #[test]
        fn prop_text_roundtrips(t in "[^\u{0}-\u{8}\u{b}\u{c}\u{e}-\u{1f}\u{fffe}\u{ffff}]{0,40}") {
            let root = Element::new("opnsense")
                .child_element(Element::with_text("v", t.clone()).attr("a", t.clone()));
            let doc = Document { root };
            let written = to_config_string(&doc);
            let back = parse(&written).unwrap();
            let v = back.root.child("v").unwrap();
            // Whitespace-only element content survives (libxml keeps it), so the text
            // is exact; CR survives because it is written as a character reference.
            proptest::prop_assert_eq!(v.text(), t.clone());
            proptest::prop_assert_eq!(v.attribute("a"), Some(t.as_str()));
        }
    }
}
