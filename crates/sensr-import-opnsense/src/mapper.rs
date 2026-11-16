//! The mapper framework: section mappers turn parts of the [`Document`] tree into the
//! sensr document, and the framework proves nothing was skipped.
//!
//! A mapper claims one or more section paths (`system`, `nat/rule`,
//! `OPNsense/Firewall/Alias`) and reads them through a [`MapContext`], whose
//! accessors record every element they touch. After all mappers ran, every element
//! nobody touched is reported — as *expected* when it matches a known pattern (with
//! the reason), otherwise as *unexpected* — together with its XML, so the user sees
//! exactly what did not come across and nothing is silently dropped.
//!
//! Mappers are generic over the output document `D` so the framework does not depend
//! on which model crate defines it.

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::str::FromStr;

use crate::report::{ImportReport, Mapped, Severity, Unmapped, Warning};
use crate::tree::{Document, Element};
use crate::xml::element_to_string;

/// Maps one or more `config.xml` sections into the output document `D`.
pub trait Mapper<D> {
    /// Short name shown in the report (`system`, `firewall-alias`, …).
    fn name(&self) -> &'static str;

    /// Section paths below the root this mapper handles, `/`-separated
    /// (`"OPNsense/Firewall/Alias"`). A path whose last element repeats (`"nat/rule"`)
    /// calls [`Mapper::map`] once per occurrence.
    fn sections(&self) -> &'static [&'static str];

    /// Map one section element. Everything read through `ctx` counts as mapped.
    fn map<'doc>(&self, section: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut D);

    /// Patterns (see [`Importer::expect_unmapped`]) this mapper deliberately ignores, with why.
    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Runs after every mapper has mapped its sections, for cross-section fix-ups.
    fn finish<'doc>(&self, _doc: &'doc Document, _ctx: &mut MapContext<'doc>, _out: &mut D) {}
}

/// Tracks which elements were consumed and collects warnings while mappers run.
pub struct MapContext<'doc> {
    xpaths: HashMap<usize, String>,
    consumed: HashSet<usize>,
    whole: HashSet<usize>,
    warnings: Vec<Warning>,
    _doc: std::marker::PhantomData<&'doc Document>,
}

/// Elements are identified by address: the tree is borrowed immutably for the whole
/// import, so addresses are stable and unique.
fn id(e: &Element) -> usize {
    std::ptr::from_ref(e) as usize
}

impl<'doc> MapContext<'doc> {
    fn new(doc: &'doc Document) -> Self {
        let mut xpaths = HashMap::new();
        index_xpaths(&doc.root, format!("/{}", doc.root.name), &mut xpaths);
        Self {
            xpaths,
            consumed: HashSet::new(),
            whole: HashSet::new(),
            warnings: Vec::new(),
            _doc: std::marker::PhantomData,
        }
    }

    /// XPath of `e` in the source document (`/opnsense/filter/rule[2]`, or
    /// `…/alias[@uuid='…']` for MVC items).
    pub fn xpath(&self, e: &Element) -> String {
        self.xpaths
            .get(&id(e))
            .cloned()
            .unwrap_or_else(|| format!("(detached)/{}", e.name))
    }

    /// Mark `e` itself as mapped; its children still need mapping individually.
    pub fn consume(&mut self, e: &'doc Element) {
        self.consumed.insert(id(e));
    }

    /// Mark `e` and everything below it as mapped.
    pub fn consume_subtree(&mut self, e: &'doc Element) {
        self.consumed.insert(id(e));
        self.whole.insert(id(e));
    }

    /// Undo every consumption in `e`'s subtree, so an item a mapper gave up on is
    /// reported whole as unmapped instead of half-mapped.
    pub fn release(&mut self, e: &Element) {
        self.consumed.remove(&id(e));
        self.whole.remove(&id(e));
        for c in e.elements() {
            self.release(c);
        }
    }

    /// The first child named `name`, marked as mapped.
    pub fn child(&mut self, parent: &'doc Element, name: &str) -> Option<&'doc Element> {
        let c = parent.child(name)?;
        self.consume(c);
        Some(c)
    }

    /// All children named `name`, each marked as mapped.
    pub fn children(&mut self, parent: &'doc Element, name: &str) -> Vec<&'doc Element> {
        let found: Vec<&'doc Element> = parent.elements().filter(|e| e.name == name).collect();
        for c in &found {
            self.consume(c);
        }
        found
    }

    /// Text of the leaf `name` (consumed with any subtree), if present.
    pub fn text(&mut self, parent: &'doc Element, name: &str) -> Option<String> {
        let c = parent.child(name)?;
        self.consume_subtree(c);
        Some(c.text())
    }

    /// Text of the leaf `name`, `None` when absent or empty (OPNsense's "not set").
    pub fn non_empty(&mut self, parent: &'doc Element, name: &str) -> Option<String> {
        self.text(parent, name).filter(|t| !t.is_empty())
    }

    /// A legacy flag: present means true (`isset()`, so `<enable/>` is true), except
    /// an explicit `0`, which the pages that test with `empty()` treat as false and
    /// newer pages write for "off".
    pub fn flag(&mut self, parent: &'doc Element, name: &str) -> bool {
        self.text(parent, name).is_some_and(|t| t.trim() != "0")
    }

    /// An MVC boolean: `1` is true, anything else (including absence) false.
    pub fn bool01(&mut self, parent: &'doc Element, name: &str) -> bool {
        self.text(parent, name).is_some_and(|t| t.trim() == "1")
    }

    /// Parse the non-empty leaf `name` as `T`; an unparsable value is reported as
    /// [`Severity::Invalid`] at that leaf and yields `None`.
    pub fn parse<T>(&mut self, parent: &'doc Element, name: &str) -> Option<T>
    where
        T: FromStr,
        T::Err: Display,
    {
        let c = parent.child(name)?;
        self.consume_subtree(c);
        let text = c.text();
        if text.is_empty() {
            return None;
        }
        match text.parse() {
            Ok(v) => Some(v),
            Err(e) => {
                self.warn(
                    c,
                    Severity::Invalid,
                    format!("value {text:?} not imported: {e}"),
                );
                None
            }
        }
    }

    /// Consume the listed leaves of `parent` when they hold their default (empty, or
    /// the given text). A leaf with any other value stays unconsumed and so surfaces
    /// in the report: sensr has no equivalent for it, and a non-default setting must
    /// never vanish quietly.
    pub fn defaults(&mut self, parent: &'doc Element, fields: &[(&str, &str)]) {
        for (name, default) in fields {
            for c in parent.elements().filter(|e| e.name == *name) {
                if c.has_element_children() {
                    continue;
                }
                let text = c.text();
                if text.trim().is_empty() || text == *default {
                    self.consume_subtree(c);
                }
            }
        }
    }

    /// Attach a warning to `at`.
    pub fn warn(&mut self, at: &Element, severity: Severity, message: impl Into<String>) {
        let xpath = self.xpath(at);
        self.warnings.push(Warning {
            xpath,
            severity,
            message: message.into(),
        });
    }
}

fn index_xpaths(e: &Element, path: String, out: &mut HashMap<usize, String>) {
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for c in e.elements() {
        *seen.entry(c.name.as_str()).or_default() += 1;
    }
    let mut position: HashMap<&str, usize> = HashMap::new();
    for c in e.elements() {
        let n = position.entry(c.name.as_str()).or_default();
        *n += 1;
        let step = match c.attribute("uuid") {
            Some(uuid) if !uuid.contains('\'') => format!("{}[@uuid='{uuid}']", c.name),
            _ if seen[c.name.as_str()] > 1 => format!("{}[{n}]", c.name),
            _ => c.name.clone(),
        };
        index_xpaths(c, format!("{path}/{step}"), out);
    }
    out.insert(id(e), path);
}

/// The result of an import.
#[derive(Debug)]
pub struct Imported<D> {
    /// The sensr-side document the mappers built.
    pub document: D,
    /// What happened to every node.
    pub report: ImportReport,
}

/// A set of mappers plus the patterns of nodes that are fine to leave unmapped.
pub struct Importer<D> {
    mappers: Vec<Box<dyn Mapper<D>>>,
    expected: Vec<(&'static str, &'static str)>,
}

impl<D> Default for Importer<D> {
    fn default() -> Self {
        Self {
            mappers: Vec::new(),
            expected: Vec::new(),
        }
    }
}

impl<D: Default> Importer<D> {
    /// An importer with no mappers.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapper; mappers run in the order they are added.
    #[must_use]
    pub fn with_mapper(mut self, mapper: impl Mapper<D> + 'static) -> Self {
        self.mappers.push(Box::new(mapper));
        self
    }

    /// Declare that nodes matching `pattern` may stay unmapped, for `reason`.
    ///
    /// Patterns are `/`-separated element-name paths below the root, without
    /// predicates. A segment may end in `*` to match a name prefix, `*` alone matches
    /// any one name and `**` any number of levels: `system/powerd_*`,
    /// `OPNsense/IDS/**`.
    #[must_use]
    pub fn expect_unmapped(mut self, pattern: &'static str, reason: &'static str) -> Self {
        self.expected.push((pattern, reason));
        self
    }

    /// Run every mapper over `doc` and account for every element.
    pub fn import(&self, doc: &Document) -> Imported<D> {
        let mut ctx = MapContext::new(doc);
        let mut out = D::default();
        let mut mapped = Vec::new();
        for mapper in &self.mappers {
            for section in mapper.sections() {
                let segments: Vec<&str> = section.split('/').collect();
                for element in find_all(&doc.root, &segments) {
                    ctx.consume(element);
                    mapped.push(Mapped {
                        xpath: ctx.xpath(element),
                        mapper: mapper.name(),
                    });
                    mapper.map(element, &mut ctx, &mut out);
                }
            }
        }
        for mapper in &self.mappers {
            mapper.finish(doc, &mut ctx, &mut out);
        }

        let expected: Vec<(&str, &str)> = self
            .expected
            .iter()
            .copied()
            .chain(
                self.mappers
                    .iter()
                    .flat_map(|m| m.expected_unmapped().iter().copied()),
            )
            .collect();
        let mut report = ImportReport {
            mapped,
            warnings: std::mem::take(&mut ctx.warnings),
            ..ImportReport::default()
        };
        let mut names = Vec::new();
        for child in doc.root.elements() {
            collect_unmapped(child, &mut names, &ctx, &expected, &mut report);
        }
        Imported {
            document: out,
            report,
        }
    }
}

fn find_all<'a>(root: &'a Element, segments: &[&str]) -> Vec<&'a Element> {
    let mut current = vec![root];
    for seg in segments {
        current = current
            .into_iter()
            .flat_map(|e| e.elements().filter(move |c| c.name == *seg))
            .collect();
    }
    current
}

fn any_consumed(e: &Element, ctx: &MapContext<'_>) -> bool {
    ctx.consumed.contains(&id(e)) || e.elements().any(|c| any_consumed(c, ctx))
}

fn collect_unmapped<'a>(
    e: &'a Element,
    names: &mut Vec<&'a str>,
    ctx: &MapContext<'_>,
    expected: &[(&str, &'static str)],
    report: &mut ImportReport,
) {
    if ctx.whole.contains(&id(e)) {
        return;
    }
    names.push(&e.name);
    if any_consumed(e, ctx) {
        // Consumed itself or partly mapped below: account for the children one by one.
        for c in e.elements() {
            collect_unmapped(c, names, ctx, expected, report);
        }
    } else {
        let reason = expected
            .iter()
            .find(|(pattern, _)| pattern_matches(pattern, names))
            .map(|(_, reason)| *reason);
        let entry = Unmapped {
            xpath: ctx.xpath(e),
            reason,
            xml: element_to_string(e),
        };
        if reason.is_some() {
            report.unmapped_expected.push(entry);
        } else {
            report.unmapped_unexpected.push(entry);
        }
    }
    names.pop();
}

/// Match an element-name path against a pattern (see [`Importer::expect_unmapped`]).
pub fn pattern_matches(pattern: &str, names: &[&str]) -> bool {
    fn segment(p: &str, name: &str) -> bool {
        match p.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => p == name,
        }
    }
    fn go(p: &[&str], n: &[&str]) -> bool {
        match p.split_first() {
            None => n.is_empty(),
            Some((&"**", rest)) => (0..=n.len()).any(|i| go(rest, &n[i..])),
            Some((first, rest)) => n
                .split_first()
                .is_some_and(|(name, tail)| segment(first, name) && go(rest, tail)),
        }
    }
    let p: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    go(&p, names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::parse;

    #[derive(Default, Debug)]
    struct Out {
        hostname: Option<String>,
        ports: Vec<u16>,
        rules: usize,
        finished: bool,
    }

    struct SystemMapper;
    impl Mapper<Out> for SystemMapper {
        fn name(&self) -> &'static str {
            "system"
        }
        fn sections(&self) -> &'static [&'static str] {
            &["system"]
        }
        fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Out) {
            out.hostname = ctx.non_empty(s, "hostname");
            if let Some(ssh) = ctx.child(s, "ssh") {
                out.ports.extend(ctx.parse::<u16>(ssh, "port"));
            }
        }
        fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
            &[(
                "system/powerd_*",
                "power management is not managed by sensr",
            )]
        }
    }

    struct RuleMapper;
    impl Mapper<Out> for RuleMapper {
        fn name(&self) -> &'static str {
            "filter"
        }
        fn sections(&self) -> &'static [&'static str] {
            &["filter/rule"]
        }
        fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Out) {
            ctx.consume_subtree(s);
            out.rules += 1;
        }
        fn finish(&self, _: &Document, _: &mut MapContext<'_>, out: &mut Out) {
            out.finished = true;
        }
    }

    const CONFIG: &str = r#"<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>gw</hostname>
    <powerd_ac_mode>hadp</powerd_ac_mode>
    <ssh>
      <port>99999</port>
      <group>admins</group>
    </ssh>
    <mystery/>
  </system>
  <filter>
    <rule uuid="a1"><type>pass</type></rule>
    <rule><type>block</type></rule>
  </filter>
  <rrd><enable/></rrd>
  <unknown><deep>1</deep></unknown>
</opnsense>
"#;

    fn importer() -> Importer<Out> {
        Importer::new()
            .with_mapper(SystemMapper)
            .with_mapper(RuleMapper)
            .expect_unmapped("rrd", "graphs are replaced by sensr-monitor")
    }

    #[test]
    fn every_node_is_accounted_for() {
        let doc = parse(CONFIG).unwrap();
        let imported = importer().import(&doc);
        let out = &imported.document;
        assert_eq!(out.hostname.as_deref(), Some("gw"));
        assert!(out.ports.is_empty());
        assert_eq!(out.rules, 2);
        assert!(out.finished);

        let r = &imported.report;
        let mapped: Vec<&str> = r.mapped.iter().map(|m| m.xpath.as_str()).collect();
        assert_eq!(
            mapped,
            [
                "/opnsense/system",
                "/opnsense/filter/rule[@uuid='a1']",
                "/opnsense/filter/rule[2]"
            ]
        );
        let expected: Vec<&str> = r
            .unmapped_expected
            .iter()
            .map(|u| u.xpath.as_str())
            .collect();
        assert_eq!(
            expected,
            ["/opnsense/system/powerd_ac_mode", "/opnsense/rrd"]
        );
        let unexpected: Vec<&str> = r
            .unmapped_unexpected
            .iter()
            .map(|u| u.xpath.as_str())
            .collect();
        // The partly-read <ssh> reports only its unread child; <unknown> is reported
        // whole, not leaf by leaf, and keeps its XML.
        assert_eq!(
            unexpected,
            [
                "/opnsense/system/ssh/group",
                "/opnsense/system/mystery",
                "/opnsense/unknown"
            ]
        );
        assert_eq!(
            r.unmapped_unexpected[2].xml,
            "<unknown>\n  <deep>1</deep>\n</unknown>"
        );
        assert_eq!(r.warnings.len(), 1);
        assert_eq!(r.warnings[0].xpath, "/opnsense/system/ssh/port");
        assert_eq!(r.warnings[0].severity, Severity::Invalid);
        assert!(!r.is_clean());
    }

    #[test]
    fn patterns() {
        assert!(pattern_matches(
            "system/powerd_*",
            &["system", "powerd_ac_mode"]
        ));
        assert!(!pattern_matches("system/powerd_*", &["system"]));
        assert!(pattern_matches("OPNsense/IDS/**", &["OPNsense", "IDS"]));
        assert!(pattern_matches(
            "OPNsense/IDS/**",
            &["OPNsense", "IDS", "a", "b"]
        ));
        assert!(pattern_matches("**/descr", &["interfaces", "lan", "descr"]));
        assert!(pattern_matches(
            "interfaces/*/media",
            &["interfaces", "wan", "media"]
        ));
        assert!(!pattern_matches(
            "interfaces/*/media",
            &["interfaces", "media"]
        ));
    }
}
