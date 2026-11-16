//! `cargo xtask source-coverage` (docs/PLAN.md §2.6): every behaviour-carrying
//! file of the pinned OPNsense core and plugins trees has a row in
//! `reference/COVERAGE.toml` saying which sensr crate covers it and how far.
//!
//! - `--check` fails when the manifest's pins differ from `reference/REFS`,
//!   when a row is malformed, and (with the trees fetched, see
//!   scripts/fetch-reference.sh) when a file has no row or a row has no
//!   file. A new upstream file therefore shows up as `todo`, never silently.
//! - `--seed` adds missing files as `todo`, drops rows whose file is gone and
//!   takes the pins from REFS; existing rows keep their status.
//!
//! The manifest is one line per file so diffs stay readable:
//! `"core/src/.../Alias.xml" = { status = "done", crate = "sensr-rules", ... }`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::walk;

const MANIFEST: &str = "reference/COVERAGE.toml";
const REFS: &str = "reference/REFS";
const TREES: &str = "reference/opnsense";
const REPOS: [&str; 2] = ["core", "plugins"];

#[derive(clap::Args)]
pub struct Args {
    /// Fail on drift between the manifest, REFS and the trees.
    #[arg(long)]
    check: bool,
    /// With --check: fail if the reference trees are not fetched.
    #[arg(long)]
    require_tree: bool,
    /// Add missing files as todo, drop vanished ones, take pins from REFS.
    #[arg(long)]
    seed: bool,
    /// Print coverage per OPNsense module and per sensr crate.
    #[arg(long)]
    report: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Todo,
    InProgress,
    Done,
    NA,
    Deferred,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Todo => "todo",
            Status::InProgress => "in-progress",
            Status::Done => "done",
            Status::NA => "n-a",
            Status::Deferred => "deferred",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub status: Status,
    #[serde(rename = "crate", default, skip_serializing_if = "Option::is_none")]
    pub krate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<String>,
    /// For `deferred`: the phase, e.g. "P3".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl Row {
    fn todo() -> Self {
        Row {
            status: Status::Todo,
            krate: None,
            module: None,
            features: vec![],
            tests: vec![],
            phase: None,
            note: None,
        }
    }

    /// What is wrong with this row, if anything.
    fn problems(&self) -> Vec<&'static str> {
        let mut p = vec![];
        match self.status {
            Status::NA if self.note.is_none() => p.push("n-a needs a note saying why"),
            Status::Deferred if self.phase.is_none() => p.push("deferred needs a phase"),
            Status::Done | Status::InProgress if self.krate.is_none() => {
                p.push("done/in-progress needs a crate")
            }
            _ => {}
        }
        p
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub pins: BTreeMap<String, String>,
    #[serde(default)]
    pub files: BTreeMap<String, Row>,
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

impl Manifest {
    /// One line per file, stable order.
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# Source coverage: every behaviour-carrying file of the pinned OPNsense trees\n\
             # and which sensr crate covers it (docs/PLAN.md §2.6). `cargo xtask\n\
             # source-coverage --seed` adds new upstream files as todo; flip a row when a\n\
             # PR covers the file. status: todo | in-progress | done | n-a (note) | deferred (phase)\n\n[pins]\n",
        );
        for (k, v) in &self.pins {
            let _ = writeln!(out, "{k} = {}", quote(v));
        }
        out.push_str("\n[files]\n");
        for (path, row) in &self.files {
            let mut fields = vec![format!("status = {}", quote(row.status.as_str()))];
            if let Some(c) = &row.krate {
                fields.push(format!("crate = {}", quote(c)));
            }
            if let Some(m) = &row.module {
                fields.push(format!("module = {}", quote(m)));
            }
            for (k, list) in [("features", &row.features), ("tests", &row.tests)] {
                if !list.is_empty() {
                    let items: Vec<_> = list.iter().map(|s| quote(s)).collect();
                    fields.push(format!("{k} = [{}]", items.join(", ")));
                }
            }
            if let Some(p) = &row.phase {
                fields.push(format!("phase = {}", quote(p)));
            }
            if let Some(n) = &row.note {
                fields.push(format!("note = {}", quote(n)));
            }
            let _ = writeln!(out, "{} = {{ {} }}", quote(path), fields.join(", "));
        }
        out
    }
}

/// Whether a path in a tree (relative to the repository root, `/`-separated)
/// carries behaviour: models, controllers, forms, views, configd actions,
/// templates, scripts, legacy includes, rc scripts, syshooks, tests and
/// dashboard widgets. Static assets (images, fonts, stylesheets, vendored
/// minified JS) do not.
pub fn carries_behaviour(repo: &str, rel: &str) -> bool {
    const ASSETS: [&str; 12] = [
        ".png", ".svg", ".gif", ".jpg", ".jpeg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".css",
        ".map",
    ];
    if ASSETS.iter().any(|e| rel.ends_with(e)) || rel.ends_with(".min.js") {
        return false;
    }
    let src_behaviour = |src: &str| {
        [
            "opnsense/mvc/app/",
            "opnsense/mvc/tests/",
            "opnsense/service/",
            "opnsense/scripts/",
            "opnsense/www/js/widgets/",
            "etc/",
            "www/",
            "sbin/",
            "bin/",
        ]
        .iter()
        .any(|p| src.starts_with(p))
    };
    match repo {
        "core" => rel.strip_prefix("src/").is_some_and(src_behaviour),
        "plugins" => {
            // <category>/<plugin>/{Makefile,pkg-descr,src/...}
            let parts: Vec<&str> = rel.splitn(3, '/').collect();
            match parts.as_slice() {
                [_, _, "Makefile" | "pkg-descr"] => true,
                [_, _, rest] => rest.strip_prefix("src/").is_some_and(src_behaviour),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Behaviour-carrying files of the fetched trees, as manifest keys
/// (`core/...`, `plugins/...`). `None` when the trees are not fetched.
fn tree_files(root: &Path) -> Result<Option<Vec<String>>> {
    let mut out = vec![];
    for repo in REPOS {
        let dir = root.join(TREES).join(repo);
        if !dir.is_dir() {
            return Ok(None);
        }
        for path in walk::files(&dir)? {
            let rel = walk::rel(&dir, &path);
            if carries_behaviour(repo, &rel) {
                out.push(format!("{repo}/{rel}"));
            }
        }
    }
    Ok(Some(out))
}

pub fn parse_refs(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next()?.to_string()))
        })
        .filter(|(r, _)| REPOS.contains(&r.as_str()))
        .collect()
}

/// The OPNsense module a file belongs to, for the report: the segment after
/// `OPNsense/` (core MVC), the plugin (`plugins/net/wireguard`), or the
/// directory (`core/src/etc/inc`).
pub fn module_of(key: &str) -> String {
    if let Some(p) = key.strip_prefix("plugins/") {
        let mut it = p.splitn(3, '/');
        if let (Some(c), Some(n)) = (it.next(), it.next()) {
            return format!("plugins/{c}/{n}");
        }
    }
    if let Some(i) = key.find("/OPNsense/") {
        let rest = &key[i + "/OPNsense/".len()..];
        if let Some(m) = rest.split('/').next()
            && rest.contains('/')
        {
            return format!("core/{m}");
        }
    }
    let parts: Vec<&str> = key.split('/').collect();
    parts[..parts.len().saturating_sub(1).min(3)].join("/")
}

pub fn run(root: &Path, args: &Args) -> Result<()> {
    let refs = parse_refs(&fs::read_to_string(root.join(REFS)).context(REFS)?);
    let manifest_path = root.join(MANIFEST);
    let mut manifest: Manifest = match fs::read_to_string(&manifest_path) {
        Ok(s) => toml::from_str(&s).with_context(|| MANIFEST.to_string())?,
        Err(_) => Manifest::default(),
    };
    let tree = tree_files(root)?;

    if args.seed {
        let Some(tree) = &tree else {
            bail!("--seed needs the reference trees: scripts/fetch-reference.sh");
        };
        let before = manifest.files.len();
        let keep: std::collections::BTreeSet<&String> = tree.iter().collect();
        manifest.files.retain(|k, _| keep.contains(k));
        let dropped = before - manifest.files.len();
        let mut added = 0;
        for f in tree {
            manifest.files.entry(f.clone()).or_insert_with(|| {
                added += 1;
                Row::todo()
            });
        }
        manifest.pins = refs.clone();
        fs::write(&manifest_path, manifest.render())?;
        println!(
            "{MANIFEST}: {added} added, {dropped} dropped, {} rows",
            manifest.files.len()
        );
    }

    let mut errors = vec![];
    for repo in REPOS {
        if manifest.pins.get(repo) != refs.get(repo) {
            errors.push(format!(
                "pin for {repo} is {:?} in {MANIFEST} but {:?} in {REFS}: re-run --seed and review",
                manifest.pins.get(repo),
                refs.get(repo)
            ));
        }
    }
    for (k, row) in &manifest.files {
        if !REPOS.iter().any(|r| k.starts_with(&format!("{r}/"))) {
            errors.push(format!("{k}: key must start with core/ or plugins/"));
        }
        for p in row.problems() {
            errors.push(format!("{k}: {p}"));
        }
    }
    match &tree {
        Some(tree) => {
            let missing: Vec<_> = tree
                .iter()
                .filter(|f| !manifest.files.contains_key(*f))
                .collect();
            let set: std::collections::BTreeSet<&String> = tree.iter().collect();
            let stale: Vec<_> = manifest.files.keys().filter(|k| !set.contains(k)).collect();
            for m in missing.iter().take(20) {
                errors.push(format!("{m}: no row (new upstream file?)"));
            }
            if missing.len() > 20 {
                errors.push(format!(
                    "... and {} more files without a row",
                    missing.len() - 20
                ));
            }
            for s in stale.iter().take(20) {
                errors.push(format!("{s}: row for a file the pinned tree does not have"));
            }
        }
        None if args.require_tree => {
            errors.push(format!(
                "{TREES} is not fetched (scripts/fetch-reference.sh)"
            ));
        }
        None => println!("note: {TREES} not fetched; checked the manifest and pins only"),
    }

    let mut by_status: BTreeMap<&str, usize> = BTreeMap::new();
    for row in manifest.files.values() {
        *by_status.entry(row.status.as_str()).or_default() += 1;
    }
    let total = manifest.files.len();
    let resolved = manifest
        .files
        .values()
        .filter(|r| matches!(r.status, Status::Done | Status::NA | Status::Deferred))
        .count();
    println!("source coverage ({MANIFEST}): {resolved}/{total} resolved (done, n-a or deferred)");
    for (s, n) in &by_status {
        println!("  {n:>5} {s}");
    }
    if args.report {
        let mut per_mod: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        let mut per_crate: BTreeMap<String, usize> = BTreeMap::new();
        for (k, r) in &manifest.files {
            let e = per_mod.entry(module_of(k)).or_default();
            e.1 += 1;
            if matches!(r.status, Status::Done | Status::NA | Status::Deferred) {
                e.0 += 1;
            }
            if let Some(c) = &r.krate {
                *per_crate.entry(c.clone()).or_default() += 1;
            }
        }
        println!("per OPNsense module:");
        for (m, (d, t)) in &per_mod {
            println!("  {d:>4}/{t:<4} {m}");
        }
        println!("per sensr crate:");
        for (c, n) in &per_crate {
            println!("  {n:>5} {c}");
        }
    }
    for e in &errors {
        println!("error: {e}");
    }
    if args.check && !errors.is_empty() {
        bail!("{} source-coverage problem(s)", errors.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_paths() {
        assert!(carries_behaviour(
            "core",
            "src/opnsense/mvc/app/models/OPNsense/Firewall/Alias.xml"
        ));
        assert!(carries_behaviour(
            "core",
            "src/opnsense/service/conf/actions.d/actions_filter.conf"
        ));
        assert!(carries_behaviour("core", "src/etc/inc/filter.inc"));
        assert!(carries_behaviour(
            "core",
            "src/etc/rc.syshook.d/early/99-selftest"
        ));
        assert!(carries_behaviour(
            "core",
            "src/opnsense/www/js/widgets/Cpu.js"
        ));
        assert!(!carries_behaviour(
            "core",
            "src/opnsense/www/js/jquery-3.7.1.min.js"
        ));
        assert!(!carries_behaviour(
            "core",
            "src/opnsense/www/themes/opnsense/build/css/main.css"
        ));
        assert!(!carries_behaviour("core", "Mk/lint.mk"));
        assert!(carries_behaviour("plugins", "net/wireguard/Makefile"));
        assert!(carries_behaviour(
            "plugins",
            "net/wireguard/src/opnsense/mvc/app/models/OPNsense/Wireguard/Server.xml"
        ));
        assert!(!carries_behaviour(
            "plugins",
            "net/wireguard/src/opnsense/www/img/logo.png"
        ));
        assert!(!carries_behaviour("plugins", "Mk/plugins.mk"));
    }

    #[test]
    fn manifest_round_trips_one_line_per_file() {
        let mut m = Manifest::default();
        m.pins.insert("core".into(), "8b88393".into());
        m.files
            .insert("core/src/etc/inc/filter.inc".into(), Row::todo());
        m.files.insert(
            "core/src/opnsense/mvc/app/models/OPNsense/Firewall/Alias.xml".into(),
            Row {
                status: Status::Done,
                krate: Some("sensr-rules".into()),
                module: Some("alias::model".into()),
                features: vec!["FW-AL-001".into()],
                tests: vec!["T-0204".into()],
                phase: None,
                note: Some("counters are \"State\"".into()),
            },
        );
        let text = m.render();
        assert_eq!(text.lines().filter(|l| l.starts_with("\"core/")).count(), 2);
        let back: Manifest = toml::from_str(&text).unwrap();
        assert_eq!(back.files, m.files);
        assert_eq!(back.pins, m.pins);
    }

    #[test]
    fn row_rules() {
        let mut r = Row::todo();
        assert!(r.problems().is_empty());
        r.status = Status::NA;
        assert!(!r.problems().is_empty());
        r.note = Some("FreeBSD only".into());
        assert!(r.problems().is_empty());
        r.status = Status::Deferred;
        assert!(!r.problems().is_empty());
        r.status = Status::Done;
        assert!(!r.problems().is_empty());
    }

    #[test]
    fn refs_and_modules() {
        let refs = parse_refs("# c\ncore abc 27.1\nplugins def x\ndocs 123 y\n");
        assert_eq!(refs.len(), 2);
        assert_eq!(refs["core"], "abc");
        assert_eq!(
            module_of("core/src/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml"),
            "core/Kea"
        );
        assert_eq!(
            module_of("plugins/net/wireguard/Makefile"),
            "plugins/net/wireguard"
        );
        assert_eq!(module_of("core/src/etc/inc/filter.inc"), "core/src/etc");
    }

    #[test]
    fn the_checked_in_manifest_parses_and_matches_refs() {
        let root = walk::repo_root().unwrap();
        let m: Manifest =
            toml::from_str(&fs::read_to_string(root.join(MANIFEST)).unwrap()).unwrap();
        let refs = parse_refs(&fs::read_to_string(root.join(REFS)).unwrap());
        assert_eq!(m.pins, refs);
        assert!(m.files.len() > 1000, "{}", m.files.len());
        for (k, r) in &m.files {
            assert!(r.problems().is_empty(), "{k}: {:?}", r.problems());
        }
    }
}
