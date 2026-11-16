//! `cargo xtask parity`: how many rows of the test-parity checklist
//! (docs/research/03-test-parity.md) a test discharges (docs/PLAN.md §4).
//!
//! A row counts when its ID appears
//! - as a `tNNNN` token in the name of a Rust test function under `crates/`
//!   (`fn direction_t0006()`), or in a file name under a crate's `tests/`
//!   (trybuild cases), unless that function is `#[ignore]`d (T-0073 is the
//!   one row allowed to be ignored);
//! - on a `parity:` line of a `nix/tests/*.nix` file
//!   (`# parity: T-0391 T-0392`), up to the first token that is not an ID;
//! - in [`crate::parity_ids::DISCHARGED`] (checks xtask and CI run).
//!
//! `--check` fails when fewer rows are covered than `tests/parity-baseline.txt`
//! says, or when a test names an ID the checklist does not have. The
//! baseline only goes up: `--update-baseline` rewrites it after a PR raised
//! coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;

use crate::parity_ids::DISCHARGED;
use crate::walk;

const CHECKLIST: &str = "docs/research/03-test-parity.md";
const BASELINE: &str = "tests/parity-baseline.txt";
/// The one checklist row whose test is ignored upstream too.
const ALLOWED_IGNORE: &str = "T-0073";

#[derive(clap::Args)]
pub struct Args {
    /// Fail if coverage is below the baseline or a test names an unknown ID.
    #[arg(long)]
    check: bool,
    /// Rewrite the baseline to the current coverage (only ever raises it).
    #[arg(long)]
    update_baseline: bool,
    /// Write a coverage badge (SVG) to this path.
    #[arg(long)]
    badge: Option<std::path::PathBuf>,
    /// List every discharged ID and where.
    #[arg(long)]
    list: bool,
}

/// The checklist: ID → category heading.
pub fn parse_checklist(text: &str) -> BTreeMap<String, String> {
    let row = Regex::new(r"^\|\s*(T-\d{4})\s*\|").expect("static regex");
    let mut category = String::from("uncategorised");
    let mut ids = BTreeMap::new();
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("### ") {
            category = h.split(" (").next().unwrap_or(h).trim().to_string();
        } else if let Some(c) = row.captures(line) {
            ids.insert(c[1].to_string(), category.clone());
        }
    }
    ids
}

/// IDs carried by an identifier: every `_`-separated token `tNNNN`.
fn id_tokens(name: &str) -> Vec<String> {
    name.split('_')
        .filter(|t| {
            t.len() == 5 && t.starts_with('t') && t[1..].bytes().all(|b| b.is_ascii_digit())
        })
        .map(|t| format!("T-{}", &t[1..]))
        .collect()
}

#[derive(Debug, Default)]
pub struct Found {
    /// ID → places that discharge it.
    pub ids: BTreeMap<String, BTreeSet<String>>,
    /// ID → ignored tests that name it (do not count).
    pub ignored: BTreeMap<String, BTreeSet<String>>,
}

impl Found {
    fn add(&mut self, id: String, at: String) {
        self.ids.entry(id).or_default().insert(at);
    }
}

/// Test functions in one Rust source file.
pub fn scan_rust_source(text: &str, file: &str, found: &mut Found) {
    let fn_re = Regex::new(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)").expect("static regex");
    let mut attrs = String::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("#[") || t.starts_with("#![") {
            attrs.push_str(t);
            continue;
        }
        if let Some(c) = fn_re.captures(t) {
            let name = &c[1];
            let ignored = attrs.contains("ignore");
            for id in id_tokens(name) {
                let at = format!("{file}:{}:{name}", n + 1);
                if ignored && id != ALLOWED_IGNORE {
                    found.ignored.entry(id).or_default().insert(at);
                } else {
                    found.add(id, at);
                }
            }
        }
        if !t.is_empty() && !t.starts_with("//") {
            attrs.clear();
        }
    }
}

/// `parity:` lines in one nix test file.
pub fn scan_nix_source(text: &str, file: &str, found: &mut Found) {
    let id = Regex::new(r"^T-\d{4}$").expect("static regex");
    for (n, line) in text.lines().enumerate() {
        let Some((_, rest)) = line.split_once("parity:") else {
            continue;
        };
        for tok in rest.split_whitespace() {
            if !id.is_match(tok) {
                break;
            }
            found.add(tok.to_string(), format!("{file}:{}", n + 1));
        }
    }
}

pub fn scan(root: &Path) -> Result<Found> {
    let mut found = Found::default();
    for path in walk::files(&root.join("crates"))? {
        let rel = walk::rel(root, &path);
        // xtask's own tests carry sample IDs in strings; its real rows are
        // registered in parity_ids.rs.
        if rel.starts_with("crates/xtask/") {
            continue;
        }
        if rel.ends_with(".rs") {
            let text = fs::read_to_string(&path).with_context(|| rel.clone())?;
            scan_rust_source(&text, &rel, &mut found);
            if rel.contains("/tests/") {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                for id in id_tokens(&stem) {
                    found.add(id, rel.clone());
                }
            }
        }
    }
    for path in walk::files(&root.join("nix/tests"))? {
        let rel = walk::rel(root, &path);
        if rel.ends_with(".nix") {
            let text = fs::read_to_string(&path).with_context(|| rel.clone())?;
            scan_nix_source(&text, &rel, &mut found);
        }
    }
    for (id, what) in DISCHARGED {
        found.add((*id).to_string(), format!("xtask/CI: {what}"));
    }
    Ok(found)
}

fn badge_svg(covered: usize, total: usize) -> String {
    let pct = (covered * 100).checked_div(total).unwrap_or(0);
    let colour = match pct {
        90.. => "#4c1",
        50.. => "#dfb317",
        _ => "#e05d44",
    };
    let value = format!("{covered}/{total}");
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20" role="img" aria-label="parity: {value}"><title>parity: {value}</title><rect width="50" height="20" fill="#555"/><rect x="50" width="80" height="20" fill="{colour}"/><g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11"><text x="25" y="14">parity</text><text x="90" y="14">{value}</text></g></svg>
"##
    )
}

pub fn run(root: &Path, args: &Args) -> Result<()> {
    let text = fs::read_to_string(root.join(CHECKLIST)).context(CHECKLIST)?;
    let checklist = parse_checklist(&text);
    let found = scan(root)?;

    let unknown: Vec<_> = found
        .ids
        .keys()
        .filter(|id| !checklist.contains_key(*id))
        .collect();
    let covered: BTreeSet<&String> = found
        .ids
        .keys()
        .filter(|id| checklist.contains_key(*id))
        .collect();

    let mut per_cat: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (id, cat) in &checklist {
        let e = per_cat.entry(cat.as_str()).or_default();
        e.1 += 1;
        if covered.contains(id) {
            e.0 += 1;
        }
    }
    println!("test parity ({CHECKLIST})");
    for (cat, (c, t)) in &per_cat {
        println!("  {c:>4}/{t:<4} {cat}");
    }
    println!("  {:>4}/{:<4} total", covered.len(), checklist.len());
    if args.list {
        for (id, at) in &found.ids {
            for a in at {
                println!("{id} {a}");
            }
        }
    }
    for (id, at) in &found.ignored {
        if !covered.contains(id) {
            println!(
                "note: {id} only has ignored tests: {}",
                at.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
    }
    for id in &unknown {
        println!(
            "error: {id} is not a row of {CHECKLIST}: {:?}",
            found.ids[*id]
        );
    }

    if let Some(path) = &args.badge {
        fs::write(path, badge_svg(covered.len(), checklist.len()))?;
    }

    let baseline_path = root.join(BASELINE);
    let baseline: usize = match fs::read_to_string(&baseline_path) {
        Ok(s) => s
            .trim()
            .parse()
            .with_context(|| format!("{BASELINE} is not a number"))?,
        Err(_) => 0,
    };
    if args.update_baseline {
        if covered.len() < baseline {
            bail!(
                "coverage {} is below the baseline {baseline}; the baseline never goes down",
                covered.len()
            );
        }
        fs::write(&baseline_path, format!("{}\n", covered.len()))?;
        println!("{BASELINE}: {baseline} -> {}", covered.len());
    }
    if args.check {
        if !unknown.is_empty() {
            bail!("{} test ID(s) are not in the checklist", unknown.len());
        }
        if covered.len() < baseline {
            bail!("parity fell from {baseline} to {} rows", covered.len());
        }
        if covered.len() > baseline && !args.update_baseline {
            println!(
                "parity rose from {baseline} to {}: run `cargo xtask parity --update-baseline` and commit {BASELINE}",
                covered.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checklist_rows_and_categories() {
        let md = "### 2.1 PHPUnit — library (`x`)\n| ID | a |\n|---|---|\n| T-0001 | x |\n### 2.5 Lint\n| T-0347 | y |\n";
        let ids = parse_checklist(md);
        assert_eq!(ids.len(), 2);
        assert_eq!(ids["T-0001"], "2.1 PHPUnit — library");
        assert_eq!(ids["T-0347"], "2.5 Lint");
    }

    #[test]
    fn the_real_checklist_has_408_rows() {
        let root = walk::repo_root().unwrap();
        let text = fs::read_to_string(root.join(CHECKLIST)).unwrap();
        let ids = parse_checklist(&text);
        assert!(ids.len() >= 408, "{}", ids.len());
        assert!(ids.contains_key("T-0001") && ids.contains_key("T-0408"));
    }

    #[test]
    fn tokens_in_function_names() {
        assert_eq!(id_tokens("direction_t0006"), vec!["T-0006"]);
        assert_eq!(
            id_tokens("prop_usable_length_alignment_t0011_t0012"),
            vec!["T-0011", "T-0012"]
        );
        assert!(id_tokens("t00x1_test").is_empty());
        assert!(id_tokens("start0006").is_empty());
    }

    #[test]
    fn ignored_tests_do_not_count() {
        let src = "#[test]\nfn a_t0006() {}\n\n#[test]\n#[ignore = \"slow\"]\nfn b_t0007() {}\n#[test]\n#[ignore]\nfn c_t0073() {}\n";
        let mut f = Found::default();
        scan_rust_source(src, "x.rs", &mut f);
        assert!(f.ids.contains_key("T-0006"));
        assert!(!f.ids.contains_key("T-0007"));
        assert!(f.ignored.contains_key("T-0007"));
        assert!(f.ids.contains_key("T-0073"), "T-0073 is the allowed ignore");
    }

    #[test]
    fn attributes_reset_between_functions() {
        let src = "#[ignore]\nconst X: u8 = 1;\n#[test]\nfn a_t0006() {}\n";
        let mut f = Found::default();
        scan_rust_source(src, "x.rs", &mut f);
        assert!(f.ids.contains_key("T-0006"));
    }

    #[test]
    fn nix_parity_lines_stop_at_prose() {
        let src = "  # parity: T-0391 T-0392 (T-0401 once configGet lands)\n";
        let mut f = Found::default();
        scan_nix_source(src, "t.nix", &mut f);
        assert_eq!(
            f.ids.keys().cloned().collect::<Vec<_>>(),
            vec!["T-0391", "T-0392"]
        );
    }

    #[test]
    fn badge_is_svg() {
        let svg = badge_svg(10, 408);
        assert!(svg.starts_with("<svg") && svg.contains("10/408"));
    }
}
