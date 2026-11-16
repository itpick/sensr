//! `cargo xtask`: repository checks that CI runs (docs/PLAN.md §4, §2.6).
//!
//! Each task is a subcommand. `--check` variants exit non-zero on failure so
//! CI can gate on them.

mod coverage;
mod fixtures;
mod freshness;
mod parity;
mod parity_ids;
mod walk;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cargo xtask", about = "sensr repository checks")]
struct Cli {
    /// Repository root (default: the workspace this binary was built from).
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Count the docs/research/03 test IDs that tests discharge.
    Parity(parity::Args),
    /// Compare reference/COVERAGE.toml with the pinned OPNsense trees.
    SourceCoverage(coverage::Args),
    /// Check that flake inputs and the toolchain are not falling behind.
    Freshness(freshness::Args),
    /// Lint test fixtures: XML/JSON parse, synthetic-data conventions (T-0347).
    LintFixtures,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = match cli.root {
        Some(r) => r,
        None => walk::repo_root()?,
    };
    match cli.task {
        Task::Parity(a) => parity::run(&root, &a),
        Task::SourceCoverage(a) => coverage::run(&root, &a),
        Task::Freshness(a) => freshness::run(&root, &a),
        Task::LintFixtures => fixtures::run(&root),
    }
}
