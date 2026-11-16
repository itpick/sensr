//! `sensr`, the command line (docs/PLAN.md §2.1: mirrors `configctl` /
//! `opnsense-shell`). Talks to `sensr-agent` over `sensr-ipc`.

pub mod import;
pub mod output;

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sensr_ipc::{Client, ClientError, ConfigPath, Op, Principal, Response, Source};
use serde_json::Value;

use crate::import::{ConfigImporter, OpnsenseImporter};

/// sensr command line.
#[derive(Debug, Parser)]
#[command(name = "sensr", version, about = "sensr firewall command line")]
pub struct Cli {
    /// sensr-agent socket.
    #[arg(long, global = true, env = sensr_ipc::client::SOCKET_ENV, default_value = sensr_ipc::client::DEFAULT_SOCKET)]
    pub socket: PathBuf,
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Agent, revision and commit-confirm status.
    Status {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Read and change the configuration.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Import a foreign configuration into the candidate.
    #[command(subcommand)]
    Import(ImportCmd),
    /// Show what applying would change.
    Apply {
        /// Plan only; change nothing (the only mode: applying happens on commit).
        #[arg(long)]
        dry_run: bool,
        /// Which document to plan: candidate (default), head, applied or a revision number.
        #[arg(long, default_value = "candidate")]
        source: SourceArg,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `sensr config …`
#[derive(Debug, Subcommand)]
pub enum ConfigCmd {
    /// Print the value at PATH (default: the whole document).
    Get {
        /// Dotted path, e.g. `system.hostname`.
        path: Option<String>,
        /// Print JSON instead of `path = value` lines.
        #[arg(long)]
        json: bool,
        /// candidate (default), head, applied or a revision number.
        #[arg(long, default_value = "candidate")]
        source: SourceArg,
    },
    /// Stage VALUE at PATH in the candidate.
    Set {
        /// Dotted path.
        path: String,
        /// New value (a string unless --json).
        value: String,
        /// Parse VALUE as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Stage removal of PATH.
    Delete {
        /// Dotted path.
        path: String,
    },
    /// Throw away staged changes.
    Discard,
    /// Store the candidate as a new revision and apply it.
    Commit {
        /// Revision description.
        #[arg(short, long)]
        message: Option<String>,
        /// Roll back automatically unless `sensr config confirm` runs within SECS.
        #[arg(long, value_name = "SECS", num_args = 0..=1, default_missing_value = "300")]
        confirm: Option<u32>,
    },
    /// Keep a commit made with --confirm.
    Confirm,
    /// Re-apply an earlier revision (default: the one before head) as a new revision.
    Rollback {
        /// Revision number.
        revision: Option<u64>,
    },
    /// List revisions, newest first.
    History {
        /// At most N entries.
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: u32,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show differences (default: head → candidate).
    Diff {
        /// Old side.
        #[arg(default_value = "head")]
        from: SourceArg,
        /// New side.
        #[arg(default_value = "candidate")]
        to: SourceArg,
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `sensr import …`
#[derive(Debug, Subcommand)]
pub enum ImportCmd {
    /// Stage an OPNsense config.xml (backup) as the candidate.
    Opnsense {
        /// Path to config.xml.
        file: PathBuf,
        /// Print the import report.
        #[arg(long)]
        report: bool,
    },
}

/// A document selector on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceArg(pub Source);

impl FromStr for SourceArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SourceArg(match s {
            "candidate" => Source::Candidate,
            "head" => Source::Head,
            "applied" | "running" => Source::Applied,
            n => Source::Revision(n.parse().map_err(|_| {
                format!("{n:?}: expected candidate, head, applied or a revision number")
            })?),
        }))
    }
}

fn path(s: Option<&str>) -> anyhow::Result<ConfigPath> {
    s.unwrap_or("/")
        .parse()
        .with_context(|| format!("invalid config path {:?}", s.unwrap_or("/")))
}

/// The principal the CLI claims: the invoking user. The agent derives the
/// real identity from the socket peer and records a sudo user as
/// `impersonated_by`.
fn principal() -> Principal {
    let user = std::env::var("SUDO_USER")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default();
    Principal::unix(user, 0)
}

/// Turns an agent error into a readable message with validation details.
pub fn describe(e: &ClientError) -> String {
    match e {
        ClientError::Agent(err) => {
            let mut s = err.message.clone();
            for v in &err.validations {
                s.push_str(&format!("\n  {}: {}", v.path, v.message));
            }
            s
        }
        other => other.to_string(),
    }
}

async fn call(c: &mut Client, op: Op) -> anyhow::Result<Response> {
    c.call(op).await.map_err(|e| anyhow::anyhow!(describe(&e)))
}

fn unexpected(r: Response) -> anyhow::Error {
    anyhow::anyhow!("unexpected reply from sensr-agent: {r:?}")
}

/// Runs one command, writing human output to `out`.
pub async fn run(cli: Cli, out: &mut dyn Write) -> anyhow::Result<()> {
    let mut c = Client::connect(&cli.socket, principal())
        .await
        .map_err(|e| anyhow::anyhow!(describe(&e)))?;
    match cli.command {
        Command::Status { json } => {
            let Response::Status(st) = call(&mut c, Op::Status).await? else {
                bail!("unexpected status reply")
            };
            if json {
                writeln!(out, "{}", output::json(&st))?;
            } else {
                output::status(out, &st)?;
            }
        }
        Command::Config(cmd) => config(&mut c, cmd, out).await?,
        Command::Import(ImportCmd::Opnsense { file, report }) => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let imported = OpnsenseImporter.import(&bytes)?;
            if report {
                write!(out, "{}", imported.report)?;
            }
            let Response::Staged { dirty } = call(
                &mut c,
                Op::ConfigLoad {
                    document: imported.document,
                },
            )
            .await?
            else {
                bail!("unexpected reply to load")
            };
            if dirty {
                writeln!(
                    out,
                    "staged {} as the candidate; review with `sensr config diff`, then `sensr config commit`",
                    file.display()
                )?;
            } else {
                writeln!(out, "{} matches head; nothing staged", file.display())?;
            }
        }
        Command::Apply {
            dry_run,
            source,
            json,
        } => {
            if !dry_run {
                bail!(
                    "changes are applied by `sensr config commit`; use `sensr apply --dry-run` to preview"
                );
            }
            match call(&mut c, Op::ApplyDryRun { source: source.0 }).await? {
                Response::Plan(plan) if json => writeln!(out, "{}", output::json(&plan))?,
                Response::Plan(plan) => output::plan(out, &plan)?,
                other => return Err(unexpected(other)),
            }
        }
    }
    Ok(())
}

async fn config(c: &mut Client, cmd: ConfigCmd, out: &mut dyn Write) -> anyhow::Result<()> {
    match cmd {
        ConfigCmd::Get {
            path: p,
            json,
            source,
        } => {
            let p = path(p.as_deref())?;
            match call(
                c,
                Op::ConfigGet {
                    path: p.clone(),
                    source: source.0,
                },
            )
            .await?
            {
                Response::Value(None) => bail!("{p} is not set"),
                Response::Value(Some(v)) if json => {
                    writeln!(out, "{}", serde_json::to_string_pretty(&v)?)?
                }
                Response::Value(Some(v)) => output::flat(out, &p, &v)?,
                other => return Err(unexpected(other)),
            }
        }
        ConfigCmd::Set {
            path: p,
            value,
            json,
        } => {
            let value = if json {
                serde_json::from_str(&value).context("VALUE is not valid JSON")?
            } else {
                Value::String(value)
            };
            call(
                c,
                Op::ConfigSet {
                    path: path(Some(&p))?,
                    value,
                },
            )
            .await?;
        }
        ConfigCmd::Delete { path: p } => {
            call(
                c,
                Op::ConfigDelete {
                    path: path(Some(&p))?,
                },
            )
            .await?;
        }
        ConfigCmd::Discard => {
            call(c, Op::ConfigDiscard).await?;
            writeln!(out, "staged changes discarded")?;
        }
        ConfigCmd::Commit { message, confirm } => {
            match call(
                c,
                Op::ConfigCommit {
                    description: message,
                    confirm_secs: confirm,
                },
            )
            .await?
            {
                Response::Committed(o) => output::committed(out, &o)?,
                other => return Err(unexpected(other)),
            }
        }
        ConfigCmd::Confirm => match call(c, Op::ConfigConfirm).await? {
            Response::Confirmed(rev) => writeln!(out, "revision {rev} confirmed")?,
            other => return Err(unexpected(other)),
        },
        ConfigCmd::Rollback { revision } => {
            match call(c, Op::ConfigRollback { to: revision }).await? {
                Response::Committed(o) => {
                    writeln!(
                        out,
                        "rolled back: revision {} ({})",
                        o.revision.id, o.revision.description
                    )?;
                }
                other => return Err(unexpected(other)),
            }
        }
        ConfigCmd::History { limit, json } => {
            match call(c, Op::ConfigHistory { limit: Some(limit) }).await? {
                Response::History(h) if json => writeln!(out, "{}", output::json(&h))?,
                Response::History(h) => output::history(out, &h)?,
                other => return Err(unexpected(other)),
            }
        }
        ConfigCmd::Diff { from, to, json } => match call(
            c,
            Op::ConfigDiff {
                from: from.0,
                to: to.0,
            },
        )
        .await?
        {
            Response::Diff(d) if json => writeln!(out, "{}", output::json(&d))?,
            Response::Diff(d) if d.changes.is_empty() => writeln!(out, "no changes")?,
            Response::Diff(d) => write!(out, "{}", d.unified)?,
            other => return Err(unexpected(other)),
        },
    }
    Ok(())
}
