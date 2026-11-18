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
    /// Run-time state as JSON: `gateways`, `aliases` or `ipv6`.
    Runtime {
        /// Which subsystem.
        section: RuntimeArg,
    },
    /// Read and change the configuration.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Traffic insight (Reporting › Insight) from the local flow database.
    #[command(subcommand)]
    Insight(InsightCmd),
    /// Import a foreign configuration into the candidate.
    #[command(subcommand)]
    Import(ImportCmd),
    /// Network cards and which interface each one carries.
    #[command(subcommand)]
    Interfaces(InterfacesCmd),
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

/// Subsystems for `sensr runtime`.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RuntimeArg {
    /// Gateway monitor.
    Gateways,
    /// Alias feeds.
    Aliases,
    /// IPv6 prefix delegation.
    Ipv6,
}

/// `sensr insight …`
#[derive(Debug, Subcommand)]
pub enum InsightCmd {
    /// The local hosts with the most traffic in a time window.
    Hosts {
        /// Window into the past, e.g. `1h`, `24h`, `7d` or a number of minutes.
        #[arg(long, default_value = "1h")]
        since: String,
        /// How many rows.
        #[arg(long, default_value_t = 50)]
        limit: u32,
        /// Flow database directory.
        #[arg(long, default_value = sensr_flow::config::DB_DIR)]
        db_dir: PathBuf,
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

/// `sensr interfaces …`
#[derive(Debug, Subcommand)]
pub enum InterfacesCmd {
    /// List the host's network cards: name, MAC, driver, bus position,
    /// link, and the interface bound to each.
    List {
        /// Print JSON.
        #[arg(long)]
        json: bool,
    },
    /// Bind interfaces to cards by MAC, so moving a card to another slot
    /// or USB port never changes its network. Without arguments, asks for
    /// each interface on standard input.
    Assign {
        /// `INTERFACE=CARD`, where CARD is a MAC address or a current kernel
        /// name (`wan=00:e0:4c:68:00:01`, `lan=end0`).
        assignments: Vec<String>,
        /// Commit right away (otherwise review with `sensr config diff`).
        #[arg(long)]
        commit: bool,
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
        /// Rename a FreeBSD device to its Linux name (repeatable), e.g.
        /// `--device igc0=enp1s0`.
        #[arg(long = "device", value_name = "FREEBSD=LINUX")]
        devices: Vec<String>,
        /// Import without staging: no agent is contacted. Exits non-zero
        /// when unexpected nodes were left unmapped.
        #[arg(long)]
        dry_run: bool,
        /// With `--dry-run`, also write the imported document (JSON) here.
        #[arg(long, value_name = "FILE", requires = "dry_run")]
        output: Option<PathBuf>,
    },
}

/// `sensr import opnsense --dry-run`: the import report without an agent.
/// Returns whether the import was clean.
pub fn import_dry_run(
    file: &std::path::Path,
    devices: &[String],
    report: bool,
    output: Option<&std::path::Path>,
    out: &mut dyn Write,
) -> anyhow::Result<bool> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let imported = OpnsenseImporter::with_devices(devices)?.import(&bytes)?;
    if report {
        write!(out, "{}", imported.report)?;
    }
    if let Some(path) = output {
        let json = serde_json::to_vec_pretty(&imported.document)?;
        write_private(path, &json).with_context(|| format!("writing {}", path.display()))?;
    }
    if !imported.clean {
        writeln!(
            out,
            "note: some nodes were not imported (see --report, \"unmapped, unexpected\")"
        )?;
    }
    if !imported.invalid.is_empty() {
        writeln!(
            out,
            "## does not validate ({}): sensr would refuse to commit it",
            imported.invalid.len()
        )?;
        for line in &imported.invalid {
            writeln!(out, "{line}")?;
        }
    }
    Ok(imported.clean && imported.invalid.is_empty())
}

/// Imported documents hold secrets, so they are written owner-only.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(bytes)
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

/// Runs one command, writing human output to `out`; interactive prompts
/// read standard input.
pub async fn run(cli: Cli, out: &mut dyn Write) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    run_with_input(cli, &mut stdin.lock(), out).await
}

/// [`run`] with prompts answered from `input`.
pub async fn run_with_input(
    cli: Cli,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    if let Command::Import(ImportCmd::Opnsense {
        file,
        report,
        devices,
        dry_run: true,
        output,
    }) = &cli.command
    {
        if !import_dry_run(file, devices, *report, output.as_deref(), out)? {
            bail!(
                "{}: not clean (unexpected unmapped nodes, or the document does not validate)",
                file.display()
            );
        }
        return Ok(());
    }
    if let Command::Insight(InsightCmd::Hosts {
        since,
        limit,
        db_dir,
        json,
    }) = &cli.command
    {
        insight_hosts(since, *limit, db_dir, *json, out)?;
        return Ok(());
    }
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
        Command::Runtime { section } => {
            let section = match section {
                RuntimeArg::Gateways => sensr_ipc::RuntimeSection::Gateways,
                RuntimeArg::Aliases => sensr_ipc::RuntimeSection::Aliases,
                RuntimeArg::Ipv6 => sensr_ipc::RuntimeSection::Ipv6,
            };
            let Response::Value(v) = call(&mut c, Op::Runtime { section }).await? else {
                bail!("unexpected runtime reply")
            };
            writeln!(
                out,
                "{}",
                output::json(&v.unwrap_or(serde_json::Value::Null))
            )?;
        }
        // Handled before the agent connection: insight reads the local database.
        Command::Insight(_) => {}
        Command::Config(cmd) => config(&mut c, cmd, out).await?,
        Command::Interfaces(cmd) => interfaces(&mut c, cmd, input, out).await?,
        Command::Import(ImportCmd::Opnsense {
            file,
            report,
            devices,
            ..
        }) => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let imported = OpnsenseImporter::with_devices(&devices)?.import(&bytes)?;
            if report {
                write!(out, "{}", imported.report)?;
            }
            if !imported.clean {
                writeln!(
                    out,
                    "note: some nodes were not imported (see --report, \"unmapped, unexpected\")"
                )?;
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

/// Parse a `--since` window (`30s`, `15m`, `24h`, `7d`; a bare number is minutes)
/// into seconds, at least one minute.
fn window_seconds(s: &str) -> anyhow::Result<i64> {
    let s = s.trim();
    let (digits, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], Some(c.to_ascii_lowercase())),
        _ => (s, None),
    };
    let n: i64 = digits
        .parse()
        .with_context(|| format!("`{s}` is not a time window (e.g. 1h, 24h, 7d)"))?;
    let secs = match unit {
        Some('s') => n,
        None | Some('m') => n * 60,
        Some('h') => n * 3_600,
        Some('d') => n * 86_400,
        Some(c) => bail!("unknown unit `{c}` in `{s}` (s, m, h or d)"),
    };
    Ok(secs.max(60))
}

/// `sensr insight hosts`: the local hosts with the most traffic, read from the
/// flow database the insight daemon writes.
fn insight_hosts(
    since: &str,
    limit: u32,
    db_dir: &std::path::Path,
    json: bool,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let path = db_dir.join(sensr_flow::config::FLOWS_DB);
    let store = sensr_flow::store::FlowStore::open_read_only(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let rows = store
        .top(
            sensr_flow::store::RowKind::Host,
            None,
            now - window_seconds(since)?,
            now,
            limit,
        )
        .with_context(|| format!("reading {}", path.display()))?;
    if json {
        let rows: Vec<serde_json::Value> = rows
            .iter()
            .map(|r| {
                serde_json::json!({
                    "host": r.key,
                    "up": r.up,
                    "down": r.down,
                    "up_packets": r.up_packets,
                    "down_packets": r.down_packets,
                })
            })
            .collect();
        writeln!(out, "{}", output::json(&rows))?;
    } else {
        for r in &rows {
            writeln!(out, "{}  up {}  down {}", r.key, bytes(r.up), bytes(r.down))?;
        }
    }
    Ok(())
}

/// A byte count for humans.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

async fn nics(c: &mut Client) -> anyhow::Result<Vec<sensr_ipc::Nic>> {
    match call(c, Op::Nics).await? {
        Response::Nics(n) => Ok(n),
        other => Err(unexpected(other)),
    }
}

/// Asks which card each interface gets. Answers: a number from the list,
/// a MAC, a kernel name, empty to keep the current binding.
async fn ask_assignments(
    c: &mut Client,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<Vec<sensr_ipc::Assignment>> {
    let cards = nics(c).await?;
    if cards.is_empty() {
        bail!("no network cards found");
    }
    output::nics(out, &cards, true)?;
    let ids: Vec<String> = match call(
        c,
        Op::ConfigGet {
            path: "interfaces".parse()?,
            source: Source::Candidate,
        },
    )
    .await?
    {
        Response::Value(Some(Value::Object(m))) => m
            .iter()
            .filter(|(_, i)| i.get("vlan").is_none())
            .map(|(k, _)| k.clone())
            .collect(),
        _ => Vec::new(),
    };
    let mut line = String::new();
    let mut read = |out: &mut dyn Write, prompt: &str| -> anyhow::Result<Option<String>> {
        write!(out, "{prompt}")?;
        out.flush()?;
        line.clear();
        if input.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        Ok(Some(line.trim().to_owned()))
    };
    let pick = |answer: &str| -> anyhow::Result<String> {
        match answer.parse::<usize>() {
            Ok(n) if (1..=cards.len()).contains(&n) => Ok(cards[n - 1].pin_mac().to_owned()),
            Ok(n) => bail!("there is no card {n}"),
            Err(_) => Ok(answer.to_owned()),
        }
    };
    let mut picked = Vec::new();
    for id in ids {
        let current = cards
            .iter()
            .find(|n| n.assigned.as_deref() == Some(id.as_str()))
            .map(|n| format!(" [{} {}]", n.name, n.pin_mac()))
            .unwrap_or_default();
        let Some(answer) = read(
            out,
            &format!("card for {id}{current} (number, MAC or name; enter keeps): "),
        )?
        else {
            break;
        };
        if !answer.is_empty() {
            picked.push(sensr_ipc::Assignment {
                interface: id,
                nic: pick(&answer)?,
            });
        }
    }
    while let Some(answer) = read(out, "another interface as NAME=CARD (enter to finish): ")? {
        if answer.is_empty() {
            break;
        }
        let Some((id, card)) = answer.split_once('=') else {
            writeln!(out, "expected NAME=CARD")?;
            continue;
        };
        picked.push(sensr_ipc::Assignment {
            interface: id.trim().to_owned(),
            nic: pick(card.trim())?,
        });
    }
    Ok(picked)
}

async fn interfaces(
    c: &mut Client,
    cmd: InterfacesCmd,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    match cmd {
        InterfacesCmd::List { json } => {
            let n = nics(c).await?;
            if json {
                writeln!(out, "{}", output::json(&n))?;
            } else {
                output::nics(out, &n, false)?;
            }
        }
        InterfacesCmd::Assign {
            assignments,
            commit,
        } => {
            let picked = if assignments.is_empty() {
                ask_assignments(c, input, out).await?
            } else {
                assignments
                    .iter()
                    .map(|a| {
                        let (interface, nic) = a
                            .split_once('=')
                            .with_context(|| format!("{a:?}: expected INTERFACE=CARD"))?;
                        Ok(sensr_ipc::Assignment {
                            interface: interface.trim().to_owned(),
                            nic: nic.trim().to_owned(),
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?
            };
            if picked.is_empty() {
                writeln!(out, "nothing assigned")?;
                return Ok(());
            }
            let what = picked
                .iter()
                .map(|a| format!("{}={}", a.interface, a.nic))
                .collect::<Vec<_>>()
                .join(" ");
            match call(
                c,
                Op::InterfacesAssign {
                    assignments: picked,
                },
            )
            .await?
            {
                Response::Staged { dirty } => {
                    if !dirty {
                        writeln!(out, "already assigned that way")?;
                    } else if commit {
                        match call(
                            c,
                            Op::ConfigCommit {
                                description: Some(format!("interfaces assign {what}")),
                                confirm_secs: None,
                            },
                        )
                        .await?
                        {
                            Response::Committed(o) => output::committed(out, &o)?,
                            other => return Err(unexpected(other)),
                        }
                    } else {
                        writeln!(
                            out,
                            "staged {what}; review with `sensr config diff`, then `sensr config commit`"
                        )?;
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_windows() {
        assert_eq!(window_seconds("1h").unwrap(), 3_600);
        assert_eq!(window_seconds("7d").unwrap(), 604_800);
        assert_eq!(window_seconds("30m").unwrap(), 1_800);
        assert_eq!(window_seconds("15").unwrap(), 900);
        assert_eq!(window_seconds("5s").unwrap(), 60, "clamped to a minute");
        assert!(window_seconds("7w").is_err());
        assert!(window_seconds("soon").is_err());
    }

    const HOME_ROUTER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sensr-import-opnsense/tests/fixtures/corpus/home-router.xml"
    );

    #[test]
    fn dry_run_reports_and_writes_the_document_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let doc = dir.path().join("doc.json");
        let mut out = Vec::new();
        import_dry_run(
            std::path::Path::new(HOME_ROUTER),
            &[],
            true,
            Some(&doc),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("# sensr import report"), "{text}");
        assert!(!text.contains("does not validate"), "{text}");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
        assert!(json["interfaces"]["lan"].is_object());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&doc).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn dry_run_fails_a_document_that_does_not_validate() {
        let dir = tempfile::tempdir().unwrap();
        let xml = std::fs::read_to_string(HOME_ROUTER).unwrap();
        // the LAN tracks the WAN, which then asks for no prefix
        let broken = xml.replace(
            "<dhcp6-ia-pd-len>8</dhcp6-ia-pd-len>",
            "<dhcp6-ia-pd-len>none</dhcp6-ia-pd-len>",
        );
        assert_ne!(xml, broken, "fixture changed; update this test");
        let file = dir.path().join("config.xml");
        std::fs::write(&file, broken).unwrap();
        let mut out = Vec::new();
        let clean = import_dry_run(&file, &[], false, None, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!clean);
        assert!(text.contains("does not validate"), "{text}");
    }
}
