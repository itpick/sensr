//! Operator hook drop-ins: sensr's `rc.syshook`.
//!
//! Executables in `/etc/sensr/hooks/<level>/` run in lexical order with the
//! level's arguments, as upstream runs `rc.syshook.d/<level>/*`. A failing hook
//! is reported and the remaining hooks still run (upstream sets `RETURN=1` and
//! carries on), so one broken script cannot stop boot.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, Program, Runner};

/// The documented hook levels (upstream `rc.syshook.d` directories).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookLevel {
    /// Before services start at boot.
    Early,
    /// After the boot apply finished.
    Start,
    /// At shutdown.
    Stop,
    /// VRRP/CARP state transitions.
    Carp,
    /// After an apply committed a new configuration.
    Config,
    /// Gateway monitor alarms.
    Monitor,
    /// After a configuration import.
    Import,
    /// After a package/closure update.
    Update,
    /// After a major upgrade (new NixOS generation).
    Upgrade,
}

impl HookLevel {
    /// Every level.
    pub const ALL: [HookLevel; 9] = [
        HookLevel::Early,
        HookLevel::Start,
        HookLevel::Stop,
        HookLevel::Carp,
        HookLevel::Config,
        HookLevel::Monitor,
        HookLevel::Import,
        HookLevel::Update,
        HookLevel::Upgrade,
    ];

    /// Directory name of the level.
    pub fn as_str(self) -> &'static str {
        match self {
            HookLevel::Early => "early",
            HookLevel::Start => "start",
            HookLevel::Stop => "stop",
            HookLevel::Carp => "carp",
            HookLevel::Config => "config",
            HookLevel::Monitor => "monitor",
            HookLevel::Import => "import",
            HookLevel::Update => "update",
            HookLevel::Upgrade => "upgrade",
        }
    }
}

impl fmt::Display for HookLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Unknown hook level name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown hook level {0:?}")]
pub struct UnknownLevel(pub String);

impl FromStr for HookLevel {
    type Err = UnknownLevel;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HookLevel::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or_else(|| UnknownLevel(s.to_owned()))
    }
}

/// Where hooks live, relative to an injectable root (`/` in production).
#[derive(Debug, Clone)]
pub struct Hooks {
    root: PathBuf,
}

/// What happened to one hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookResult {
    /// Display name: file name without its `NN-` ordering prefix.
    pub name: String,
    /// The file that ran.
    pub path: PathBuf,
    /// Whether it exited 0.
    pub ok: bool,
    /// Its stderr (or why it could not run).
    pub message: String,
}

/// The outcome of a hook level.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookReport {
    /// One entry per hook, in execution order.
    pub results: Vec<HookResult>,
    /// Files skipped because they are not executable.
    pub skipped: Vec<PathBuf>,
}

impl HookReport {
    /// True when every hook succeeded (an empty level succeeds).
    pub fn ok(&self) -> bool {
        self.results.iter().all(|r| r.ok)
    }
}

impl Hooks {
    /// Hooks under `root/etc/sensr/hooks`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Hooks { root: root.into() }
    }

    /// The directory of a level.
    pub fn dir(&self, level: HookLevel) -> PathBuf {
        self.root.join("etc/sensr/hooks").join(level.as_str())
    }

    /// The hook files of a level, in execution (lexical byte) order.
    pub fn list(&self, level: HookLevel) -> std::io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
        let dir = self.dir(level);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // No directory means no hooks, as upstream.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), Vec::new()));
            }
            Err(e) => return Err(e),
        };
        let mut files = Vec::new();
        for e in entries {
            let e = e?;
            let ft = e.file_type()?;
            // Follow symlinks: operators commonly link hooks from elsewhere.
            if ft.is_file() || (ft.is_symlink() && e.path().is_file()) {
                files.push(e.path());
            }
        }
        files.sort();
        let (run, skip) = files.into_iter().partition(|p| is_executable(p));
        Ok((run, skip))
    }

    /// Run every hook of `level` with `args`.
    pub fn run(
        &self,
        level: HookLevel,
        args: &[&str],
        runner: &dyn Runner,
    ) -> std::io::Result<HookReport> {
        let (files, skipped) = self.list(level)?;
        let mut report = HookReport {
            results: Vec::new(),
            skipped,
        };
        for path in files {
            let file_name = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let cmd = Cmd::from_program(Program::path(path.clone())).args(args);
            let (ok, message) = match runner.run(&cmd, None) {
                Ok(out) => (out.success(), out.stderr_text()),
                Err(e) => (false, e.to_string()),
            };
            report.results.push(HookResult {
                name: display_name(&file_name).to_owned(),
                path,
                ok,
                message,
            });
        }
        Ok(report)
    }
}

/// `20-mycorehook` → `mycorehook` (upstream strips two characters and a dash).
fn display_name(file: &str) -> &str {
    let b = file.as_bytes();
    if b.len() > 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b'-' {
        &file[3..]
    } else {
        file
    }
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    fn write(dir: &Path, name: &str, mode: u32) {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    #[test]
    fn levels_round_trip_and_match_upstream_dirs() {
        for l in HookLevel::ALL {
            assert_eq!(l.as_str().parse::<HookLevel>().unwrap(), l);
        }
        // Upstream ships these directories under rc.syshook.d.
        for d in [
            "carp", "early", "import", "monitor", "start", "stop", "update", "upgrade",
        ] {
            assert!(d.parse::<HookLevel>().is_ok(), "{d}");
        }
        assert!("bogus".parse::<HookLevel>().is_err());
    }

    #[test]
    fn hooks_run_in_lexical_order_with_args_and_continue_after_failure() {
        let root = tempfile::tempdir().unwrap();
        let hooks = Hooks::new(root.path());
        let dir = hooks.dir(HookLevel::Start);
        std::fs::create_dir_all(&dir).unwrap();
        write(&dir, "50-plugin", 0o755);
        write(&dir, "20-core", 0o755);
        write(&dir, "30-broken", 0o755);
        write(&dir, "40-notexec", 0o644);

        let run = FakeRunner::new();
        run.respond(|cmd, _| {
            cmd.program()
                .as_os_str()
                .to_string_lossy()
                .ends_with("30-broken")
                .then(|| Output::failed(1, "boom"))
        });
        let rep = hooks.run(HookLevel::Start, &["wan"], &run).unwrap();
        let names: Vec<_> = rep.results.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["core", "broken", "plugin"]);
        assert!(!rep.ok());
        assert_eq!(rep.results[1].message, "boom");
        assert_eq!(rep.skipped.len(), 1);
        assert!(run.call_lines().iter().all(|l| l.ends_with(" 'wan'")));
    }

    #[test]
    fn missing_level_dir_is_empty_success() {
        let root = tempfile::tempdir().unwrap();
        let rep = Hooks::new(root.path())
            .run(HookLevel::Carp, &[], &FakeRunner::new())
            .unwrap();
        assert!(rep.ok());
        assert!(rep.results.is_empty());
    }
}
