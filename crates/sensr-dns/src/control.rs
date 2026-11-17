//! `unbound-control`, run through sensr-apply's typed command runner with
//! the minimal `control.conf` (the full `unbound.conf` includes the
//! blocklist, which `unbound-control` would parse on every call).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use sensr_apply::cmd::{Cmd, CmdError, Runner};

/// Control failures.
#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    /// Could not run `unbound-control`.
    #[error(transparent)]
    Cmd(#[from] CmdError),
    /// It ran and failed (Unbound down, command rejected).
    #[error("unbound-control {cmd}: {message}")]
    Failed {
        /// The subcommand.
        cmd: String,
        /// Its output.
        message: String,
    },
}

/// A handle on a running Unbound.
pub struct Control<'a> {
    runner: &'a dyn Runner,
    conf: PathBuf,
}

impl<'a> Control<'a> {
    /// `unbound-control -c <conf>`.
    pub fn new(runner: &'a dyn Runner, conf: impl Into<PathBuf>) -> Self {
        Self {
            runner,
            conf: conf.into(),
        }
    }

    fn run(&self, args: &[&str], input: Option<&[String]>) -> Result<String, ControlError> {
        let cmd = Cmd::new("unbound-control")
            .arg("-c")
            .arg(&self.conf)
            .args(args);
        let out = match input {
            Some(lines) => {
                let mut feed = |w: &mut dyn Write| {
                    for l in lines {
                        w.write_all(l.as_bytes())?;
                        w.write_all(b"\n")?;
                    }
                    Ok(())
                };
                self.runner.run(&cmd, Some(&mut feed))?
            }
            None => self.runner.run(&cmd, None)?,
        };
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        // unbound-control reports some failures on stdout with exit 0.
        if !out.success() || stdout.starts_with("error") {
            return Err(ControlError::Failed {
                cmd: args.join(" "),
                message: format!("{}{}", stdout.trim(), out.stderr_text()),
            });
        }
        Ok(stdout)
    }

    /// Whether Unbound answers on its control socket.
    pub fn is_running(&self) -> bool {
        self.run(&["status"], None).is_ok()
    }

    /// Adds local zones (`name type` lines), changing the type of existing
    /// ones.
    pub fn local_zones(&self, lines: &[String]) -> Result<(), ControlError> {
        self.bulk("local_zones", lines)
    }

    /// Removes local zones by name.
    pub fn local_zones_remove(&self, names: &[String]) -> Result<(), ControlError> {
        self.bulk("local_zones_remove", names)
    }

    /// Adds local data (RR lines).
    pub fn local_datas(&self, lines: &[String]) -> Result<(), ControlError> {
        self.bulk("local_datas", lines)
    }

    /// Removes local data by name.
    pub fn local_datas_remove(&self, names: &[String]) -> Result<(), ControlError> {
        self.bulk("local_datas_remove", names)
    }

    fn bulk(&self, cmd: &str, lines: &[String]) -> Result<(), ControlError> {
        if lines.is_empty() {
            return Ok(());
        }
        // Bounded batches keep each control connection short.
        for chunk in lines.chunks(50_000) {
            self.run(&[cmd], Some(chunk))?;
        }
        Ok(())
    }

    /// Re-reads the configuration without dropping service or the cache
    /// (`fast_reload`); falls back to a plain `reload` where that is not
    /// available.
    pub fn reload(&self) -> Result<&'static str, ControlError> {
        match self.run(&["fast_reload"], None) {
            Ok(_) => Ok("fast_reload"),
            Err(_) => self.run(&["reload"], None).map(|_| "reload"),
        }
    }

    /// `stats_noreset` as key → value.
    pub fn stats(&self) -> Result<BTreeMap<String, f64>, ControlError> {
        Ok(parse_stats(&self.run(&["stats_noreset"], None)?))
    }
}

/// Parses `key=value` statistics lines.
pub fn parse_stats(text: &str) -> BTreeMap<String, f64> {
    text.lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_owned(), v.trim().parse().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_apply::cmd::{FakeRunner, Output};

    #[test]
    fn bulk_commands_feed_stdin_and_reload_falls_back() {
        let r = FakeRunner::new();
        r.respond(|cmd, _| {
            cmd.get_args()
                .iter()
                .any(|a| a == "fast_reload")
                .then(|| Output::failed(1, "error unknown command"))
        });
        let c = Control::new(&r, "/run/sensr/unbound/control.conf");
        c.local_zones(&["ads.example.com. always_null".into()])
            .unwrap();
        c.local_datas_remove(&[]).unwrap();
        assert_eq!(c.reload().unwrap(), "reload");
        let calls = r.calls();
        assert_eq!(
            r.call_lines(),
            [
                "unbound-control '-c' '/run/sensr/unbound/control.conf' 'local_zones'",
                "unbound-control '-c' '/run/sensr/unbound/control.conf' 'fast_reload'",
                "unbound-control '-c' '/run/sensr/unbound/control.conf' 'reload'",
            ]
        );
        assert_eq!(
            calls[0].stdin.as_deref(),
            Some(&b"ads.example.com. always_null\n"[..])
        );
    }

    #[test]
    fn stats_parse() {
        let s = parse_stats("total.num.queries=10\ntotal.num.cachehits=7\ntime.up=12.5\nbogus\n");
        assert_eq!(s["total.num.queries"], 10.0);
        assert_eq!(s["time.up"], 12.5);
        assert_eq!(s.len(), 3);
    }
}
