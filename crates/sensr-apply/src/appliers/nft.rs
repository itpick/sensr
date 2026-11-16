//! nftables applier: check, then load, the whole ruleset as one JSON
//! transaction (`nft -c -j -f -`, then `nft -j -f -`).
//!
//! The ruleset is streamed straight from its producer into nft's stdin (and
//! into the digest), never held as one big buffer or JSON DOM: research note
//! 07 measured 337 MiB for a DOM-built 10k-rule ruleset against ~10 MiB
//! streamed.

use std::io::{self, Write};
use std::time::{Duration, Instant};

use crate::cmd::{Cmd, CmdError, Runner};
use crate::plan::NftSpec;

/// Something that can write a complete nftables JSON document
/// (`{"nftables": [...]}`), including its own `flush ruleset`/table flushes.
/// `sensr-rules` implements this for its rendered rulesets.
pub trait NftRuleset {
    /// Write the document. Called more than once per apply (digest, check,
    /// load), so it must be deterministic.
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()>;
}

impl NftRuleset for [u8] {
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self)
    }
}

impl NftRuleset for Vec<u8> {
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self)
    }
}

impl NftRuleset for str {
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self.as_bytes())
    }
}

/// Adapts any writer function (e.g. `|w| sensr_rules::render::nft::render(w, ..)`)
/// to [`NftRuleset`].
pub struct FnRuleset<F>(pub F);

impl<F: Fn(&mut dyn Write) -> io::Result<()>> NftRuleset for FnRuleset<F> {
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        (self.0)(w)
    }
}

/// Which nft invocation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftStage {
    /// `nft -c` (dry run against the kernel).
    Check,
    /// The real transaction.
    Load,
}

/// nft applier errors.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// nft rejected the ruleset; `message` is nft's own error text, which
    /// points at the offending command.
    #[error("nft {stage:?} rejected the ruleset: {message}")]
    Rejected {
        /// Check or load.
        stage: NftStage,
        /// nft's stderr.
        message: String,
    },
    /// nft could not be run.
    #[error(transparent)]
    Cmd(#[from] CmdError),
    /// The ruleset writer failed.
    #[error("rendering the ruleset: {0}")]
    Render(#[from] io::Error),
}

/// Timings and size of one apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NftReport {
    /// Bytes of JSON streamed per invocation.
    pub bytes: u64,
    /// Time spent in `nft -c` (render streaming included).
    pub check: Duration,
    /// Time spent in the loading `nft` run (render streaming included).
    pub load: Duration,
}

/// Counts bytes and computes a 64-bit FNV-1a digest while forwarding.
/// The digest only needs to be stable and collision-unlikely for plan diffs,
/// not cryptographic.
struct Tee<'a> {
    inner: Option<&'a mut dyn Write>,
    bytes: u64,
    hash: u64,
}

impl<'a> Tee<'a> {
    fn new(inner: Option<&'a mut dyn Write>) -> Self {
        Tee {
            inner,
            bytes: 0,
            hash: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl Write for Tee<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = match self.inner.as_mut() {
            Some(w) => w.write(buf)?,
            None => buf.len(),
        };
        for b in &buf[..n] {
            self.hash ^= u64::from(*b);
            self.hash = self.hash.wrapping_mul(0x0100_0000_01b3);
        }
        self.bytes += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

/// Digest and size of a ruleset, computed by streaming it once.
pub fn digest<R: NftRuleset + ?Sized>(rs: &R) -> io::Result<(String, u64)> {
    let mut t = Tee::new(None);
    rs.write_json(&mut t)?;
    Ok((format!("{:016x}", t.hash), t.bytes))
}

/// The plan entry for a ruleset.
pub fn plan_spec<R: NftRuleset + ?Sized>(
    rs: &R,
    summary: impl Into<String>,
) -> io::Result<NftSpec> {
    Ok(NftSpec {
        digest: digest(rs)?.0,
        summary: summary.into(),
    })
}

fn run_nft<R: NftRuleset + ?Sized>(
    runner: &dyn Runner,
    rs: &R,
    check: bool,
) -> Result<(u64, Duration), NftError> {
    let mut args = vec!["-j", "-f", "-"];
    if check {
        args.insert(0, "-c");
    }
    let cmd = Cmd::new("nft").args(&args);
    let mut bytes = 0;
    let mut render_err: Option<io::Error> = None;
    let start = Instant::now();
    let mut feed = |w: &mut dyn Write| {
        let mut t = Tee::new(Some(w));
        let r = rs.write_json(&mut t);
        bytes = t.bytes;
        if let Err(e) = &r
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            render_err = Some(io::Error::new(e.kind(), e.to_string()));
        }
        r
    };
    let out = runner.run(&cmd, Some(&mut feed))?;
    let took = start.elapsed();
    if let Some(e) = render_err {
        return Err(NftError::Render(e));
    }
    if !out.success() {
        return Err(NftError::Rejected {
            stage: if check {
                NftStage::Check
            } else {
                NftStage::Load
            },
            message: out.stderr_text(),
        });
    }
    Ok((bytes, took))
}

/// Dry-run the ruleset against the kernel (`nft -c`), loading nothing.
pub fn check<R: NftRuleset + ?Sized>(runner: &dyn Runner, rs: &R) -> Result<(), NftError> {
    run_nft(runner, rs, true).map(|_| ())
}

/// Load the ruleset in one atomic transaction without a separate check
/// pass. Equally safe (a rejected transaction changes nothing) and about
/// half the time of [`apply`] (measured: 10k rules ~250 ms instead of
/// ~510 ms), but the error comes from the load stage.
pub fn load<R: NftRuleset + ?Sized>(runner: &dyn Runner, rs: &R) -> Result<NftReport, NftError> {
    let (bytes, load) = run_nft(runner, rs, false)?;
    Ok(NftReport {
        bytes,
        check: Duration::ZERO,
        load,
    })
}

/// Check, then atomically load, the ruleset. Nothing is loaded if the check
/// fails; if the load itself fails the kernel keeps the previous ruleset
/// (nft transactions are all-or-nothing).
pub fn apply<R: NftRuleset + ?Sized>(runner: &dyn Runner, rs: &R) -> Result<NftReport, NftError> {
    let (bytes, check) = run_nft(runner, rs, true)?;
    let (_, load) = run_nft(runner, rs, false)?;
    Ok(NftReport { bytes, check, load })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output, SystemRunner};

    const RULESET: &str = r#"{"nftables":[{"flush":{"ruleset":null}},{"add":{"table":{"family":"inet","name":"sensr"}}},{"add":{"chain":{"family":"inet","table":"sensr","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}}},{"add":{"rule":{"family":"inet","table":"sensr","chain":"input","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}}}]}"#;

    #[test]
    fn checks_then_loads_streaming_the_same_bytes() {
        let run = FakeRunner::new();
        let rep = apply(&run, RULESET).unwrap();
        assert_eq!(rep.bytes, RULESET.len() as u64);
        let calls = run.calls();
        assert_eq!(
            run.call_lines(),
            ["nft '-c' '-j' '-f' '-'", "nft '-j' '-f' '-'"]
        );
        for c in &calls {
            assert_eq!(c.stdin.as_deref(), Some(RULESET.as_bytes()));
        }
    }

    #[test]
    fn failed_check_never_loads_and_reports_nft_message() {
        let run = FakeRunner::new();
        run.push(
            "nft",
            Output::failed(
                1,
                "Error: Could not process rule: No such file or directory\n",
            ),
        );
        let err = apply(&run, RULESET).unwrap_err();
        match err {
            NftError::Rejected { stage, message } => {
                assert_eq!(stage, NftStage::Check);
                assert!(message.contains("Could not process rule"));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(run.calls().len(), 1);
    }

    #[test]
    fn closures_are_rulesets() {
        let rs = FnRuleset(|w: &mut dyn Write| w.write_all(RULESET.as_bytes()));
        assert_eq!(digest(&rs).unwrap(), digest(RULESET).unwrap());
    }

    #[test]
    fn load_is_a_single_transaction() {
        let run = FakeRunner::new();
        let rep = load(&run, RULESET).unwrap();
        assert_eq!(rep.check, Duration::ZERO);
        assert_eq!(run.call_lines(), ["nft '-j' '-f' '-'"]);
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let (a, n) = digest(RULESET).unwrap();
        assert_eq!(digest(RULESET).unwrap().0, a);
        assert_eq!(n, RULESET.len() as u64);
        assert_ne!(digest("{}").unwrap().0, a);
        assert_eq!(plan_spec(RULESET, "1 rule").unwrap().digest, a);
    }

    /// Real `nft -c` when available, in a throwaway user+network namespace
    /// when we are not root. Skips (with a note) where nft is absent, e.g. on
    /// macOS dev machines; CI and nixtop have it.
    #[test]
    fn real_nft_accepts_sample_ruleset() {
        if !SystemRunner.has_program("nft") {
            eprintln!("note: nft not installed; skipping real nft check");
            return;
        }
        let out = SystemRunner
            .run(
                &Cmd::new("unshare").args(["-rn", "nft", "-c", "-j", "-f", "-"]),
                Some(&mut |w: &mut dyn Write| w.write_all(RULESET.as_bytes())),
            )
            .unwrap();
        if out.stderr_text().starts_with("unshare:") {
            eprintln!("note: user namespaces unavailable; skipping");
            return;
        }
        assert!(out.success(), "{}", out.stderr_text());
    }
}
