//! Typed external commands: the only place in sensr that spawns processes.
//!
//! OPNsense builds shell strings (`Shell::exec_safe`, configd's `_cmd_builder`)
//! and hands them to `/bin/sh`. sensr never does: a [`Cmd`] is a program from a
//! fixed set plus an argument vector, executed directly with `execve`, so there
//! is nothing for an argument to escape from. [`safe_format`] still exists, with
//! upstream's exact semantics, because audit logs and `--dry-run` output show
//! commands as copy-pasteable shell text and because T-0005 pins those
//! semantics.
//!
//! `std::process::Command::new` is a disallowed method for this crate
//! (`clippy.toml`, T-0372); the single allowed call is in [`SystemRunner`].

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// One argument for [`safe_format`], mirroring the PHP scalar kinds upstream accepts.
#[derive(Debug, Clone, PartialEq)]
pub enum FormatArg<'a> {
    /// PHP `null`: formats as an empty quoted string.
    Null,
    /// A string.
    Str(&'a str),
    /// An integer.
    Int(i64),
    /// A float, formatted like PHP's string conversion for simple values.
    Float(f64),
}

impl FormatArg<'_> {
    fn to_text(&self) -> String {
        match self {
            FormatArg::Null => String::new(),
            FormatArg::Str(s) => (*s).to_owned(),
            FormatArg::Int(i) => i.to_string(),
            FormatArg::Float(f) => f.to_string(),
        }
    }
}

impl<'a> From<&'a str> for FormatArg<'a> {
    fn from(s: &'a str) -> Self {
        FormatArg::Str(s)
    }
}

/// Why a format string could not be expanded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    /// A `%x` directive other than `%s` / `%%`.
    #[error("unsupported formatter %{0}")]
    UnsupportedFormatter(char),
    /// More `%s` than arguments.
    #[error("missing arguments")]
    MissingArguments,
    /// More arguments than `%s`.
    #[error("excess arguments")]
    ExcessArguments,
}

/// POSIX single-quote an argument (PHP `escapeshellarg` semantics).
pub fn shell_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Expand `%s` (quoted argument) and `%%` (literal `%`) in a format that is
/// given as words joined by single spaces, like upstream's `exec_safe`.
///
/// Every argument is consumed exactly once; anything else is an error rather
/// than upstream's `/usr/bin/true` sentinel, so callers cannot run a command
/// they did not mean to.
pub fn safe_format(format: &[&str], args: &[FormatArg<'_>]) -> Result<String, FormatError> {
    let joined = format.join(" ");
    let mut out = String::with_capacity(joined.len() + 16);
    let mut remaining = args.iter();
    let mut chars = joined.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some('s') => {
                let arg = remaining.next().ok_or(FormatError::MissingArguments)?;
                out.push_str(&shell_quote(&arg.to_text()));
            }
            Some(other) => return Err(FormatError::UnsupportedFormatter(other)),
            // A trailing lone '%' is not a directive (PCRE `%.` needs a second char).
            None => out.push('%'),
        }
    }
    if remaining.next().is_some() {
        return Err(FormatError::ExcessArguments);
    }
    Ok(out)
}

/// What to execute. Only programs named at compile time, or hook files
/// discovered by [`crate::hooks`], can be run.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Program(ProgramKind);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ProgramKind {
    Named(&'static str),
    Path(PathBuf),
}

impl Program {
    /// A program looked up on the agent's `PATH` (set by its systemd unit).
    pub const fn named(name: &'static str) -> Self {
        Program(ProgramKind::Named(name))
    }

    /// An operator-provided executable (hook drop-ins only).
    pub(crate) fn path(path: PathBuf) -> Self {
        Program(ProgramKind::Path(path))
    }

    /// The program as passed to `execve`.
    pub fn as_os_str(&self) -> &OsStr {
        match &self.0 {
            ProgramKind::Named(n) => OsStr::new(n),
            ProgramKind::Path(p) => p.as_os_str(),
        }
    }
}

/// A typed command: program plus argument vector, no shell involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    program: Program,
    args: Vec<OsString>,
}

impl Cmd {
    /// A command for a program known at compile time.
    pub fn new(program: &'static str) -> Self {
        Cmd {
            program: Program::named(program),
            args: Vec::new(),
        }
    }

    pub(crate) fn from_program(program: Program) -> Self {
        Cmd {
            program,
            args: Vec::new(),
        }
    }

    /// Append one argument (never split, never interpreted).
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    /// Append several arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    /// The program.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// The argument vector (without argv\[0\]).
    pub fn get_args(&self) -> &[OsString] {
        &self.args
    }

    /// Shell-quoted rendering for logs, audit and `--dry-run`; every argument is quoted.
    pub fn display(&self) -> String {
        let mut out = self.program.as_os_str().to_string_lossy().into_owned();
        for a in &self.args {
            out.push(' ');
            out.push_str(&shell_quote(&a.to_string_lossy()));
        }
        out
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Result of running a [`Cmd`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit code; `None` when killed by a signal.
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: Vec<u8>,
    /// Captured standard error.
    pub stderr: Vec<u8>,
}

impl Output {
    /// A successful empty result.
    pub fn ok() -> Self {
        Output {
            code: Some(0),
            ..Default::default()
        }
    }

    /// A failed result with a message on stderr.
    pub fn failed(code: i32, stderr: impl Into<Vec<u8>>) -> Self {
        Output {
            code: Some(code),
            stdout: Vec::new(),
            stderr: stderr.into(),
        }
    }

    /// Exit status 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Standard error as (lossy) text, trimmed.
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).trim().to_owned()
    }
}

/// Failure to run a command at all (as opposed to a non-zero exit).
#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    /// The program could not be started.
    #[error("cannot run {cmd}: {source}")]
    Spawn {
        /// The command, shell-quoted.
        cmd: String,
        /// The OS error.
        source: io::Error,
    },
    /// Writing stdin or reading output failed.
    #[error("i/o with {cmd}: {source}")]
    Io {
        /// The command, shell-quoted.
        cmd: String,
        /// The OS error.
        source: io::Error,
    },
}

/// Produces a command's standard input incrementally, so large inputs (an nft
/// ruleset) are streamed instead of buffered.
pub type StdinWriter<'a> = &'a mut dyn FnMut(&mut dyn Write) -> io::Result<()>;

/// Executes commands. Appliers take a `&dyn Runner` so tests use [`FakeRunner`].
pub trait Runner: Send + Sync {
    /// Run `cmd`, feeding `stdin` if given, and capture its output.
    fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError>;

    /// Whether `program` can be found (used to skip optional checkers).
    fn has_program(&self, program: &str) -> bool;
}

/// Runs commands on the host.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError> {
        use std::process::Stdio;
        let shown = || cmd.display();
        #[allow(clippy::disallowed_methods)] // the one sanctioned spawn site (T-0372)
        let mut command = std::process::Command::new(cmd.program.as_os_str());
        command
            .args(&cmd.args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(|source| CmdError::Spawn {
            cmd: shown(),
            source,
        })?;
        let child_stdin = child.stdin.take();
        let mut child_stdout = child.stdout.take();
        let mut child_stderr = child.stderr.take();
        // Drain stdout/stderr on their own threads while we write stdin, so a
        // chatty child can never deadlock against a full pipe.
        let (stdout, stderr, write_result) = std::thread::scope(|s| {
            let out = s.spawn(move || {
                let mut buf = Vec::new();
                if let Some(o) = child_stdout.as_mut() {
                    o.read_to_end(&mut buf)?;
                }
                Ok::<_, io::Error>(buf)
            });
            let err = s.spawn(move || {
                let mut buf = Vec::new();
                if let Some(e) = child_stderr.as_mut() {
                    e.read_to_end(&mut buf)?;
                }
                Ok::<_, io::Error>(buf)
            });
            let write_result = match (stdin, child_stdin) {
                (Some(writer), Some(pipe)) => {
                    let mut pipe = io::BufWriter::with_capacity(64 * 1024, pipe);
                    let r = writer(&mut pipe).and_then(|()| pipe.flush());
                    drop(pipe); // close stdin so the child sees EOF
                    r
                }
                _ => Ok(()),
            };
            let stdout = out.join().unwrap_or_else(|_| Ok(Vec::new()));
            let stderr = err.join().unwrap_or_else(|_| Ok(Vec::new()));
            (stdout, stderr, write_result)
        });
        let status = child.wait().map_err(|source| CmdError::Io {
            cmd: shown(),
            source,
        })?;
        let io_err = |source| CmdError::Io {
            cmd: shown(),
            source,
        };
        let stdout = stdout.map_err(io_err)?;
        let stderr = stderr.map_err(io_err)?;
        // A broken pipe means the child exited early; its exit status and
        // stderr explain why better than EPIPE does.
        if let Err(e) = write_result
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            return Err(io_err(e));
        }
        Ok(Output {
            code: status.code(),
            stdout,
            stderr,
        })
    }

    fn has_program(&self, program: &str) -> bool {
        find_on_path(program).is_some()
    }
}

/// Locate `program` on `PATH` (no execution).
pub fn find_on_path(program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        let p = Path::new(program);
        return p.is_file().then(|| p.to_owned());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(program))
        .find(|p| p.is_file())
}

/// One call recorded by [`FakeRunner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The command.
    pub cmd: Cmd,
    /// Everything written to its stdin.
    pub stdin: Option<Vec<u8>>,
}

type Responder = Box<dyn Fn(&Cmd, Option<&[u8]>) -> Option<Output> + Send + Sync>;

/// A [`Runner`] for tests: records every call and answers from a script.
///
/// Responses are matched in order: queued one-shot outputs for a program
/// first, then responders, then a default success.
#[derive(Default)]
pub struct FakeRunner {
    calls: Mutex<Vec<Recorded>>,
    queued: Mutex<Vec<(String, VecDeque<Output>)>>,
    responders: Mutex<Vec<Responder>>,
    missing: Mutex<Vec<String>>,
}

impl fmt::Debug for FakeRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeRunner")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

impl FakeRunner {
    /// A runner where every command succeeds with no output.
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer the next call to `program` with `output`.
    pub fn push(&self, program: &str, output: Output) -> &Self {
        let mut q = lock(&self.queued);
        match q.iter_mut().find(|(p, _)| p == program) {
            Some((_, v)) => v.push_back(output),
            None => q.push((program.to_owned(), VecDeque::from([output]))),
        }
        self
    }

    /// Answer calls with `f` whenever it returns `Some`.
    pub fn respond(
        &self,
        f: impl Fn(&Cmd, Option<&[u8]>) -> Option<Output> + Send + Sync + 'static,
    ) -> &Self {
        lock(&self.responders).push(Box::new(f));
        self
    }

    /// Pretend `program` is not installed.
    pub fn without_program(&self, program: &str) -> &Self {
        lock(&self.missing).push(program.to_owned());
        self
    }

    /// All calls so far.
    pub fn calls(&self) -> Vec<Recorded> {
        lock(&self.calls).clone()
    }

    /// The calls so far, shell-quoted, one per entry.
    pub fn call_lines(&self) -> Vec<String> {
        lock(&self.calls).iter().map(|r| r.cmd.display()).collect()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panicking test thread must not cascade into unrelated assertions.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Runner for FakeRunner {
    fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError> {
        let input = match stdin {
            Some(w) => {
                let mut buf = Vec::new();
                w(&mut buf).map_err(|source| CmdError::Io {
                    cmd: cmd.display(),
                    source,
                })?;
                Some(buf)
            }
            None => None,
        };
        let program = cmd.program.as_os_str().to_string_lossy().into_owned();
        if lock(&self.missing).contains(&program) {
            return Err(CmdError::Spawn {
                cmd: cmd.display(),
                source: io::Error::from(io::ErrorKind::NotFound),
            });
        }
        lock(&self.calls).push(Recorded {
            cmd: cmd.clone(),
            stdin: input.clone(),
        });
        if let Some(out) = lock(&self.queued)
            .iter_mut()
            .find(|(p, _)| *p == program)
            .and_then(|(_, q)| q.pop_front())
        {
            return Ok(out);
        }
        for r in lock(&self.responders).iter() {
            if let Some(out) = r(cmd, input.as_deref()) {
                return Ok(out);
            }
        }
        Ok(Output::ok())
    }

    fn has_program(&self, program: &str) -> bool {
        !lock(&self.missing).iter().any(|p| p == program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Upstream's failure sentinel; a `FormatError` stands in for it here.
    const FAIL: &str = "/usr/bin/true";

    fn exec_safe(format: &[&str], args: &[FormatArg<'_>]) -> String {
        safe_format(format, args).unwrap_or_else(|_| FAIL.to_owned())
    }

    #[test]
    fn safe_format_table_t0005() {
        use FormatArg::{Float, Int, Null, Str};
        let simple = ["/this/cmd"];
        let normal = ["/this/cmd %s %% foo"];
        let normal_a = ["/this/cmd", "%s", "%%", "foo"];
        let r1 = "/this/cmd 'ok' % foo";
        let r2 = "/this/cmd '' % foo";
        let r3 = "/this/cmd '0' % foo";
        let complex = ["/this/cmd %s%%%s foo %s"];
        let unsupported = ["/this/cmd %d"];

        // (format, args, expected) — one row per upstream assertion, in order.
        let table: Vec<(&[&str], Vec<FormatArg<'_>>, &str)> = vec![
            (&[], vec![], ""),
            (&[], vec![], ""), // exec_safe([], [])
            (&[""], vec![], ""),
            (&[""], vec![Str("")], FAIL),
            (&[FAIL], vec![], FAIL),
            (&simple, vec![], "/this/cmd"),
            (&simple, vec![], "/this/cmd"), // ($simple, [])
            (&simple, vec![Str("fail")], FAIL),
            (&simple, vec![Str("fail"), Str("too")], FAIL),
            (&normal, vec![], FAIL),
            (&normal, vec![Str("ok")], r1), // scalar 'ok'
            (&normal, vec![Str("ok")], r1), // ['ok']
            (&normal, vec![Null], r2),
            (&normal, vec![Str("")], r2),
            (&normal, vec![Int(0)], r3),
            (&normal, vec![Str("ok"), Str("not")], FAIL),
            (&normal_a, vec![], FAIL),
            (&normal_a, vec![Str("ok")], r1),
            (&normal_a, vec![Str("ok")], r1),
            (&normal_a, vec![Str("ok"), Str("not")], FAIL),
            (
                &complex,
                vec![Str("1"), Int(1), Float(1.01)],
                "/this/cmd '1'%'1' foo '1.01'",
            ),
            (
                &complex,
                vec![Str(";rmfall ''"), Str("#comment\""), Str("&& echo hello")],
                "/this/cmd ';rmfall '\\'''\\'''%'#comment\"' foo '&& echo hello'",
            ),
            (&unsupported, vec![], FAIL),
            (&unsupported, vec![Str("foo")], FAIL),
            (&unsupported, vec![Int(1)], FAIL),
        ];
        assert_eq!(table.len(), 25);
        for (i, (format, args, expected)) in table.iter().enumerate() {
            assert_eq!(
                exec_safe(format, args),
                *expected,
                "row {i}: {format:?} {args:?}"
            );
        }
        assert_eq!(
            safe_format(&unsupported, &[]),
            Err(FormatError::UnsupportedFormatter('d'))
        );
        assert_eq!(
            safe_format(&normal, &[]),
            Err(FormatError::MissingArguments)
        );
        assert_eq!(
            safe_format(&simple, &[Str("x")]),
            Err(FormatError::ExcessArguments)
        );
    }

    /// Minimal POSIX word splitter for quoted text: single quotes and
    /// backslash-escapes outside quotes, which is all `shell_quote` emits.
    fn sh_split(s: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut cur = String::new();
        let mut in_word = false;
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            match c {
                '\'' => {
                    in_word = true;
                    for q in chars.by_ref() {
                        if q == '\'' {
                            break;
                        }
                        cur.push(q);
                    }
                }
                '\\' => {
                    in_word = true;
                    if let Some(n) = chars.next() {
                        cur.push(n);
                    }
                }
                ' ' => {
                    if in_word {
                        words.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                other => {
                    in_word = true;
                    cur.push(other);
                }
            }
        }
        if in_word {
            words.push(cur);
        }
        words
    }

    proptest! {
        #[test]
        fn prop_never_unquoted_t0005(args in proptest::collection::vec(".*", 0..6)) {
            let cmd = Cmd::new("prog").args(&args);
            let words = sh_split(&cmd.display());
            prop_assert_eq!(&words[0], "prog");
            prop_assert_eq!(&words[1..], &args[..]);

            let fmt = vec!["prog"; 1].into_iter().chain(args.iter().map(|_| "%s")).collect::<Vec<_>>();
            let fargs: Vec<FormatArg<'_>> = args.iter().map(|a| FormatArg::Str(a)).collect();
            let line = safe_format(&fmt, &fargs).unwrap();
            prop_assert_eq!(&sh_split(&line)[1..], &args[..]);
        }

        #[test]
        fn prop_safe_format_never_panics(fmt in ".*", n in 0usize..4) {
            let args = vec![FormatArg::Str("x"); n];
            let _ = safe_format(&[fmt.as_str()], &args);
        }
    }

    #[test]
    fn fake_runner_records_stdin_and_scripted_output() {
        let r = FakeRunner::new();
        r.push("nft", Output::failed(1, "Error: syntax"));
        let cmd = Cmd::new("nft").args(["-c", "-j", "-f", "-"]);
        let mut w = |out: &mut dyn Write| out.write_all(b"{}");
        let out = r.run(&cmd, Some(&mut w)).unwrap();
        assert!(!out.success());
        assert_eq!(out.stderr_text(), "Error: syntax");
        assert!(r.run(&cmd, None).unwrap().success());
        let calls = r.calls();
        assert_eq!(calls[0].stdin.as_deref(), Some(&b"{}"[..]));
        assert_eq!(r.call_lines()[1], "nft '-c' '-j' '-f' '-'");
    }

    #[cfg(unix)]
    #[test]
    fn system_runner_streams_stdin_through_cat() {
        if !SystemRunner.has_program("cat") {
            eprintln!("note: `cat` not on PATH, skipping");
            return;
        }
        let big = vec![b'x'; 1 << 20];
        let mut w = |out: &mut dyn Write| {
            for chunk in big.chunks(4096) {
                out.write_all(chunk)?;
            }
            Ok(())
        };
        let out = SystemRunner.run(&Cmd::new("cat"), Some(&mut w)).unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.len(), 1 << 20);
    }

    #[test]
    fn system_runner_reports_missing_program() {
        let err = SystemRunner
            .run(&Cmd::new("sensr-definitely-not-a-program"), None)
            .unwrap_err();
        assert!(matches!(err, CmdError::Spawn { .. }));
    }
}
