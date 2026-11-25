//! Test tool for the loader (nix/tests/guard-load.nix, nix/tests/guard-load.sh).
//!
//! `guard-load-probe <pack dir> <fifo dir>` loads the pack, then serves
//! commands: it reads lines from the FIFO `<fifo dir>/cmd` and answers each
//! on the FIFO `<fifo dir>/reply` (both made by the caller with mkfifo):
//!
//! - `status`: one line per program, `<name> <hook> attached|detached [reason]`
//! - `apply <rules.json> <0|1>`: compile the rules, apply them with that
//!   kill switch and this process as guard_tgid; `ok` or `error: ...`
//! - `hits`: `<rule id> <count>` per applied rule
//! - `events`: drain the ring buffer, `rule=<slot> hook=<n> blocked=<0|1> port=<p>`
//! - `quit`: `bye`, then drop the pack (detaching everything) and exit.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("guard-load-probe: Linux only");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Write};
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;

    use sensr_guard::compile::compile;
    use sensr_guard::loader::{Loaded, load};
    use sensr_guard::rule::Rule;

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        let [_, pack, dir] = args.as_slice() else {
            eprintln!("usage: guard-load-probe <pack dir> <fifo dir>");
            return ExitCode::from(2);
        };
        let mut loaded = match load(Path::new(pack)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("load: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!("loaded {} programs", loaded.status().len());
        let dir = PathBuf::from(dir);
        let mut ring = match loaded.ringbuf() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("ringbuf: {e}");
                return ExitCode::FAILURE;
            }
        };
        loop {
            let cmd = match std::fs::File::open(dir.join("cmd")) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("cmd fifo: {e}");
                    return ExitCode::FAILURE;
                }
            };
            for line in BufReader::new(cmd).lines() {
                let Ok(line) = line else { break };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                let (reply, quit) = run(&mut loaded, &mut ring, &line);
                if let Err(e) = std::fs::OpenOptions::new()
                    .write(true)
                    .open(dir.join("reply"))
                    .and_then(|mut f| f.write_all(reply.as_bytes()))
                {
                    eprintln!("reply fifo: {e}");
                    return ExitCode::FAILURE;
                }
                if quit {
                    drop(ring);
                    drop(loaded);
                    return ExitCode::SUCCESS;
                }
            }
        }
    }

    fn run(
        loaded: &mut Loaded,
        ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
        line: &str,
    ) -> (String, bool) {
        let words: Vec<&str> = line.split_whitespace().collect();
        let mut out = String::new();
        match words.as_slice() {
            ["status"] => {
                for p in loaded.status() {
                    let state = if p.attached { "attached" } else { "detached" };
                    let reason = p.reason.unwrap_or_default().replace('\n', " ");
                    out += &format!("{} {} {state} {reason}\n", p.name, p.hook);
                }
            }
            ["apply", file, kill] => {
                let r = std::fs::read(file)
                    .map_err(|e| e.to_string())
                    .and_then(|b| {
                        serde_json::from_slice::<Vec<Rule>>(&b).map_err(|e| e.to_string())
                    })
                    .and_then(|rules| compile(&rules).map_err(|e| e.to_string()))
                    .and_then(|c| {
                        loaded
                            .apply(&c, *kill == "1", std::process::id())
                            .map_err(|e| e.to_string())
                    });
                out = match r {
                    Ok(()) => "ok\n".into(),
                    Err(e) => format!("error: {e}\n"),
                };
            }
            ["hits"] => {
                let mut h: Vec<_> = loaded.hits_by_id().into_iter().collect();
                h.sort();
                for (id, n) in h {
                    out += &format!("{id} {n}\n");
                }
            }
            ["events"] => {
                while let Some(item) = ring.next() {
                    let b: &[u8] = &item;
                    if b.len() < 559 {
                        continue;
                    }
                    let rule = u32::from_le_bytes(b[20..24].try_into().expect("4 bytes"));
                    let port = u16::from_le_bytes(b[556..558].try_into().expect("2 bytes"));
                    out += &format!("rule={rule} hook={} blocked={} port={port}\n", b[24], b[26]);
                }
            }
            ["quit"] => return ("bye\n".into(), true),
            _ => out = format!("error: unknown command {line:?}\n"),
        }
        (out, false)
    }
}
