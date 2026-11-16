//! Times the nft applier (stream → `nft -c` → `nft -j -f`) on synthetic
//! linear rulesets, in a throwaway user+network namespace so it needs no root:
//!
//! ```text
//! nix shell nixpkgs#nftables -c cargo run --release -p sensr-apply --example nft_apply_bench -- 50 1000 10000
//! ```
//!
//! The ruleset is generated on the fly while streaming, so the agent's peak
//! memory stays flat regardless of size (the point of the streaming design).

use std::io::{self, Write};

use sensr_apply::appliers::nft::{self, NftRuleset};
use sensr_apply::cmd::{Cmd, CmdError, Output, Runner, StdinWriter, SystemRunner};

/// N rules in a forward chain behind the usual established/related fast path.
struct Synthetic(usize);

impl NftRuleset for Synthetic {
    fn write_json(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(br#"{"nftables":[{"flush":{"ruleset":null}},{"add":{"table":{"family":"inet","name":"sensr"}}},{"add":{"chain":{"family":"inet","table":"sensr","name":"forward","type":"filter","hook":"forward","prio":0,"policy":"drop"}}},{"add":{"rule":{"family":"inet","table":"sensr","chain":"forward","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}}}"#)?;
        for j in 0..self.0 {
            write!(
                w,
                r#",{{"add":{{"rule":{{"family":"inet","table":"sensr","chain":"forward","comment":"rule {j}","expr":[{{"match":{{"op":"==","left":{{"payload":{{"protocol":"ip","field":"saddr"}}}},"right":"192.168.{}.{}"}}}},{{"match":{{"op":"==","left":{{"payload":{{"protocol":"tcp","field":"dport"}}}},"right":{}}}}},{{"counter":null}},{{"{}":null}}]}}}}}}"#,
                (j / 250) % 250,
                j % 250 + 1,
                20000 + (j % 40000),
                if j % 3 == 0 { "drop" } else { "accept" }
            )?;
        }
        w.write_all(b"]}")
    }
}

/// Runs every command as `unshare -rn <cmd>`.
struct Unshare;

impl Runner for Unshare {
    fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError> {
        let wrapped = Cmd::new("unshare")
            .arg("-rn")
            .arg(cmd.program().as_os_str())
            .args(cmd.get_args());
        SystemRunner.run(&wrapped, stdin)
    }
    fn has_program(&self, p: &str) -> bool {
        SystemRunner.has_program(p)
    }
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![50, 1000, 10_000]
    } else {
        sizes
    };
    for n in sizes {
        for _ in 0..3 {
            let rs = Synthetic(n);
            let t = std::time::Instant::now();
            let (_, bytes) = nft::digest(&rs).expect("digest");
            let digest_ms = t.elapsed().as_secs_f64() * 1e3;
            match nft::apply(&Unshare, &rs) {
                Ok(r) => println!(
                    "{{\"rules\":{n},\"bytes\":{bytes},\"digest_ms\":{digest_ms:.2},\"check_ms\":{:.2},\"load_ms\":{:.2},\"peak_rss_kib\":{}}}",
                    r.check.as_secs_f64() * 1e3,
                    r.load.as_secs_f64() * 1e3,
                    peak_rss_kib()
                ),
                Err(e) => {
                    eprintln!("{n} rules: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
