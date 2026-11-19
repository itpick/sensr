# Working on sensr (brief for implementation agents)

- Repo: ~/workspace/itpick/sensr (GitHub itpick/sensr). Work in your OWN git worktree:
  `git -C ~/workspace/itpick/sensr fetch -q && git -C ~/workspace/itpick/sensr worktree add ~/workspace/itpick/sensr-wt/<branch> -b <branch> origin/main`
  Never edit the main checkout; never push to main. Push your branch and open a PR with `gh pr create` (no Claude/AI attribution lines in commits or PR bodies).
- Toolchain: `export PATH=$HOME/.cargo/bin:$PATH` (rustup, Rust 1.100.0 from rust-toolchain.toml; Homebrew cargo is too old).
- Gates before pushing: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
- Plan: docs/PLAN.md (§2 architecture + crate map, §2.6 source workflow, §4 testing, §8 tasks). Research: docs/research/01..06. Test IDs: docs/research/03-test-parity.md.
- The OPNsense source is the spec: reference/opnsense/{core,plugins,...} in the MAIN checkout (~/workspace/itpick/sensr/reference/opnsense — gitignored, so not in your worktree; read it from there). Read behaviour and tests there; NEVER copy code or translate PHP line by line. Write idiomatic Rust; do it better where Rust allows (types that make invalid states unrepresentable, no stringly-typed fields, no panics on input).
- Tests first. Every test reproducing an OPNsense test carries its ID in the name, lowercase: e.g. `fn port_well_known_names_t0118()`. Upstream fixtures may be copied as test DATA (BSD-2, keep the upstream license header/attribution in a fixtures/README.md), never code.
- Dependencies: only from the `[workspace.dependencies]` table (all latest stable). If you need a crate not there, look up its latest version: `curl -s https://crates.io/api/v1/crates/<name> -H 'User-Agent: sensr (https://github.com/itpick/sensr)'` → `crate.max_stable_version`, add it to the workspace table at that version, and reference it with `.workspace = true`.
- `unsafe_code` is forbidden workspace-wide. Library errors use `thiserror`; binaries may use `anyhow`.
- Comments: explain why, not what; doc comments on public items.
- Testing is all-virtual. A NixOS x86_64 KVM builder is available: `ssh nixtop` (PATH needs /run/current-system/sw/bin). Use /mnt/vms/sensr for checkouts, VM disks and artifacts (root disk is nearly full — do not write large files to ~ there, and do not run nix-collect-garbage or delete anything you didn't create).
- Merge conflicts: other agents work in parallel on other crates. Touch only your crates plus the workspace Cargo.toml dependency table (append; keep alphabetical). Cargo.lock conflicts are resolved by regenerating.
