# Research index

These documents were written against the OPNsense sources pinned in
`reference/REFS` (core `8b88393`, plugins `af4166a`; clones under
`reference/opnsense/<repo>`, recreated by `scripts/fetch-reference.sh`) and the
issue snapshots in `reference/opnsense-issues/{core,plugins}.jsonl`. They are
the index into that source tree; the source itself is the specification. The
plan that assigns everything here to phases is [`../PLAN.md`](../PLAN.md).

| Doc | IDs it defines | Used by PLAN.md for |
|---|---|---|
| [01 Feature inventory](01-feature-inventory.md) | 464 feature IDs (`IF-*`, `FW-*`, …, `ARCH-*`), `OOS-*`, `DEC-*` | §3 scope lists and Appendix A (ID range → phase); per-ID status lives here |
| [02 Architecture](02-architecture.md) | crate map (first cut), compat tiers | §2 reconciled architecture (differences with 06 resolved in §2.1) |
| [03 Test parity](03-test-parity.md) | `T-0001`..`T-0408` | §4 parity gate (`cargo xtask parity`), per-phase test exit criteria |
| [04a Core issues](04a-issues-core.md) | `ISS-C-001`..`040`, 23 bug classes | anti-goals, P0 architecture-gating items, per-phase ISS-C coverage |
| [04b Plugin issues](04b-issues-plugins.md) | `ISS-P-001`..`030`, plugin tiers (core / first-party / community / drop) | PLG-* phase and community-tier assignment, framework rules for `sensr-services` |
| [05 Business features](05-business-features.md) | `BIZ-001`..`032`, BE inventory, licensing stance | Phase 3 and Phase 4 scope, §7 owner questions |
| [06 Rust + NixOS stack](06-rust-nixos-stack.md) | opnsense-pi lessons L1–L14, dependency pins, freshness policy (§5) | §2.1 decisions, §5 pins, §6 images and first-boot contract |

Rules: IDs are never renumbered, only appended. When the upstream pin is
bumped (`scripts/fetch-reference.sh --latest`), new tests become new `T-` rows
in 03, new features new rows in 01, and the "Status" line at the top of each
document records the new commits.

## Data

- `data/core-issue-dispositions.jsonl`: the reviewed sensr disposition for every
  core issue the review triaged (all open, declined and bot-closed issues). `n` is
  the issue number, `type`, `area`, `d` the disposition (`ADOPT`, `DESIGN-AVOIDS`,
  `TEST`, `N/A-LINUX`, ...) and `w` the weight, 0 to 3.
- `data/plugin-issue-classification.jsonl`: the plugin (`p`) and type (`ty`) of
  every opnsense/plugins issue, without bodies.

The analysis scripts that produced 04a/04b are kept locally in
`reference/opnsense-issues/analysis/` (gitignored).
