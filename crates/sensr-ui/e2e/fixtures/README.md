`agent-seed.json` seeds `sensr-agent` for the browser tests against the real stack: the mock
backend's document (`sensr_ui::mock::seed()`) plus a `root` user whose password is `sensr`
(test-only credentials). `tests/fixtures.rs` keeps it in sync with the mock.
