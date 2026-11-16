//! The agent seed used by the real-stack browser tests stays in sync with the mock document.

#[test]
fn agent_seed_matches_the_mock_document() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/e2e/fixtures/agent-seed.json");
    let Ok(text) = std::fs::read_to_string(path) else {
        // Source trees filtered to Rust files (the Nix build) do not carry the fixture.
        eprintln!("skipping: {path} not present");
        return;
    };
    let mut fixture: serde_json::Value = serde_json::from_str(&text).unwrap();
    let system = fixture["system"].as_object_mut().unwrap();
    assert!(
        system.remove("users").is_some(),
        "the fixture defines the test user"
    );
    system.remove("groups");
    let mut mock = sensr_ui::mock::seed();
    if let Some(s) = mock["system"].as_object_mut() {
        s.remove("users");
        s.remove("groups");
    }
    assert_eq!(
        fixture,
        mock,
        "regenerate e2e/fixtures/agent-seed.json"
    );
}
