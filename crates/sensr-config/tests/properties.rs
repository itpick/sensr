//! Store properties (03 §4.8) and the fixture/corpus gates (T-0382, T-0383).

use proptest::prelude::*;
use sensr_config::{CommitMeta, RevisionId, Store, StoreOptions};
use sensr_schema::{Document, migrate};

#[derive(Debug, Clone)]
enum Op {
    Commit(u8),
    Restore(usize),
    Same,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..6).prop_map(Op::Commit),
        (0usize..64).prop_map(Op::Restore),
        Just(Op::Same),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// History never loses a revision, ids are dense and increasing, every
    /// stored revision reads back, and restores never rewrite.
    #[test]
    fn prop_history_never_loses_a_revision(ops in proptest::collection::vec(op(), 1..24)) {
        let store = Store::open_in_memory(Document::factory, StoreOptions::default()).unwrap();
        let mut expected: Vec<Document> = vec![Document::factory()];
        for o in ops {
            let head = store.head().unwrap().document;
            match o {
                Op::Commit(n) => {
                    let mut d = head.clone();
                    d.system.hostname = format!("h{n}").parse().unwrap();
                    if d != head {
                        store.commit(&d, CommitMeta::new("p", "c")).unwrap();
                        expected.push(d);
                    }
                }
                Op::Restore(k) => {
                    let k = k % expected.len();
                    store.restore(RevisionId(i64::try_from(k).unwrap() + 1), CommitMeta::new("p", "r")).unwrap();
                    expected.push(expected[k].clone());
                }
                Op::Same => {
                    store.commit(&head, CommitMeta::new("p", "same")).unwrap();
                }
            }
        }
        let hist = store.history(1000, None).unwrap();
        prop_assert_eq!(hist.len(), expected.len());
        for (i, doc) in expected.iter().enumerate() {
            let id = RevisionId(i64::try_from(i).unwrap() + 1);
            prop_assert_eq!(&store.get(id).unwrap().document, doc);
        }
    }
}

fn fixture_documents() -> Vec<(String, serde_json::Value)> {
    let dirs = [
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sensr-schema/tests/fixtures"
        ),
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/versions"),
    ];
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "json") {
                let v = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
                out.push((p.display().to_string(), v));
            }
        }
    }
    assert!(!out.is_empty(), "no fixtures found");
    out
}

/// `make validate` equivalent: every fixture document validates at head.
#[test]
fn every_fixture_validates_t0382() {
    for (name, mut v) in fixture_documents() {
        migrate::to_head(&mut v).unwrap_or_else(|e| panic!("{name}: {e}"));
        let doc: Document = serde_json::from_value(v).unwrap_or_else(|e| panic!("{name}: {e}"));
        let errs = doc.validate();
        assert!(errs.is_ok(), "{name}:\n{errs}");
    }
}

/// `make migrate` equivalent: every historical document reaches head, and
/// migrating again is a no-op.
#[test]
fn corpus_migrates_to_head_t0383() {
    for (name, mut v) in fixture_documents() {
        migrate::to_head(&mut v).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            migrate::version_of(&v).unwrap(),
            sensr_schema::SCHEMA_VERSION,
            "{name}"
        );
        let again = v.clone();
        assert!(migrate::to_head(&mut v).unwrap().is_empty(), "{name}");
        assert_eq!(v, again);
    }
}
