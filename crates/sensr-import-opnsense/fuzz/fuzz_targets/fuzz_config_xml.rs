#![no_main]
//! Arbitrary bytes must never panic the loader, and anything it accepts must be
//! written back to a form that re-parses to the same output (writer idempotence).

use libfuzzer_sys::fuzz_target;
use sensr_import_opnsense::{parse_bytes, to_config_string};

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = parse_bytes(data) {
        let once = to_config_string(&doc);
        let again =
            to_config_string(&sensr_import_opnsense::parse(&once).expect("writer output parses"));
        assert_eq!(once, again);
    }
});
