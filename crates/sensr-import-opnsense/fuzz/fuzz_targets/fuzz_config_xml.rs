#![no_main]
//! Arbitrary bytes must never panic the loader or the importer; anything the
//! loader accepts must be written back to a form that re-parses to the same output
//! (writer idempotence), and its import must export to XML that imports again.

use libfuzzer_sys::fuzz_target;
use sensr_import_opnsense::opnsense::{ImportOptions, export_config, import_document};
use sensr_import_opnsense::{parse, parse_bytes, to_config_string};

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = parse_bytes(data) {
        let once = to_config_string(&doc);
        let again = to_config_string(&parse(&once).expect("writer output parses"));
        assert_eq!(once, again);
        let imported = import_document(&doc, &ImportOptions::default());
        let exported = export_config(&imported.document);
        parse(&exported).expect("export parses");
    }
});
