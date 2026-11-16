//! Golden-file helpers shared by the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

/// `tests/golden/<name>`
pub fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

/// Compares rendered nft JSON with `tests/golden/<name>.nft.json`: the exact
/// renderer bytes, with a newline after each top-level command so reviews see
/// one command per line. `SENSR_GOLDEN_UPDATE=1` rewrites it.
pub fn golden_json(name: &str, rendered: &[u8]) {
    serde_json::from_slice::<serde_json::Value>(rendered).expect("renderer emits JSON");
    let text = std::str::from_utf8(rendered).expect("utf-8");
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    let mut out = String::with_capacity(text.len() + 1024);
    for c in text.chars() {
        out.push(c);
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 2 => out.push('\n'),
            _ => {}
        }
    }
    out.push('\n');
    golden_text(&format!("{name}.nft.json"), &out);
}

/// Compares text with `tests/golden/<file>`.
pub fn golden_text(file: &str, rendered: &str) {
    let path = golden_path(file);
    if std::env::var_os("SENSR_GOLDEN_UPDATE").is_some() {
        std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
        std::fs::write(&path, rendered).expect("write golden");
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "missing golden {}; run with SENSR_GOLDEN_UPDATE=1",
            path.display()
        )
    });
    pretty_assertions::assert_eq!(rendered, want, "golden {}", path.display());
}
