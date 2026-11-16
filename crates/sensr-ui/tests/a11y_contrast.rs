//! WCAG AA contrast for every text/background token pair in both themes.

use sensr_ui::theme::{DARK, LIGHT, token};

fn luminance(hex: &str) -> f64 {
    let hex = hex.trim_start_matches('#');
    assert_eq!(hex.len(), 6, "colour tokens must be #rrggbb, got {hex}");
    let ch = |i: usize| {
        let c = f64::from(u8::from_str_radix(&hex[i..i + 2], 16).unwrap()) / 255.0;
        if c <= 0.039_28 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * ch(0) + 0.7152 * ch(2) + 0.0722 * ch(4)
}

fn ratio(a: &str, b: &str) -> f64 {
    let (x, y) = (luminance(a), luminance(b));
    (x.max(y) + 0.05) / (x.min(y) + 0.05)
}

/// (foreground, background, minimum ratio).
const PAIRS: &[(&str, &str, f64)] = &[
    ("fg", "bg", 4.5),
    ("fg", "card", 4.5),
    ("muted", "bg", 4.5),
    ("muted", "card", 4.5),
    ("topbar-fg", "topbar", 4.5),
    ("side-fg", "side", 4.5),
    ("side-muted", "side", 4.5),
    ("side-fg", "side-hover", 4.5),
    ("side-active-fg", "side-active", 4.5),
    ("accent-fg", "accent", 4.5),
    ("link", "card", 4.5),
    ("link", "bg", 4.5),
    ("input-fg", "input", 4.5),
    ("ok", "ok-bg", 4.5),
    ("bad", "bad-bg", 4.5),
    ("bad", "card", 4.5),
    ("warn", "warn-bg", 4.5),
    ("info", "info-bg", 4.5),
    ("diff-add", "diff-add-bg", 4.5),
    ("diff-del", "diff-del-bg", 4.5),
    ("fg", "accent-soft", 4.5),
    // Non-text UI components (WCAG 1.4.11): 3:1.
    ("input-line", "input", 3.0),
    ("focus", "card", 3.0),
    ("focus", "bg", 3.0),
    ("spark-rx", "bg", 3.0),
    ("spark-tx", "bg", 3.0),
];

fn check(name: &str, theme: &[(&'static str, &'static str)]) {
    let mut failures = Vec::new();
    for (fg, bg, min) in PAIRS {
        let (f, b) = (token(theme, fg).unwrap(), token(theme, bg).unwrap());
        let r = ratio(f, b);
        if r < *min {
            failures.push(format!(
                "{name}: --{fg} on --{bg} is {r:.2}:1, needs {min}:1"
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn light_theme_meets_wcag_aa() {
    check("light", LIGHT);
}

#[test]
fn dark_theme_meets_wcag_aa() {
    check("dark", DARK);
}

#[test]
fn both_themes_define_the_same_tokens() {
    let mut a: Vec<_> = LIGHT.iter().map(|(k, _)| *k).collect();
    let mut b: Vec<_> = DARK.iter().map(|(k, _)| *k).collect();
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b);
}

#[test]
fn css_uses_only_defined_tokens() {
    let css = sensr_ui::theme::tokens_css();
    assert!(css.contains(":root[data-theme=dark]") && css.contains("prefers-color-scheme:dark"));
}
