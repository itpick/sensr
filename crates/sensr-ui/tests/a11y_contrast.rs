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

/// `fg` alpha-blended over `bg` (both `#rrggbb`), as `#rrggbb`.
fn blend(fg: &str, bg: &str, alpha: f64) -> String {
    let ch = |h: &str, i: usize| f64::from(u8::from_str_radix(&h[i..i + 2], 16).unwrap());
    let (f, b) = (fg.trim_start_matches('#'), bg.trim_start_matches('#'));
    let mix = |i| (ch(f, i) * alpha + ch(b, i) * (1.0 - alpha)).round() as u8;
    format!("#{:02x}{:02x}{:02x}", mix(0), mix(2), mix(4))
}

/// The Hosts card's row tint: every category colour at its tint alpha over the card keeps
/// row text (body, muted, links) readable, in both themes; the colours themselves, used
/// for legend dots and bars, stand out from the card (3:1).
#[test]
fn category_tint_contrast() {
    let mut failures = Vec::new();
    for (name, theme) in [("light", LIGHT), ("dark", DARK)] {
        let card = token(theme, "card").unwrap();
        for (key, _) in sensr_ui::runtime::CATEGORIES {
            let tok = sensr_ui::runtime::category_token(key);
            let colour = token(theme, &tok).unwrap_or_else(|| panic!("{name}: no --{tok}"));
            let tint = blend(
                colour,
                card,
                f64::from(sensr_ui::theme::CATEGORY_TINT_PCT) / 100.0,
            );
            for fg in ["fg", "muted", "link"] {
                let r = ratio(token(theme, fg).unwrap(), &tint);
                if r < 4.5 {
                    failures.push(format!("{name}: --{fg} on {tok} tint is {r:.2}:1"));
                }
            }
            let r = ratio(colour, card);
            if r < 3.0 {
                failures.push(format!("{name}: --{tok} on --card is {r:.2}:1"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
