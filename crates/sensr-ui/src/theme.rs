//! Design tokens for the light and dark themes.
//!
//! Defined here rather than in CSS so the contrast test (tests/a11y_contrast.rs) checks the
//! exact values the browser gets; the shell inlines [`tokens_css`] in `<head>`, and
//! `style/main.css` only references the variables.

/// Light theme (default).
pub const LIGHT: &[(&str, &str)] = &[
    ("bg", "#f4f5f5"),
    ("fg", "#1c2121"),
    ("muted", "#566161"),
    ("card", "#ffffff"),
    ("line", "#dde2e2"),
    ("line-strong", "#b9c2c2"),
    ("topbar", "#ffffff"),
    ("topbar-fg", "#1c2121"),
    ("side", "#2b2f2f"),
    ("side-fg", "#e3e8e8"),
    ("side-muted", "#a9b4b4"),
    ("side-hover", "#383d3d"),
    ("side-active", "#b7410e"),
    ("side-active-fg", "#ffffff"),
    ("accent", "#b7410e"),
    ("accent-fg", "#ffffff"),
    ("accent-soft", "#fbe9e1"),
    ("link", "#9a360b"),
    ("focus", "#1d64d8"),
    ("input", "#ffffff"),
    ("input-fg", "#1c2121"),
    ("input-line", "#7d8888"),
    ("ok", "#166534"),
    ("ok-bg", "#dcfce7"),
    ("bad", "#9f1239"),
    ("bad-bg", "#ffe4e6"),
    ("warn", "#7c4a03"),
    ("warn-bg", "#fef3c7"),
    ("info", "#1e3a8a"),
    ("info-bg", "#e0eaff"),
    ("diff-add", "#14532d"),
    ("diff-add-bg", "#dcfce7"),
    ("diff-del", "#881337"),
    ("diff-del-bg", "#ffe4e6"),
    ("spark-rx", "#15803d"),
    ("spark-tx", "#b7410e"),
    ("logo-s", "#15803d"),
    ("logo-ens", "#e0a800"),
    ("logo-r", "#b7410e"),
    (
        "shadow",
        "0 1px 2px rgb(0 0 0 / 6%), 0 1px 1px rgb(0 0 0 / 4%)",
    ),
];

/// Dark theme: `data-theme="dark"`, or the OS preference when the user chose nothing.
pub const DARK: &[(&str, &str)] = &[
    ("bg", "#0d1212"),
    ("fg", "#e6eded"),
    ("muted", "#9fb0b0"),
    ("card", "#151c1c"),
    ("line", "#263232"),
    ("line-strong", "#3b4a4a"),
    ("topbar", "#151c1c"),
    ("topbar-fg", "#e6eded"),
    ("side", "#0a0e0e"),
    ("side-fg", "#dfe7e7"),
    ("side-muted", "#93a3a3"),
    ("side-hover", "#1b2424"),
    ("side-active", "#e2622f"),
    ("side-active-fg", "#160803"),
    ("accent", "#e2622f"),
    ("accent-fg", "#160803"),
    ("accent-soft", "#3a1a0c"),
    ("link", "#f08a5d"),
    ("focus", "#7fb0ff"),
    ("input", "#0f1515"),
    ("input-fg", "#e6eded"),
    ("input-line", "#5c6e6e"),
    ("ok", "#86efac"),
    ("ok-bg", "#0f3d22"),
    ("bad", "#fda4af"),
    ("bad-bg", "#4c0519"),
    ("warn", "#fcd34d"),
    ("warn-bg", "#3a2a06"),
    ("info", "#bfd3ff"),
    ("info-bg", "#142449"),
    ("diff-add", "#bbf7d0"),
    ("diff-add-bg", "#0f3d22"),
    ("diff-del", "#fecdd3"),
    ("diff-del-bg", "#4c0519"),
    ("spark-rx", "#4ade80"),
    ("spark-tx", "#e2622f"),
    ("logo-s", "#4ade80"),
    ("logo-ens", "#facc15"),
    ("logo-r", "#e2622f"),
    ("shadow", "0 1px 2px rgb(0 0 0 / 40%)"),
];

fn decls(tokens: &[(&str, &str)]) -> String {
    tokens.iter().map(|(k, v)| format!("--{k}:{v};")).collect()
}

/// The `:root` custom properties for both themes.
pub fn tokens_css() -> String {
    let (light, dark) = (decls(LIGHT), decls(DARK));
    format!(
        ":root{{{light}color-scheme:light}}\
         :root[data-theme=dark]{{{dark}color-scheme:dark}}\
         @media (prefers-color-scheme:dark){{:root:not([data-theme]){{{dark}color-scheme:dark}}}}"
    )
}

/// Looks up a token.
pub fn token(theme: &[(&'static str, &'static str)], name: &str) -> Option<&'static str> {
    theme.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}
