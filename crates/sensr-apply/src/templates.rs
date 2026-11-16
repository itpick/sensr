//! Template modules: sensr's `service/templates/OPNsense/<Module>/` + `+TARGETS`.
//!
//! A [`Module`] is a set of minijinja templates and a `Targets` table mapping
//! each template to a file in the daemon's directory under `/run/sensr/<daemon>/`.
//! Rendering goes to `/run/sensr/<daemon>/.next/` first so the daemon's own
//! checker can validate the complete new set; [`Staged::commit`] then renames
//! every file into place (each rename is atomic, the directory is the same
//! filesystem).
//!
//! Unlike upstream, templates see a typed, serialised context rather than the
//! raw `config.xml` tree, and undefined variables are errors, not empty
//! strings, so a template typo fails the apply instead of writing a broken
//! file.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use minijinja::value::{Serde, Value};
use minijinja::{Environment, UndefinedBehavior};
use serde::Serialize;

use crate::plan::FileSpec;

/// A template module.
#[derive(Debug, Clone)]
pub struct Module {
    /// Module name (`"sample"`, `"unbound"`).
    pub name: &'static str,
    /// Daemon directory under `/run/sensr/`.
    pub daemon: &'static str,
    /// Template name → source.
    pub templates: &'static [(&'static str, &'static str)],
    /// `+TARGETS`-style table: `template:relative/destination` per line.
    pub targets: &'static str,
}

/// One target line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Template name within the module.
    pub template: String,
    /// Destination relative to the daemon directory.
    pub dest: PathBuf,
}

/// Template errors.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// A `Targets` line is malformed.
    #[error("module {module}: bad target line {line:?}: {why}")]
    BadTarget {
        /// Module.
        module: &'static str,
        /// The offending line.
        line: String,
        /// Explanation.
        why: &'static str,
    },
    /// A module name is not registered.
    #[error("unknown template module {0:?}")]
    UnknownModule(String),
    /// A module was registered twice.
    #[error("template module {0:?} registered twice")]
    Duplicate(&'static str),
    /// minijinja failed to parse or render.
    #[error("module {module} template {template}: {source}")]
    Render {
        /// Module.
        module: &'static str,
        /// Template.
        template: String,
        /// Underlying error (with line information).
        source: minijinja::Error,
    },
    /// Filesystem error while staging or committing.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The OS error.
        source: std::io::Error,
    },
}

/// Parse a `Targets` table. Blank lines and `#` comments are ignored;
/// destinations must be relative and may not climb out of the daemon dir.
pub fn parse_targets(module: &'static str, text: &str) -> Result<Vec<Target>, TemplateError> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bad = |why| TemplateError::BadTarget {
            module,
            line: line.to_owned(),
            why,
        };
        let (tpl, dest) = line
            .split_once(':')
            .ok_or_else(|| bad("expected template:dest"))?;
        let dest = PathBuf::from(dest.trim());
        if dest.as_os_str().is_empty() || tpl.trim().is_empty() {
            return Err(bad("empty template or destination"));
        }
        if !dest.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(bad("destination must be relative without .."));
        }
        out.push(Target {
            template: tpl.trim().to_owned(),
            dest,
        });
    }
    Ok(out)
}

/// A rendered file, not yet written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Daemon directory name.
    pub daemon: &'static str,
    /// Destination relative to the daemon directory.
    pub dest: PathBuf,
    /// Contents.
    pub contents: String,
}

/// The template registry.
pub struct Templates {
    env: Environment<'static>,
    modules: BTreeMap<&'static str, (Module, Vec<Target>)>,
}

impl std::fmt::Debug for Templates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Templates")
            .field("modules", &self.modules.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Templates {
    /// An empty registry with sensr's template settings.
    pub fn empty() -> Self {
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        // Config files are line-oriented: block tags on their own line should
        // not leave blank lines behind.
        if let Ok(syntax) = minijinja::syntax::SyntaxConfig::builder()
            .trim_blocks(true)
            .lstrip_blocks(true)
            .keep_trailing_newline(true)
            .build()
        {
            env.set_syntax(syntax);
        }
        Templates {
            env,
            modules: BTreeMap::new(),
        }
    }

    /// The registry with every module sensr ships.
    pub fn builtin() -> Result<Self, TemplateError> {
        let mut t = Self::empty();
        for m in builtin_modules() {
            t.register(m)?;
        }
        Ok(t)
    }

    /// Add a module (its templates are parsed now, so syntax errors surface
    /// at startup rather than at the first apply).
    pub fn register(&mut self, module: Module) -> Result<(), TemplateError> {
        if self.modules.contains_key(module.name) {
            return Err(TemplateError::Duplicate(module.name));
        }
        let targets = parse_targets(module.name, module.targets)?;
        for (name, src) in module.templates {
            self.env
                .add_template_owned(format!("{}/{}", module.name, name), *src)
                .map_err(|source| TemplateError::Render {
                    module: module.name,
                    template: (*name).to_owned(),
                    source,
                })?;
        }
        for t in &targets {
            if !module.templates.iter().any(|(n, _)| *n == t.template) {
                return Err(TemplateError::BadTarget {
                    module: module.name,
                    line: t.template.clone(),
                    why: "target names a template the module does not have",
                });
            }
        }
        self.modules.insert(module.name, (module, targets));
        Ok(())
    }

    /// Registered module names.
    pub fn module_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.modules.keys().copied()
    }

    /// The targets of a module.
    pub fn targets(&self, module: &str) -> Result<&[Target], TemplateError> {
        self.modules
            .get(module)
            .map(|(_, t)| t.as_slice())
            .ok_or_else(|| TemplateError::UnknownModule(module.to_owned()))
    }

    /// Render one module against `ctx`.
    pub fn render(
        &self,
        module: &str,
        ctx: &impl Serialize,
    ) -> Result<Vec<Rendered>, TemplateError> {
        let (m, targets) = self
            .modules
            .get(module)
            .ok_or_else(|| TemplateError::UnknownModule(module.to_owned()))?;
        let value = Value::from(Serde(ctx));
        targets
            .iter()
            .map(|t| {
                let err = |source| TemplateError::Render {
                    module: m.name,
                    template: t.template.clone(),
                    source,
                };
                let tpl = self
                    .env
                    .get_template(&format!("{}/{}", m.name, t.template))
                    .map_err(err)?;
                Ok(Rendered {
                    daemon: m.daemon,
                    dest: t.dest.clone(),
                    contents: tpl.render(value.clone()).map_err(err)?,
                })
            })
            .collect()
    }

    /// Render every module (upstream `generate('*')`).
    pub fn render_all(&self, ctx: &impl Serialize) -> Result<Vec<Rendered>, TemplateError> {
        let mut out = Vec::new();
        for name in self.modules.keys() {
            out.extend(self.render(name, ctx)?);
        }
        Ok(out)
    }
}

/// Where rendered files go, below an injectable root (`/` in production).
#[derive(Debug, Clone)]
pub struct Staging {
    root: PathBuf,
}

/// A set of files written to `.next/`, ready to be checked and committed.
#[derive(Debug)]
#[must_use = "staged files are not live until committed"]
pub struct Staged {
    /// (staged path, live path) pairs.
    pub files: Vec<(PathBuf, PathBuf)>,
}

impl Staging {
    /// Staging below `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Staging { root: root.into() }
    }

    /// `/run/sensr/<daemon>`.
    pub fn live_dir(&self, daemon: &str) -> PathBuf {
        self.root.join("run/sensr").join(daemon)
    }

    /// `/run/sensr/<daemon>/.next`.
    pub fn next_dir(&self, daemon: &str) -> PathBuf {
        self.live_dir(daemon).join(".next")
    }

    /// The live path of a rendered file.
    pub fn live_path(&self, r: &Rendered) -> PathBuf {
        self.live_dir(r.daemon).join(&r.dest)
    }

    /// Plan entries for rendered files (live paths), for diffing.
    pub fn plan_files(&self, rendered: &[Rendered]) -> BTreeMap<PathBuf, FileSpec> {
        rendered
            .iter()
            .map(|r| {
                (
                    self.live_path(r),
                    FileSpec {
                        contents: r.contents.clone().into_bytes(),
                        mode: 0o644,
                    },
                )
            })
            .collect()
    }

    /// Write rendered files under `.next/` (each via temp file + rename).
    pub fn stage(&self, rendered: &[Rendered]) -> Result<Staged, TemplateError> {
        let mut files = Vec::new();
        for r in rendered {
            let next = self.next_dir(r.daemon).join(&r.dest);
            write_atomic(&next, r.contents.as_bytes(), 0o644)?;
            files.push((next, self.live_path(r)));
        }
        Ok(Staged { files })
    }
}

impl Staged {
    /// Move every staged file into its live place.
    pub fn commit(self) -> Result<Vec<PathBuf>, TemplateError> {
        let mut live = Vec::new();
        for (next, dest) in self.files {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|source| TemplateError::Io {
                    path: parent.to_owned(),
                    source,
                })?;
            }
            std::fs::rename(&next, &dest).map_err(|source| TemplateError::Io {
                path: dest.clone(),
                source,
            })?;
            live.push(dest);
        }
        Ok(live)
    }

    /// Throw the staged files away (checker rejected them).
    pub fn discard(self) {
        for (next, _) in self.files {
            let _ = std::fs::remove_file(next);
        }
    }
}

/// Write `contents` to `path` atomically: temp file in the same directory,
/// fsync, rename. Readers see the old or the new file, never a partial one.
pub fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<(), TemplateError> {
    let io = |source| TemplateError::Io {
        path: path.to_owned(),
        source,
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(io)?;
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{file_name}.tmp{}", std::process::id()));
    {
        let mut f = std::fs::File::create(&tmp).map_err(io)?;
        f.write_all(contents).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    set_mode(&tmp, mode).map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// The demonstration module (upstream's test references a `Sample` module it
/// no longer ships; sensr keeps one so the template machinery stays tested).
pub const SAMPLE: Module = Module {
    name: "sample",
    daemon: "sample",
    templates: &[
        (
            "sample.conf",
            include_str!("../templates/sample/sample.conf"),
        ),
        (
            "sample.json",
            include_str!("../templates/sample/sample.json"),
        ),
        ("hosts", include_str!("../templates/sample/hosts")),
        ("motd", include_str!("../templates/sample/motd")),
    ],
    targets: include_str!("../templates/sample/TARGETS"),
};

/// Every module sensr ships.
pub fn builtin_modules() -> Vec<Module> {
    vec![SAMPLE]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/full.json")).unwrap()
    }

    #[test]
    fn sample_module_renders_four_targets_t0322() {
        let t = Templates::builtin().unwrap();
        let out = t.render("sample", &fixture()).unwrap();
        assert_eq!(out.len(), 4);
        for r in &out {
            insta::assert_snapshot!(format!("sample__{}", r.dest.display()), r.contents);
        }
    }

    #[test]
    fn all_targets_rendered_t0323() {
        let t = Templates::builtin().unwrap();
        let root = tempfile::tempdir().unwrap();
        let staging = Staging::new(root.path());
        let rendered = t.render_all(&fixture()).unwrap();
        let staged = staging.stage(&rendered).unwrap();
        let live = staged.commit().unwrap();
        for name in t.module_names().collect::<Vec<_>>() {
            let module = t.modules[name].0.clone();
            for target in t.targets(name).unwrap() {
                let p = staging.live_dir(module.daemon).join(&target.dest);
                assert!(live.contains(&p), "{name}: {} not rendered", p.display());
                assert!(p.is_file());
            }
        }
    }

    #[test]
    fn staging_then_commit_swaps_files() {
        let t = Templates::builtin().unwrap();
        let root = tempfile::tempdir().unwrap();
        let staging = Staging::new(root.path());
        let r = t.render("sample", &fixture()).unwrap();
        let staged = staging.stage(&r).unwrap();
        let live = staging.live_dir("sample").join("sample.conf");
        assert!(!live.exists(), "not live before commit");
        assert!(staging.next_dir("sample").join("sample.conf").is_file());
        staged.commit().unwrap();
        assert!(live.is_file());
        assert!(!staging.next_dir("sample").join("sample.conf").exists());
    }

    #[test]
    fn undefined_variables_are_errors() {
        let mut t = Templates::empty();
        t.register(Module {
            name: "typo",
            daemon: "typo",
            templates: &[("a", "{{ system.hostnme }}")],
            targets: "a:a.conf",
        })
        .unwrap();
        assert!(matches!(
            t.render("typo", &fixture()),
            Err(TemplateError::Render { .. })
        ));
    }

    #[test]
    fn targets_must_stay_inside_daemon_dir() {
        for bad in ["a:/etc/passwd", "a:../x", "a", "a:", ":x"] {
            assert!(parse_targets("m", bad).is_err(), "{bad}");
        }
        let ok = parse_targets("m", "# comment\n\na: sub/dir/file.conf\n").unwrap();
        assert_eq!(ok[0].dest, PathBuf::from("sub/dir/file.conf"));
    }

    #[test]
    fn unknown_module_and_dangling_target() {
        let t = Templates::builtin().unwrap();
        assert!(matches!(
            t.render("nope", &fixture()),
            Err(TemplateError::UnknownModule(_))
        ));
        let mut t = Templates::empty();
        let r = t.register(Module {
            name: "m",
            daemon: "m",
            templates: &[],
            targets: "missing:x",
        });
        assert!(matches!(r, Err(TemplateError::BadTarget { .. })));
    }

    #[test]
    fn plan_files_use_live_paths() {
        let t = Templates::builtin().unwrap();
        let s = Staging::new("/");
        let files = s.plan_files(&t.render("sample", &fixture()).unwrap());
        assert!(files.contains_key(Path::new("/run/sensr/sample/sample.conf")));
    }
}
