//! Template modules: sensr's `service/templates/OPNsense/<Module>/` + `+TARGETS`.
//!
//! A [`Module`] is a set of minijinja templates and a `Targets` table mapping
//! each template to a file in the module's live directory (normally
//! `/run/sensr/<daemon>/`, or e.g. `/run/systemd/network/` for networkd).
//! Rendering goes to `<live dir>/.next/` first so the daemon's own
//! checker can validate the complete new set; [`Staged::commit`] then renames
//! every file into place (each rename is atomic, the directory is the same
//! filesystem).
//!
//! Unlike upstream, templates see a typed, serialised context rather than the
//! raw `config.xml` tree, and undefined variables are errors, not empty
//! strings, so a template typo fails the apply instead of writing a broken
//! file.
//!
//! A target may produce one file per list item, like upstream's
//! `wg[OPNsense.wireguard.server.servers.server.%.instance].conf`:
//! `netdev:50-[wireguard.interfaces.%.name].netdev` renders the template once
//! per element of `wireguard.interfaces`, with that element bound to `item`.

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
    /// Live directory, relative to the root (`"run/sensr/unbound"`).
    pub dir: &'static str,
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
    /// Destination relative to the live directory (for a per-item target,
    /// the text around the placeholder).
    pub dest: PathBuf,
    /// Per-item expansion, if the destination has a `[list.%.field]` part.
    pub each: Option<Each>,
}

/// Per-item expansion of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Each {
    /// Dotted path of the list in the context.
    pub list: Vec<String>,
    /// Field of each item that names the file.
    pub field: String,
    /// File name text before the placeholder.
    pub prefix: String,
    /// File name text after the placeholder.
    pub suffix: String,
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
    /// A per-item target's list or name field is missing or unusable.
    #[error("module {module} template {template}: {why}")]
    BadItem {
        /// Module.
        module: &'static str,
        /// Template.
        template: String,
        /// Explanation.
        why: String,
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
        let dest = dest.trim();
        if dest.is_empty() || tpl.trim().is_empty() {
            return Err(bad("empty template or destination"));
        }
        let (dest, each) = match (dest.find('['), dest.find(']')) {
            (None, None) => (PathBuf::from(dest), None),
            (Some(a), Some(b)) if a < b => {
                let spec = &dest[a + 1..b];
                let (list, field) = spec
                    .split_once(".%.")
                    .ok_or_else(|| bad("placeholder must be [list.path.%.field]"))?;
                let (dir, prefix) = match dest[..a].rsplit_once('/') {
                    Some((d, p)) => (format!("{d}/"), p.to_owned()),
                    None => (String::new(), dest[..a].to_owned()),
                };
                let suffix = dest[b + 1..].to_owned();
                if suffix.contains('/') || list.is_empty() || field.is_empty() {
                    return Err(bad("placeholder must be in the file name"));
                }
                (
                    PathBuf::from(if dir.is_empty() { ".".to_owned() } else { dir }),
                    Some(Each {
                        list: list.split('.').map(str::to_owned).collect(),
                        field: field.to_owned(),
                        prefix,
                        suffix,
                    }),
                )
            }
            _ => return Err(bad("unbalanced [ ] in destination")),
        };
        if !dest
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        {
            return Err(bad("destination must be relative without .."));
        }
        out.push(Target {
            template: tpl.trim().to_owned(),
            dest,
            each,
        });
    }
    Ok(out)
}

/// A rendered file, not yet written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// Live directory relative to the root.
    pub dir: &'static str,
    /// Destination relative to the live directory.
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
        let doc = serde_json::to_value(ctx).map_err(|e| TemplateError::BadItem {
            module: m.name,
            template: String::new(),
            why: format!("context does not serialise: {e}"),
        })?;
        let value = Value::from(Serde(&doc));
        let mut out = Vec::new();
        for t in targets {
            let err = |source| TemplateError::Render {
                module: m.name,
                template: t.template.clone(),
                source,
            };
            let tpl = self
                .env
                .get_template(&format!("{}/{}", m.name, t.template))
                .map_err(err)?;
            let Some(each) = &t.each else {
                out.push(Rendered {
                    dir: m.dir,
                    dest: t.dest.clone(),
                    contents: tpl.render(value.clone()).map_err(err)?,
                });
                continue;
            };
            let bad = |why: String| TemplateError::BadItem {
                module: m.name,
                template: t.template.clone(),
                why,
            };
            // A missing list means "no items" (the feature is off), as upstream.
            let items = each
                .list
                .iter()
                .try_fold(&doc, |v, k| v.get(k))
                .and_then(|v| v.as_array())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            for item in items {
                let name = match item.get(&each.field) {
                    Some(serde_json::Value::String(s)) => s.clone(),
                    Some(serde_json::Value::Number(n)) => n.to_string(),
                    _ => return Err(bad(format!("item without {}", each.field))),
                };
                let file = format!("{}{name}{}", each.prefix, each.suffix);
                if file.is_empty()
                    || file == "."
                    || file == ".."
                    || file.contains('/')
                    || file.chars().any(char::is_control)
                {
                    return Err(bad(format!("unusable file name {file:?}")));
                }
                let mut scoped = doc.clone();
                if let Some(obj) = scoped.as_object_mut() {
                    obj.insert("item".to_owned(), item.clone());
                }
                out.push(Rendered {
                    dir: m.dir,
                    dest: t.dest.join(file),
                    contents: tpl.render(Value::from(Serde(&scoped))).map_err(err)?,
                });
            }
        }
        Ok(out)
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

    /// A module's live directory (`<root>/<dir>`).
    pub fn live_dir(&self, dir: &str) -> PathBuf {
        self.root.join(dir)
    }

    /// Its staging directory (`<root>/<dir>/.next`).
    pub fn next_dir(&self, dir: &str) -> PathBuf {
        self.live_dir(dir).join(".next")
    }

    /// The live path of a rendered file.
    pub fn live_path(&self, r: &Rendered) -> PathBuf {
        normalize(&self.live_dir(r.dir).join(&r.dest))
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
            let next = normalize(&self.next_dir(r.dir).join(&r.dest));
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

/// Drop `.` components so plan keys are canonical.
fn normalize(p: &Path) -> PathBuf {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .collect()
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
    dir: "run/sensr/sample",
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
    vec![
        SAMPLE,
        crate::appliers::unbound::MODULE,
        crate::appliers::wireguard::MODULE,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared fixture document plus the typed slice models' contexts,
    /// so every module renders from one document as upstream's
    /// `generate('*')` does.
    fn fixture() -> serde_json::Value {
        let mut doc: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/full.json")).unwrap();
        let obj = doc.as_object_mut().unwrap();
        let unbound =
            serde_json::to_value(crate::appliers::unbound::tests::model().context().unwrap())
                .unwrap();
        let wg = crate::appliers::wireguard::tests::model();
        let wg = serde_json::to_value(wg.context().unwrap()).unwrap();
        for part in [unbound, wg] {
            for (k, v) in part.as_object().unwrap() {
                obj.insert(k.clone(), v.clone());
            }
        }
        doc
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
                let expected: Vec<PathBuf> = match &target.each {
                    None => vec![staging.live_dir(module.dir).join(&target.dest)],
                    Some(each) => {
                        let doc = fixture();
                        let items = each
                            .list
                            .iter()
                            .try_fold(&doc, |v, k| v.get(k))
                            .and_then(|v| v.as_array())
                            .cloned()
                            .unwrap_or_default();
                        assert!(!items.is_empty(), "{name}: fixture has no {:?}", each.list);
                        items
                            .iter()
                            .map(|i| {
                                let n = i[&each.field].as_str().unwrap();
                                normalize(
                                    &staging
                                        .live_dir(module.dir)
                                        .join(&target.dest)
                                        .join(format!("{}{n}{}", each.prefix, each.suffix)),
                                )
                            })
                            .collect()
                    }
                };
                for p in expected {
                    assert!(live.contains(&p), "{name}: {} not rendered", p.display());
                    assert!(p.is_file());
                }
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
        let live = staging.live_dir("run/sensr/sample").join("sample.conf");
        assert!(!live.exists(), "not live before commit");
        assert!(
            staging
                .next_dir("run/sensr/sample")
                .join("sample.conf")
                .is_file()
        );
        staged.commit().unwrap();
        assert!(live.is_file());
        assert!(
            !staging
                .next_dir("run/sensr/sample")
                .join("sample.conf")
                .exists()
        );
    }

    #[test]
    fn undefined_variables_are_errors() {
        let mut t = Templates::empty();
        t.register(Module {
            name: "typo",
            dir: "run/sensr/typo",
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
        let each = parse_targets("m", "a:sub/50-[w.ifs.%.name].netdev").unwrap();
        assert_eq!(each[0].dest, PathBuf::from("sub/"));
        assert_eq!(
            each[0].each,
            Some(Each {
                list: vec!["w".into(), "ifs".into()],
                field: "name".into(),
                prefix: "50-".into(),
                suffix: ".netdev".into(),
            })
        );
        for bad in ["a:x[w.%.n]/y", "a:x[w.n]", "a:x]w.%.n[", "a:[.%.n]"] {
            assert!(parse_targets("m", bad).is_err(), "{bad}");
        }
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
            dir: "run/sensr/m",
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

#[cfg(test)]
mod each_tests {
    use super::*;

    #[test]
    fn per_item_targets_render_one_file_per_item_and_reject_bad_names() {
        let mut t = Templates::empty();
        t.register(Module {
            name: "m",
            dir: "run/sensr/m",
            templates: &[("x", "{{ item.name }}={{ top }}\n")],
            targets: "x:[things.%.name].conf",
        })
        .unwrap();
        let ctx = serde_json::json!({"top": 1, "things": [{"name": "a"}, {"name": "b"}]});
        let out = t.render("m", &ctx).unwrap();
        let s = Staging::new("/");
        let paths: Vec<_> = out.iter().map(|r| s.live_path(r)).collect();
        assert_eq!(
            paths,
            [
                PathBuf::from("/run/sensr/m/a.conf"),
                PathBuf::from("/run/sensr/m/b.conf")
            ]
        );
        assert_eq!(out[1].contents, "b=1\n");
        assert!(
            t.render("m", &serde_json::json!({"top": 1}))
                .unwrap()
                .is_empty()
        );
        let evil = serde_json::json!({"top": 1, "things": [{"name": "../../etc/x"}]});
        assert!(matches!(
            t.render("m", &evil),
            Err(TemplateError::BadItem { .. })
        ));
    }
}
