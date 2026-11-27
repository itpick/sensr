//! The kernel side of the loader (aya).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use aya::maps::lpm_trie::Key;
use aya::maps::{
    Array, HashMap as BpfHash, LpmTrie, MapData, MapError, PerCpuArray, PerCpuValues, RingBuf,
};
use aya::programs::{Program, ProgramError};
use aya::{Btf, Ebpf, EbpfLoader};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use super::{Applied, ProgramStatus, disabled_meta, hits_by_id, plan};
use crate::compile::Compiled;
use crate::maps::{MAX_RULES, PATH_LEN, UNIT_LEN};

/// Why a pack could not be loaded at all.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The pack's files could not be read.
    #[error("{path}: {source}")]
    Read {
        /// The file.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
    /// The manifest is not valid.
    #[error("{path}: {source}")]
    Manifest {
        /// The manifest.
        path: PathBuf,
        /// The error.
        source: crate::packs::PackError,
    },
    /// The pack must have exactly one object (its programs are linked
    /// together so they share their maps).
    #[error("the manifest lists {0} objects; a pack has exactly one")]
    ObjectCount(usize),
    /// The object is not a readable ELF file.
    #[error("{object}: {message}")]
    Object {
        /// The object file name.
        object: String,
        /// What is wrong.
        message: String,
    },
    /// The kernel's BTF (/sys/kernel/btf/vmlinux) could not be read.
    #[error("kernel BTF: {0}")]
    Btf(#[from] aya::BtfError),
    /// Creating the maps or relocating the object failed.
    #[error("{object}: {source}")]
    Ebpf {
        /// The object file name.
        object: String,
        /// The error.
        source: Box<aya::EbpfError>,
    },
    /// A map the contract requires is missing or has the wrong type.
    #[error("map {map}: {message}")]
    Map {
        /// The map.
        map: &'static str,
        /// What is wrong.
        message: String,
    },
    /// The ring buffer was already handed out.
    #[error("the ring buffer was already taken")]
    RingBufTaken,
}

/// Why a map access failed. After a failed apply the maps hold an unknown
/// mix of the old and new rules; the next apply rewrites every slot (and
/// deletes stale keys first wherever old and new would not fit together).
/// The counter reads ([`Loaded::hits`], ...) report their failures with it
/// too.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// A map update or delete failed.
    #[error("map {map}: {source}")]
    Map {
        /// The map.
        map: &'static str,
        /// The error.
        source: MapError,
    },
    /// A key of the wrong length (a bug: the compiler and the contract
    /// disagree).
    #[error("map {map}: key of {len} bytes")]
    KeyLength {
        /// The map.
        map: &'static str,
        /// Its length.
        len: usize,
    },
    /// The map is missing from the object.
    #[error("map {0} is missing")]
    Missing(&'static str),
    /// The number of CPUs could not be read.
    #[error("possible CPUs: {0}")]
    Cpus(String),
}

/// A loaded pack. Dropping it detaches every program and frees the maps.
pub struct Loaded {
    ebpf: Ebpf,
    status: Vec<ProgramStatus>,
    applied: Applied,
    ringbuf: Option<RingBuf<MapData>>,
    cpus: usize,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("status", &self.status)
            .field("applied", &self.applied)
            .finish_non_exhaustive()
    }
}

/// Program (function) name -> section name, for every function in a
/// program section (`lsm/<hook>`, `lsm.s/<hook>`).
fn program_sections(object: &str, bytes: &[u8]) -> Result<BTreeMap<String, String>, LoadError> {
    let bad = |message: String| LoadError::Object {
        object: object.to_string(),
        message,
    };
    let file = object::File::parse(bytes).map_err(|e| bad(e.to_string()))?;
    let mut out = BTreeMap::new();
    for sym in file.symbols() {
        if sym.kind() != SymbolKind::Text || !sym.is_global() {
            continue;
        }
        let Some(index) = sym.section_index() else {
            continue;
        };
        let section = file
            .section_by_index(index)
            .and_then(|s| s.name().map(str::to_string))
            .map_err(|e| bad(e.to_string()))?;
        if !section.contains('/') {
            continue; // .text: subprograms such as guard_pick
        }
        let name = sym.name().map_err(|e| bad(e.to_string()))?;
        out.insert(name.to_string(), section);
    }
    Ok(out)
}

/// The last lines of an error (verifier logs run to megabytes).
fn short_reason(e: &ProgramError) -> String {
    tail(&e.to_string(), 2000)
}

/// The last `max` bytes of `s` (on a char boundary), marked with "...".
fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &s[start..])
}

/// Run an iterator program once (`iter/<type>` sections), reading it to
/// the end; the core pack's `iter/task` seeds `task_exe` for the tasks that
/// predate the load. Its link is closed afterwards; the program stays loaded.
fn run_iter(program: &mut Program, iter_type: &str, btf: &Btf) -> Result<(), String> {
    use std::io::Read;

    let Program::Iter(it) = program else {
        return Err(format!(
            "not an iterator program ({:?})",
            program.prog_type()
        ));
    };
    it.load(iter_type, btf).map_err(|e| short_reason(&e))?;
    let id = it.attach().map_err(|e| short_reason(&e))?;
    let link = it.take_link(id).map_err(|e| short_reason(&e))?;
    let mut file = link.into_file().map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)
        .map_err(|e| format!("reading the iterator: {e}"))?;
    Ok(())
}

fn attach(program: &mut Program, hook: &str, btf: &Btf) -> Result<(), String> {
    match program {
        Program::Lsm(lsm) => {
            lsm.load(hook, btf).map_err(|e| short_reason(&e))?;
            lsm.attach().map_err(|e| short_reason(&e))?;
            Ok(())
        }
        other => Err(format!("not an LSM program ({:?})", other.prog_type())),
    }
}

/// Load the built-in pack in `pack_dir` (its `manifest.json` names the
/// object) and attach every program. Every file must be a regular file. A
/// program that fails to load or attach is recorded in
/// [`Loaded::status`]; the others still run. Signed packs go through
/// [`load_bytes`] instead.
pub fn load(pack_dir: &Path) -> Result<Loaded, LoadError> {
    let read = |p: PathBuf| {
        let regular = std::fs::symlink_metadata(&p).and_then(|m| {
            if m.is_file() {
                Ok(())
            } else {
                Err(std::io::Error::other("not a regular file"))
            }
        });
        regular
            .and_then(|()| std::fs::read(&p))
            .map_err(|source| LoadError::Read { path: p, source })
    };
    let manifest_path = pack_dir.join("manifest.json");
    let manifest =
        crate::packs::Manifest::parse(&read(manifest_path.clone())?).map_err(|source| {
            LoadError::Manifest {
                path: manifest_path,
                source,
            }
        })?;
    let [object] = manifest.programs.as_slice() else {
        return Err(LoadError::ObjectCount(manifest.programs.len()));
    };
    let bytes = read(pack_dir.join(object))?;
    load_object(object, &bytes)
}

/// Load a verified pack from its in-memory object: the bytes that were
/// checked are the bytes that run.
pub fn load_bytes(pack: &crate::packs::VerifiedPack) -> Result<Loaded, LoadError> {
    let [object] = pack.manifest.programs.as_slice() else {
        return Err(LoadError::ObjectCount(pack.manifest.programs.len()));
    };
    load_object(object, &pack.object)
}

fn load_object(object: &str, bytes: &[u8]) -> Result<Loaded, LoadError> {
    let sections = program_sections(object, bytes)?;
    let btf = Btf::from_sys_fs()?;
    let mut ebpf = EbpfLoader::new()
        .btf(&btf)
        // task_exe and scratch are TASK_STORAGE, which aya creates but has no
        // typed userspace API for; the loader never reads or writes them.
        .allow_unsupported_maps()
        .load(bytes)
        .map_err(|e| LoadError::Ebpf {
            object: object.to_owned(),
            source: Box::new(e),
        })?;

    // LSM programs first, iterators after: an iterator that seeds state
    // (task_exe) runs once the hooks that keep it current are attached, so
    // no task falls between the two.
    let mut status = Vec::new();
    for pass in [false, true] {
        for (name, program) in ebpf.programs_mut() {
            let section = sections.get(name).cloned().unwrap_or_default();
            let iter = section.starts_with("iter/") || section.starts_with("iter.s/");
            if iter != pass {
                continue;
            }
            let (kind, sub) = section.split_once('/').unwrap_or_default();
            let (hook, result) = if sub.is_empty() {
                (String::new(), Err(format!("no program section for {name}")))
            } else if iter {
                (format!("{kind}/{sub}"), run_iter(program, sub, &btf))
            } else {
                (sub.to_string(), attach(program, sub, &btf))
            };
            status.push(ProgramStatus {
                name: name.to_string(),
                hook,
                attached: result.is_ok(),
                reason: result.err(),
            });
        }
    }
    status.sort_by(|a, b| a.name.cmp(&b.name));

    for map in [
        "rules_meta",
        "hits",
        "config",
        "task_exe",
        "ringbuf_dropped",
    ]
    .into_iter()
    .chain(super::DIMENSION_MAPS)
    {
        if ebpf.map(map).is_none() {
            return Err(LoadError::Map {
                map,
                message: "missing".into(),
            });
        }
    }
    let ringbuf = ebpf.take_map("events").ok_or(LoadError::Map {
        map: "events",
        message: "missing".into(),
    })?;
    let ringbuf = RingBuf::try_from(ringbuf).map_err(|e| LoadError::Map {
        map: "events",
        message: e.to_string(),
    })?;
    let cpus = aya::util::nr_cpus()
        .map_err(|(what, e)| LoadError::Map {
            map: "hits",
            message: format!("{what}: {e}"),
        })?
        .get() as usize;

    Ok(Loaded {
        ebpf,
        status,
        applied: Applied::default(),
        ringbuf: Some(ringbuf),
        cpus,
    })
}

fn lpm_key<const N: usize>(map: &'static str, b: &[u8]) -> Result<Key<[u8; N]>, ApplyError> {
    if b.len() != 4 + N {
        return Err(ApplyError::KeyLength { map, len: b.len() });
    }
    let plen = u32::from_le_bytes(b[..4].try_into().expect("4 bytes"));
    let data: [u8; N] = b[4..].try_into().expect("N bytes");
    Ok(Key::new(plen, data))
}

fn hash_key<const N: usize>(map: &'static str, b: &[u8]) -> Result<[u8; N], ApplyError> {
    b.try_into()
        .map_err(|_| ApplyError::KeyLength { map, len: b.len() })
}

type RuleSetBytes = [u8; 128];

impl Loaded {
    fn map_mut(&mut self, map: &'static str) -> Result<&mut aya::maps::Map, ApplyError> {
        self.ebpf.map_mut(map).ok_or(ApplyError::Missing(map))
    }

    fn lpm<const N: usize>(
        &mut self,
        map: &'static str,
    ) -> Result<LpmTrie<&mut MapData, [u8; N], RuleSetBytes>, ApplyError> {
        LpmTrie::try_from(self.map_mut(map)?).map_err(|source| ApplyError::Map { map, source })
    }

    fn hash<const N: usize>(
        &mut self,
        map: &'static str,
    ) -> Result<BpfHash<&mut MapData, [u8; N], RuleSetBytes>, ApplyError> {
        BpfHash::try_from(self.map_mut(map)?).map_err(|source| ApplyError::Map { map, source })
    }

    /// Insert or overwrite one dimension entry (`map` is one of
    /// [`super::DIMENSION_MAPS`]).
    fn upsert(&mut self, map: &'static str, k: &[u8], v: &RuleSetBytes) -> Result<(), ApplyError> {
        let r = match map {
            "exe_prefix_lpm" | "path_prefix_lpm" => {
                let key = lpm_key::<PATH_LEN>(map, k)?;
                self.lpm::<PATH_LEN>(map)?.insert(&key, v, 0)
            }
            "net4_lpm" => {
                let key = lpm_key::<4>(map, k)?;
                self.lpm::<4>(map)?.insert(&key, v, 0)
            }
            "net6_lpm" => {
                let key = lpm_key::<16>(map, k)?;
                self.lpm::<16>(map)?.insert(&key, v, 0)
            }
            "unit_rules" => {
                let key = hash_key::<UNIT_LEN>(map, k)?;
                self.hash::<UNIT_LEN>(map)?.insert(&key, v, 0)
            }
            _ => {
                let key = hash_key::<4>(map, k)?;
                self.hash::<4>(map)?.insert(&key, v, 0)
            }
        };
        r.map_err(|source| ApplyError::Map { map, source })
    }

    /// Delete one dimension entry; a key that is already gone is fine.
    fn delete(&mut self, map: &'static str, k: &[u8]) -> Result<(), ApplyError> {
        let r = match map {
            "exe_prefix_lpm" | "path_prefix_lpm" => {
                let key = lpm_key::<PATH_LEN>(map, k)?;
                self.lpm::<PATH_LEN>(map)?.remove(&key)
            }
            "net4_lpm" => {
                let key = lpm_key::<4>(map, k)?;
                self.lpm::<4>(map)?.remove(&key)
            }
            "net6_lpm" => {
                let key = lpm_key::<16>(map, k)?;
                self.lpm::<16>(map)?.remove(&key)
            }
            "unit_rules" => {
                let key = hash_key::<UNIT_LEN>(map, k)?;
                self.hash::<UNIT_LEN>(map)?.remove(&key)
            }
            _ => {
                let key = hash_key::<4>(map, k)?;
                self.hash::<4>(map)?.remove(&key)
            }
        };
        match r {
            Ok(()) | Err(MapError::KeyNotFound) => Ok(()),
            Err(source) => Err(ApplyError::Map { map, source }),
        }
    }

    fn set_meta(&mut self, slot: u32, v: &[u8; 8]) -> Result<(), ApplyError> {
        let map = "rules_meta";
        let mut a: Array<&mut MapData, [u8; 8]> = Array::try_from(self.map_mut(map)?)
            .map_err(|source| ApplyError::Map { map, source })?;
        a.set(slot, v, 0)
            .map_err(|source| ApplyError::Map { map, source })
    }

    fn set_config(&mut self, v: &[u8; 8]) -> Result<(), ApplyError> {
        let map = "config";
        let mut a: Array<&mut MapData, [u8; 8]> = Array::try_from(self.map_mut(map)?)
            .map_err(|source| ApplyError::Map { map, source })?;
        a.set(0, v, 0)
            .map_err(|source| ApplyError::Map { map, source })
    }

    fn zero_hits(&mut self, slot: u32) -> Result<(), ApplyError> {
        let map = "hits";
        let zeros = PerCpuValues::try_from(vec![0u64; self.cpus])
            .map_err(|e| ApplyError::Cpus(e.to_string()))?;
        let mut a: PerCpuArray<&mut MapData, u64> = PerCpuArray::try_from(self.map_mut(map)?)
            .map_err(|source| ApplyError::Map { map, source })?;
        a.set(slot, zeros, 0)
            .map_err(|source| ApplyError::Map { map, source })
    }

    fn apply_plan(
        &mut self,
        c: &Compiled,
        kill_switch: bool,
        guard_tgid: u32,
    ) -> Result<(), ApplyError> {
        let p = plan(&self.applied, c, kill_switch, guard_tgid);
        if p.config_first {
            self.set_config(&p.config)?;
        }
        for &slot in &p.disable_slots {
            if (slot as usize) < MAX_RULES {
                self.set_meta(slot, &disabled_meta(slot))?;
            }
        }
        for &slot in &p.zero_hits {
            if (slot as usize) < MAX_RULES {
                self.zero_hits(slot)?;
            }
        }
        for (map, k) in &p.early_deletes {
            self.delete(map, k)?;
        }
        for (map, k, v) in &p.upserts {
            self.upsert(map, k, v)?;
        }
        for (map, k) in &p.deletes {
            self.delete(map, k)?;
        }
        for (slot, v) in &p.meta {
            self.set_meta(*slot, v)?;
        }
        self.set_config(&p.config)
    }

    /// Replace the maps' contents with `c`, set the kill switch and
    /// sensr-guard's own pid, in the order [`super::plan`] gives: changed
    /// rules are disabled while the dimension maps change, new entries go
    /// in before stale ones go out (unless a map lacks room for both), and
    /// every slot whose rule id changes has its hits zeroed.
    pub fn apply(
        &mut self,
        c: &Compiled,
        kill_switch: bool,
        guard_tgid: u32,
    ) -> Result<(), ApplyError> {
        match self.apply_plan(c, kill_switch, guard_tgid) {
            Ok(()) => {
                self.applied = Applied::after(c);
                Ok(())
            }
            Err(e) => {
                self.applied = Applied::after_failure(&self.applied, c);
                Err(e)
            }
        }
    }

    /// Every program of the pack, by name.
    pub fn status(&self) -> Vec<ProgramStatus> {
        self.status.clone()
    }

    /// The `events` ring buffer. It can be taken once; it keeps its map
    /// open on its own, the programs still detach when `self` drops.
    pub fn ringbuf(&mut self) -> Result<RingBuf<MapData>, LoadError> {
        self.ringbuf.take().ok_or(LoadError::RingBufTaken)
    }

    /// Hits per slot of the applied rules (summed over the CPUs).
    pub fn hits(&self) -> Result<HashMap<u32, u64>, ApplyError> {
        let map = "hits";
        let a = PerCpuArray::<&MapData, u64>::try_from(
            self.ebpf.map(map).ok_or(ApplyError::Missing(map))?,
        )
        .map_err(|source| ApplyError::Map { map, source })?;
        (0..self.applied.slots.len().min(MAX_RULES) as u32)
            .map(|slot| {
                a.get(&slot, 0)
                    .map(|v| (slot, v.iter().sum()))
                    .map_err(|source| ApplyError::Map { map, source })
            })
            .collect()
    }

    /// Hits per rule id of the applied rules.
    pub fn hits_by_id(&self) -> Result<HashMap<String, u64>, ApplyError> {
        Ok(hits_by_id(&self.applied.ids(), &self.hits()?))
    }

    /// Events the ring buffer had no room for (summed over the CPUs).
    pub fn ringbuf_dropped(&self) -> Result<u64, ApplyError> {
        let map = "ringbuf_dropped";
        let a = PerCpuArray::<&MapData, u64>::try_from(
            self.ebpf.map(map).ok_or(ApplyError::Missing(map))?,
        )
        .map_err(|source| ApplyError::Map { map, source })?;
        a.get(&0, 0)
            .map(|v| v.iter().sum())
            .map_err(|source| ApplyError::Map { map, source })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lpm_keys_split_prefixlen_and_data() {
        let mut b = 24u32.to_le_bytes().to_vec();
        b.extend([198, 51, 100, 0]);
        let k = lpm_key::<4>("net4_lpm", &b).unwrap();
        assert_eq!(k.prefix_len(), 24);
        assert_eq!(k.data(), [198, 51, 100, 0]);
        assert!(matches!(
            lpm_key::<16>("net6_lpm", &b),
            Err(ApplyError::KeyLength { len: 8, .. })
        ));
    }

    #[test]
    fn hash_keys_must_have_the_map_key_size() {
        assert_eq!(
            hash_key::<4>("port_rules", &[80, 0, 0, 0]).unwrap(),
            [80, 0, 0, 0]
        );
        assert!(matches!(
            hash_key::<UNIT_LEN>("unit_rules", &[0; 4]),
            Err(ApplyError::KeyLength { len: 4, .. })
        ));
    }

    #[test]
    fn long_reasons_keep_their_end() {
        assert_eq!(tail("short", 10), "short");
        let long = format!("{}é the verifier's last line", "x".repeat(50));
        let t = tail(&long, 30);
        assert!(
            t.starts_with("...") && t.ends_with("the verifier's last line"),
            "{t}"
        );
        assert!(t.len() <= 33);
    }

    #[test]
    fn a_missing_pack_is_a_read_error() {
        let e = load(Path::new("/nonexistent/sensr-guard-pack")).unwrap_err();
        assert!(matches!(e, LoadError::Read { .. }), "{e}");
    }

    #[test]
    fn a_pack_needs_exactly_one_object() {
        let dir = std::env::temp_dir().join(format!("sensr-guard-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            r#"{"name": "x", "version": "1.0.0", "min_sensr": "0.0.0", "programs": ["a.bpf.o", "b.bpf.o"], "rules": "rules.json"}"#,
        )
        .unwrap();
        let e = load(&dir).unwrap_err();
        assert!(matches!(e, LoadError::ObjectCount(2)), "{e}");
        std::fs::write(dir.join("manifest.json"), "{").unwrap();
        assert!(matches!(
            load(&dir).unwrap_err(),
            LoadError::Manifest { .. }
        ));
        std::fs::write(dir.join("manifest.json"), r#"{"name": "x", "version": "1.0.0", "min_sensr": "0.0.0", "programs": ["a.bpf.o"], "rules": "rules.json"}"#).unwrap();
        std::fs::write(dir.join("a.bpf.o"), b"not an elf").unwrap();
        assert!(matches!(load(&dir).unwrap_err(), LoadError::Object { .. }));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
