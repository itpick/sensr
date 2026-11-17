//! SSH access from the config: each user's `authorized_keys` rendered to
//! `/run/sensr/ssh/authorized_keys/<user>`, which the image's sshd reads
//! (`AuthorizedKeysFile … /run/sensr/ssh/authorized_keys/%u`; keys only,
//! no passwords), and the seed folder's `authorized_keys` imported for root.
//!
//! The files follow the *applied* revision, so a key removed in a commit
//! stops working when the commit applies, and a commit-confirm rollback
//! brings the old keys back with everything else.

use std::path::Path;

use sensr_schema::Document;
use sensr_schema::fields::SshPublicKey;
use sensr_schema::models::system::{Group, User};

use crate::store::write_atomic;

/// Where the keys go on the box.
pub const KEYS_DIR: &str = "/run/sensr/ssh/authorized_keys";

/// Writes one file per enabled user with keys (0644, directory 0755) and
/// removes the files of users that no longer have any. Only rewrites files
/// whose content changed.
pub fn render(doc: &Document, dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    let mut wanted = Vec::new();
    for u in doc.system.users.values() {
        if u.disabled || u.authorized_keys.is_empty() {
            continue;
        }
        let name = u.name.to_string();
        let text: String = u.authorized_keys.iter().map(|k| format!("{k}\n")).collect();
        let path = dir.join(&name);
        if std::fs::read_to_string(&path).ok().as_deref() != Some(text.as_str()) {
            write_atomic(&path, text.as_bytes())?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        }
        wanted.push(name);
    }
    for e in std::fs::read_dir(dir)?.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().into_owned();
        if !wanted.contains(&name) {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

/// Parses an `authorized_keys` file: one key per line, `#` comments and
/// blank lines skipped. Lines with options (`from="…" ssh-ed25519 …`) are
/// refused: the config field holds plain keys.
pub fn parse_authorized_keys(text: &str) -> Result<Vec<SshPublicKey>, String> {
    text.lines()
        .enumerate()
        .map(|(n, l)| (n + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .map(|(n, l)| {
            l.parse()
                .map_err(|e| format!("line {n}: not a plain SSH public key ({e})"))
        })
        .collect()
}

/// Adds `keys` to root (uid 0), creating root and an `admins` group with
/// every privilege when the document has none (the factory document has no
/// users). Keys root already has are not added twice. Returns how many
/// keys were new.
pub fn add_root_keys(doc: &mut Document, keys: &[SshPublicKey]) -> Result<usize, String> {
    let has_root = doc.system.users.values().any(|u| u.uid == 0);
    if !has_root {
        if !doc
            .system
            .groups
            .values()
            .any(|g| g.name.as_str() == "admins")
        {
            let g: Group = serde_json::from_value(serde_json::json!({
                "name": "admins", "gid": 1999, "privileges": ["page-all"],
                "description": "System Administrators",
            }))
            .map_err(|e| e.to_string())?;
            doc.system.groups.push(g);
        }
        let u: User = serde_json::from_value(serde_json::json!({
            "name": "root", "uid": 0, "groups": ["admins"],
            "description": "System Administrator",
        }))
        .map_err(|e| e.to_string())?;
        doc.system.users.push(u);
    }
    let root = doc
        .system
        .users
        .iter_mut()
        .map(|(_, u)| u)
        .find(|u| u.uid == 0)
        .ok_or("no root user")?;
    let mut added = 0;
    for k in keys {
        if !root.authorized_keys.contains(k) {
            root.authorized_keys.push(k.clone());
            added += 1;
        }
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC8u6EM1pQBx4cCeioZw0En7NYq7SYguxI03/I6QYJwx admin@laptop";
    const K2: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILNpSR7f6D5LuhKudlCHNUi9i+tSH3UNoUldQYb3KGpU phone";

    #[test]
    fn seed_keys_go_to_root_and_render_to_files() {
        use std::os::unix::fs::PermissionsExt;
        let keys = parse_authorized_keys(&format!("# mine\n{K1}\n\n{K2}\n{K1}\n")).unwrap();
        assert_eq!(keys.len(), 3);
        assert!(parse_authorized_keys("from=\"10.0.0.0/8\" ssh-ed25519 AAAA x").is_err());

        let mut doc = Document::factory();
        assert_eq!(
            add_root_keys(&mut doc, &keys).unwrap(),
            2,
            "duplicates once"
        );
        assert!(doc.validate().is_empty(), "{}", doc.validate());
        assert_eq!(add_root_keys(&mut doc, &keys).unwrap(), 0);

        let dir = tempfile::tempdir().unwrap();
        let keys_dir = dir.path().join("ssh/authorized_keys");
        render(&doc, &keys_dir).unwrap();
        let root = keys_dir.join("root");
        assert_eq!(
            std::fs::read_to_string(&root).unwrap(),
            format!("{K1}\n{K2}\n")
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&root), mode(&keys_dir)), (0o644, 0o755));

        // a disabled user loses access
        for (_, u) in doc.system.users.iter_mut() {
            u.disabled = true;
        }
        render(&doc, &keys_dir).unwrap();
        assert!(!root.exists());
    }
}
