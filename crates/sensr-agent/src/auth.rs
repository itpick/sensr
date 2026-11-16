//! Credential checks against the users and groups in the head document.
//!
//! Hashes never leave the agent: `sensr-api` sends the presented credential
//! over the socket and gets back the identity and effective privileges.
//!
//! Two document shapes are understood:
//! - the typed `sensr-schema` document: `system.users` and `system.groups`
//!   are UUID-keyed maps; a user has `name`, `uid`, `disabled`,
//!   `password_hash`, `groups` (group names) and `api_keys`
//!   (`[{key, secret_hash}]`); a group has `name` and `privileges`;
//! - OPNsense's `config.xml` array view: `system.user[]` with `name`,
//!   `uid`, `password`, `priv` (string, CSV or list), `disabled`, `apikeys`
//!   (`key|secret|created|descr` lines, or `{item: …}` elements);
//!   `system.group[]` with `name`, `member` (uids), `priv`,
//!   `source_networks`.

use std::net::IpAddr;
use std::sync::Arc;

use sensr_auth::acl::{Acl, Group, Registry, User};
use sensr_auth::{apikey, password};
use sensr_ipc::{AuthInfo, Credential};
use serde_json::Value;

fn list(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other],
    }
}

fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Strings, numbers or lists of them, each possibly comma-separated.
fn csv(v: Option<&Value>) -> Vec<String> {
    list(v)
        .into_iter()
        .flat_map(|item| {
            text(Some(item))
                .split(',')
                .map(|s| s.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1" || s.eq_ignore_ascii_case("yes"),
        Some(Value::Number(n)) => n.as_u64().is_some_and(|n| n != 0),
        _ => false,
    }
}

/// Items of a list, or the values of a UUID-keyed map.
fn items(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Object(m)) => m.values().collect(),
        other => list(other),
    }
}

fn users(doc: &Value) -> Vec<&Value> {
    let mut all = items(doc.pointer("/system/users"));
    all.extend(list(doc.pointer("/system/user")));
    all
}

fn first<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|k| v.get(*k))
}

fn acl_of(doc: &Value) -> Acl {
    let all_users = users(doc);
    let users: Vec<User> = all_users
        .iter()
        .filter_map(|u| {
            Some(User {
                name: text(u.get("name")),
                uid: text(u.get("uid")).parse().ok()?,
                privileges: csv(u.get("priv")),
            })
        })
        .collect();
    let mut groups: Vec<Group> = list(doc.pointer("/system/group"))
        .into_iter()
        .map(|g| Group {
            name: text(g.get("name")),
            members: csv(g.get("member"))
                .iter()
                .filter_map(|m| m.parse().ok())
                .collect(),
            privileges: csv(g.get("priv")),
            source_networks: csv(g.get("source_networks"))
                .iter()
                .filter_map(|n| n.parse().ok())
                .collect(),
        })
        .collect();
    // Typed groups: membership is listed on the user, by group name.
    for g in items(doc.pointer("/system/groups")) {
        let name = text(g.get("name"));
        let members = all_users
            .iter()
            .filter(|u| csv(u.get("groups")).contains(&name))
            .filter_map(|u| text(u.get("uid")).parse().ok())
            .collect();
        groups.push(Group {
            name,
            members,
            privileges: csv(g.get("privileges")),
            source_networks: csv(g.get("source_networks"))
                .iter()
                .filter_map(|n| n.parse().ok())
                .collect(),
        });
    }
    Acl::new(Arc::new(Registry::builtin()), &users, &groups)
}

fn api_keys(user: &Value) -> Vec<(String, String)> {
    let raw = first(user, &["api_keys", "apikeys"]);
    // Current OPNsense stores `key|secret_hash|created|descr`, one key per
    // line; older configs have `<item><key/><secret/></item>` elements.
    if let Some(Value::String(lines)) = raw {
        return lines
            .lines()
            .filter_map(|line| {
                let mut parts = line.trim().splitn(4, '|');
                Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
            })
            .filter(|(k, s)| !k.is_empty() && !s.is_empty())
            .collect();
    }
    let items = match raw {
        Some(Value::Object(m)) if m.contains_key("item") => list(m.get("item")),
        other => list(other),
    };
    items
        .into_iter()
        .map(|k| {
            (
                text(k.get("key")),
                text(first(k, &["secret_hash", "secret"])),
            )
        })
        .filter(|(k, s)| !k.is_empty() && !s.is_empty())
        .collect()
}

/// Checks `cred` against `doc`; `None` for any failure (unknown user, bad
/// secret, disabled account), so callers cannot tell which.
pub fn authenticate(doc: &Value, cred: &Credential, remote: Option<IpAddr>) -> Option<AuthInfo> {
    let user = match cred {
        Credential::Password { user, password: pw } => {
            let u = users(doc)
                .into_iter()
                .find(|u| text(u.get("name")) == *user)?;
            if !password::verify_password(pw, &text(first(u, &["password_hash", "password"]))) {
                return None;
            }
            u
        }
        Credential::ApiKey { key, secret } => users(doc).into_iter().find(|u| {
            api_keys(u)
                .iter()
                .any(|(k, s)| k == key && apikey::verify_secret(secret, s))
        })?,
    };
    if truthy(user.get("disabled")) {
        return None;
    }
    let name = text(user.get("name"));
    let uid = text(user.get("uid")).parse().ok()?;
    let acl = acl_of(doc);
    Some(AuthInfo {
        groups: acl.groups(&name),
        privileges: acl
            .effective_privileges(&name, remote)
            .into_iter()
            .collect(),
        user: name,
        uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc() -> (Value, String) {
        let key = apikey::generate().unwrap();
        let key2 = apikey::generate().unwrap();
        let doc = json!({"system": {
            "user": [
                {"name": "root", "uid": "0",
                 "password": "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS",
                 "apikeys": {"item": {"key": key.key, "secret": key.secret_hash}}},
                {"name": "bot", "uid": "2002", "apikeys": format!("other|$6$x$y|0|\n{}|{}|1794012100|automation\n", key2.key, key2.secret_hash)},
                {"name": "ro", "uid": "2000", "priv": "user-config-readonly,page-sensr-status",
                 "password": password::hash_password("pw").unwrap()},
                {"name": "off", "uid": "2001", "disabled": "1",
                 "password": password::hash_password("pw").unwrap()},
            ],
            "group": [{"name": "admins", "member": "0", "priv": "page-all"}],
        }});
        (
            doc,
            format!("{}:{}|{}:{}", key.key, key.secret, key2.key, key2.secret),
        )
    }

    fn pw(user: &str, password: &str) -> Credential {
        Credential::Password {
            user: user.into(),
            password: password.into(),
        }
    }

    #[test]
    fn password_login_resolves_groups_and_privileges() {
        let (doc, _) = doc();
        let info = authenticate(&doc, &pw("root", "opnsense"), None).unwrap();
        assert_eq!(info.uid, 0);
        assert_eq!(info.groups, ["admins"]);
        assert_eq!(info.privileges, ["page-all"]);
        let ro = authenticate(&doc, &pw("ro", "pw"), None).unwrap();
        assert_eq!(ro.privileges, ["page-sensr-status", "user-config-readonly"]);
    }

    #[test]
    fn api_key_login() {
        let (doc, pairs) = doc();
        let (first, second) = pairs.split_once('|').unwrap();
        let (key2, secret2) = second.split_once(':').unwrap();
        let line_format = Credential::ApiKey {
            key: key2.into(),
            secret: secret2.into(),
        };
        assert_eq!(authenticate(&doc, &line_format, None).unwrap().user, "bot");
        let (key, secret) = first.split_once(':').unwrap();
        let ok = Credential::ApiKey {
            key: key.into(),
            secret: secret.into(),
        };
        assert_eq!(authenticate(&doc, &ok, None).unwrap().user, "root");
        let bad = Credential::ApiKey {
            key: key.into(),
            secret: "nope".into(),
        };
        assert!(authenticate(&doc, &bad, None).is_none());
    }

    #[test]
    fn typed_document_shape() {
        let key = apikey::generate().unwrap();
        let doc = json!({"system": {
            "users": {
                "6f0c6f9e-0000-4000-8000-000000000001": {
                    "name": "root", "uid": 0, "disabled": false, "groups": ["admins"],
                    "password_hash": password::hash_password("pw").unwrap(),
                    "api_keys": [{"key": key.key, "secret_hash": key.secret_hash}],
                },
                "6f0c6f9e-0000-4000-8000-000000000002": {
                    "name": "off", "uid": 2001, "disabled": true,
                    "password_hash": password::hash_password("pw").unwrap(),
                },
            },
            "groups": {"6f0c6f9e-0000-4000-8000-0000000000a1": {"name": "admins", "gid": 1999, "privileges": ["page-all"]}},
        }});
        let info = authenticate(&doc, &pw("root", "pw"), None).unwrap();
        assert_eq!(
            (info.uid, info.groups.clone(), info.privileges.clone()),
            (0, vec!["admins".to_owned()], vec!["page-all".to_owned()])
        );
        let by_key = Credential::ApiKey {
            key: key.key.clone(),
            secret: key.secret.clone(),
        };
        assert_eq!(authenticate(&doc, &by_key, None).unwrap().user, "root");
        assert!(authenticate(&doc, &pw("off", "pw"), None).is_none());
    }

    #[test]
    fn failures_are_indistinguishable() {
        let (doc, _) = doc();
        assert!(authenticate(&doc, &pw("root", "wrong"), None).is_none());
        assert!(authenticate(&doc, &pw("ghost", "x"), None).is_none());
        assert!(authenticate(&doc, &pw("off", "pw"), None).is_none());
        assert!(authenticate(&json!({}), &pw("root", "opnsense"), None).is_none());
    }
}
