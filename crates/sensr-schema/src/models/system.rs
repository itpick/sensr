//! System settings: identity, name resolution, time, local accounts, SSH
//! (OPNsense `system` section, `Auth/User.xml`, `Auth/Group.xml`).

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{
    Description, DomainName, GroupName, Host, Hostname, InterfaceId, Port, Secret, SshPublicKey,
    Timezone, Username,
};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Identity, resolvers, time and accounts of the firewall itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct System {
    /// Host name without domain (`OPNsense`, `fw1`).
    pub hostname: Hostname,
    /// Domain of the firewall and default search domain.
    pub domain: DomainName,
    /// Upstream DNS servers for the firewall itself (and for the resolver in
    /// forwarding mode).
    #[serde(default)]
    pub dns_servers: Vec<IpAddr>,
    /// Let DHCP/PPP on WAN replace `dns_servers` (OPNsense `dnsallowoverride`).
    #[serde(default = "yes")]
    pub dns_allow_override: bool,
    /// IANA time zone.
    pub timezone: Timezone,
    /// NTP servers or pools.
    #[serde(default)]
    pub time_servers: Vec<Host>,
    /// Allow IPv6 traffic at all (OPNsense `ipv6allow`).
    #[serde(default = "yes")]
    pub ipv6_allow: bool,
    /// Local user accounts.
    #[serde(default)]
    pub users: ArrayField<User>,
    /// Local groups.
    #[serde(default)]
    pub groups: ArrayField<Group>,
    /// SSH daemon.
    #[serde(default)]
    pub ssh: Ssh,
}

impl Default for System {
    fn default() -> Self {
        Self {
            hostname: "sensr".parse().expect("valid literal"),
            domain: "internal".parse().expect("valid literal"),
            dns_servers: Vec::new(),
            dns_allow_override: true,
            timezone: "Etc/UTC".parse().expect("valid literal"),
            time_servers: Vec::new(),
            ipv6_allow: true,
            users: ArrayField::new(),
            groups: ArrayField::new(),
            ssh: Ssh::default(),
        }
    }
}

/// A local account (OPNsense `system/user`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Login name.
    pub name: Username,
    /// Numeric user id.
    pub uid: u32,
    /// Full name or note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Account locked.
    #[serde(default)]
    pub disabled: bool,
    /// Password hash in crypt(3) form (`$2y$...`, `$6$...`); `None` means no
    /// password login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<Secret<String>>,
    /// Keys allowed to log in over SSH.
    #[serde(default)]
    pub authorized_keys: Vec<SshPublicKey>,
    /// Groups the user belongs to.
    #[serde(default)]
    pub groups: Vec<GroupName>,
    /// Login shell (absolute path); `None` for the system default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell: Option<String>,
    /// API key pairs for HTTP Basic `key:secret` access (OPNsense `apikeys`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_keys: Vec<ApiKey>,
}

/// One API key: the public key and a crypt(3) hash of the secret (SHA-512-crypt
/// `$6$…` as OPNsense writes it), so imported keys keep working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApiKey {
    /// Public key, presented as the Basic-auth user name.
    pub key: String,
    /// Hash of the secret; the clear secret is never stored.
    pub secret_hash: Secret<String>,
}

/// A local group (OPNsense `system/group`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Group name.
    pub name: GroupName,
    /// Numeric group id.
    pub gid: u32,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Privileges granted to members (OPNsense privilege names such as
    /// `page-all`), evaluated by `sensr-auth`.
    #[serde(default)]
    pub privileges: Vec<String>,
}

/// The SSH daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    /// Run sshd.
    #[serde(default)]
    pub enabled: bool,
    /// Listen port.
    #[serde(default = "ssh_port")]
    pub port: Port,
    /// Interfaces to listen on; empty means all.
    #[serde(default)]
    pub interfaces: Vec<InterfaceId>,
    /// Allow `root` to log in.
    #[serde(default)]
    pub permit_root_login: bool,
    /// Allow password authentication (keys only when false).
    #[serde(default)]
    pub password_auth: bool,
    /// Only members of this group may log in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<GroupName>,
}

fn ssh_port() -> Port {
    Port::new(22).expect("non-zero")
}

impl Default for Ssh {
    fn default() -> Self {
        Self {
            enabled: false,
            port: ssh_port(),
            interfaces: Vec::new(),
            permit_root_login: false,
            password_auth: false,
            group: None,
        }
    }
}

impl Validate for System {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let users = at.join("users");
        check::unique(
            self.users
                .iter()
                .map(|(id, u)| (users.join(id), Some(u.name.as_str().to_owned()))),
            "name",
            "This username already exist.",
            out,
        );
        check::unique(
            self.users
                .iter()
                .map(|(id, u)| (users.join(id), Some(u.uid))),
            "uid",
            "This user ID is already in use.",
            out,
        );
        for (id, user) in &self.users {
            let p = users.join(id);
            for g in &user.groups {
                if !ctx.has_group(g) {
                    out.add(
                        &p.join("groups"),
                        ValidatorKind::Callback,
                        format!("Group {g} does not exist."),
                    );
                }
            }
            if let Some(shell) = &user.shell
                && (!shell.starts_with('/') || shell.contains(char::is_whitespace))
            {
                out.add(
                    &p.join("shell"),
                    ValidatorKind::Regex,
                    "The shell must be an absolute path.",
                );
            }
        }
        let mut keys = std::collections::HashSet::new();
        for (id, user) in &self.users {
            for (n, k) in user.api_keys.iter().enumerate() {
                let p = users.join(id).join("api_keys").join(n.to_string());
                if k.key.is_empty()
                    || !k
                        .key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
                {
                    out.add(
                        &p.join("key"),
                        ValidatorKind::Regex,
                        "An API key must be base64 text.",
                    );
                } else if !keys.insert(k.key.as_str()) {
                    out.add(
                        &p.join("key"),
                        ValidatorKind::Constraint,
                        "This API key already exists.",
                    );
                }
                if !k.secret_hash.expose().starts_with('$') {
                    out.add(
                        &p.join("secret_hash"),
                        ValidatorKind::Regex,
                        "The API secret must be stored as a crypt(3) hash.",
                    );
                }
            }
        }
        let groups = at.join("groups");
        check::unique(
            self.groups
                .iter()
                .map(|(id, g)| (groups.join(id), Some(g.name.as_str().to_owned()))),
            "name",
            "This group name already exists.",
            out,
        );
        check::unique(
            self.groups
                .iter()
                .map(|(id, g)| (groups.join(id), Some(g.gid))),
            "gid",
            "This group ID is already in use.",
            out,
        );
        let ssh = at.join("ssh");
        check::interfaces(ctx, &self.ssh.interfaces, &ssh.join("interfaces"), out);
        if let Some(g) = &self.ssh.group
            && !ctx.has_group(g)
        {
            out.add(
                &ssh.join("group"),
                ValidatorKind::Callback,
                format!("Group {g} does not exist."),
            );
        }
    }
}
