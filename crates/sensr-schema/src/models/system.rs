//! System settings: identity, name resolution, time, local accounts, SSH
//! (OPNsense `system` section, `Auth/User.xml`, `Auth/Group.xml`).

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::{ArrayField, Relation};
use crate::fields::{
    Description, DomainName, GroupName, Host, Hostname, HttpUrl, InterfaceId, Pem, Port, Secret,
    SshPublicKey, Timezone, Username,
};
use crate::models::trust::Certificate;
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
    /// The web GUI and API listener (OPNsense `system/webgui`).
    #[serde(default)]
    pub webgui: WebGui,
    /// Logging in through external OpenID Connect providers (OPNsense
    /// Business Edition `system/auth` OIDC fields).
    #[serde(default, skip_serializing_if = "Oidc::is_empty")]
    pub oidc: Oidc,
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
            webgui: WebGui::default(),
            oidc: Oidc::default(),
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

/// How the web GUI is served.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebProtocol {
    /// TLS (the default).
    #[default]
    Https,
    /// Plain HTTP (credentials travel in clear; only for isolated
    /// management networks).
    Http,
}

/// The web GUI and API listener (OPNsense System › Settings ›
/// Administration, `system/webgui`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebGui {
    /// HTTPS or HTTP.
    #[serde(default)]
    pub protocol: WebProtocol,
    /// Listen port; `None` is 443 for HTTPS, 80 for HTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Port>,
    /// Interfaces to listen on (loopback always included); empty means
    /// all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceId>,
    /// With HTTPS, also answer on port 80 with a redirect (inverse of
    /// OPNsense `disablehttpredirect`).
    #[serde(default = "yes")]
    pub http_redirect: bool,
    /// The server certificate from the trust store; `None` uses the
    /// self-signed one sensr generates at first boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Relation<Certificate>>,
}

impl Default for WebGui {
    fn default() -> Self {
        Self {
            protocol: WebProtocol::Https,
            port: None,
            interfaces: Vec::new(),
            http_redirect: true,
            certificate: None,
        }
    }
}

/// External OpenID Connect login (OPNsense Business Edition adds this to
/// the community GUI; sensr implements the relying-party side only).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    /// Offer the configured providers on the login page.
    #[serde(default)]
    pub enabled: bool,
    /// Providers.
    #[serde(default)]
    pub providers: ArrayField<OidcProvider>,
}

impl Oidc {
    /// True while the section is at its defaults (kept out of documents that
    /// never used it).
    pub fn is_empty(&self) -> bool {
        !self.enabled && self.providers.is_empty()
    }

    /// One provider by its object id.
    pub fn provider(&self, id: &str) -> Option<&OidcProvider> {
        self.providers
            .iter()
            .find(|(k, _)| k.to_string() == id)
            .map(|(_, p)| p)
    }

    /// Providers offered on the login page, in name order.
    pub fn active(&self) -> Vec<(&crate::array::Uuid, &OidcProvider)> {
        if !self.enabled {
            return Vec::new();
        }
        let mut v: Vec<(&crate::array::Uuid, &OidcProvider)> =
            self.providers.iter().filter(|(_, p)| p.enabled).collect();
        v.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        v
    }
}

/// Which identity provider this entry is for. The presets only supply
/// defaults an admin may override; the protocol is the same.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcProviderKind {
    /// Any standards-compliant provider (discovery metadata is fetched).
    #[default]
    Generic,
    /// Zitadel (`https://<instance>`), including its project-role claim.
    Zitadel,
    /// Google Workspace / consumer Google accounts.
    Google,
    /// Sign in with Apple (`form_post`, client secret generated from a key).
    Apple,
}

/// One OpenID Connect provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcProvider {
    /// Preset.
    #[serde(default)]
    pub kind: OidcProviderKind,
    /// Provider is offered on the login page.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Text on the login button (`Zitadel`, `Google`, …).
    pub name: String,
    /// Issuer identifier; discovery is `{issuer}/.well-known/openid-configuration`.
    pub issuer: HttpUrl,
    /// Client id registered with the provider.
    pub client_id: String,
    /// Client secret. Optional for public clients that use PKCE, and unused
    /// by the Apple preset when a signing key is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<Secret<String>>,
    /// Apple only: the ten-character team identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Apple only: the key identifier of the `Sign in with Apple` key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Apple only: the `.p8` private key, used to sign the client-secret JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Secret<Pem>>,
    /// Extra scopes. `openid` is always requested; `email` and `profile` are
    /// added by the preset unless listed here.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Claim that carries the login name shown in the GUI.
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    /// Claim that lists the user's provider groups (array, object keys or a
    /// space/comma separated string). Empty means the provider has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    /// Provider groups allowed to sign in; empty allows any authenticated
    /// identity.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    /// Local group whose privileges the signed-in identity gets.
    pub local_group: GroupName,
}

fn default_username_claim() -> String {
    "email".to_owned()
}

impl OidcProvider {
    /// The scopes actually requested.
    pub fn effective_scopes(&self) -> Vec<String> {
        let mut v = vec!["openid".to_owned()];
        let preset = match self.kind {
            OidcProviderKind::Apple => ["email", "name"].as_slice(),
            _ => ["email", "profile"].as_slice(),
        };
        for s in preset {
            if !self.scopes.iter().any(|x| x == s) {
                v.push((*s).to_owned());
            }
        }
        for s in &self.scopes {
            if !v.contains(s) {
                v.push(s.clone());
            }
        }
        v
    }

    /// The group claim the preset expects when none is configured.
    pub fn effective_groups_claim(&self) -> Option<&str> {
        self.groups_claim.as_deref().or(match self.kind {
            OidcProviderKind::Zitadel => Some("urn:zitadel:iam:org:project:roles"),
            _ => None,
        })
    }
}

/// External auth is configured but the provider cannot work as written.
fn oidc_https(u: &HttpUrl) -> bool {
    let s = u.as_str();
    if s.starts_with("https://") {
        return true;
    }
    let host = s
        .strip_prefix("http://")
        .and_then(|r| r.split(['/', '?', '#']).next())
        .unwrap_or_default();
    // A bracketed IPv6 literal keeps its brackets; only a port is stripped.
    let host = if host.starts_with('[') {
        host.split(']')
            .next()
            .map_or(host, |h| &host[..h.len() + 1])
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

impl Validate for Oidc {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let providers = at.join("providers");
        check::unique(
            self.providers
                .iter()
                .map(|(id, p)| (providers.join(id), Some(p.name.clone()))),
            "name",
            "Another provider already uses this name.",
            out,
        );
        for (id, p) in &self.providers {
            let path = providers.join(id);
            if p.name.trim().is_empty() || p.name.chars().count() > 64 {
                out.add(
                    &path.join("name"),
                    ValidatorKind::Constraint,
                    "The name must be 1 to 64 characters long.",
                );
            }
            if p.name.chars().any(char::is_control) {
                out.add(
                    &path.join("name"),
                    ValidatorKind::Regex,
                    "The name cannot contain control characters.",
                );
            }
            if !oidc_https(&p.issuer) {
                out.add(
                    &path.join("issuer"),
                    ValidatorKind::Callback,
                    "The issuer must use https (http is allowed only for localhost).",
                );
            }
            if p.client_id.trim().is_empty() {
                out.add(
                    &path.join("client_id"),
                    ValidatorKind::PresenceOf,
                    "The client id is required.",
                );
            }
            if p.username_claim.trim().is_empty() {
                out.add(
                    &path.join("username_claim"),
                    ValidatorKind::PresenceOf,
                    "A claim that carries the login name is required.",
                );
            }
            if !ctx.has_group(&p.local_group) {
                out.add(
                    &path.join("local_group"),
                    ValidatorKind::Callback,
                    format!("Group {} does not exist.", p.local_group),
                );
            }
            if p.kind == OidcProviderKind::Apple {
                let generated =
                    p.team_id.is_some() || p.key_id.is_some() || p.private_key.is_some();
                if generated
                    && (p.team_id.is_none() || p.key_id.is_none() || p.private_key.is_none())
                {
                    out.add(
                        &path.join("private_key"),
                        ValidatorKind::PresenceOf,
                        "Apple needs the team id, key id and private key together (or a pasted client secret).",
                    );
                }
                if !generated && p.client_secret.is_none() {
                    out.add(
                        &path.join("client_secret"),
                        ValidatorKind::PresenceOf,
                        "Apple needs a signing key or a client secret.",
                    );
                }
            }
        }
    }
}

/// Port of the HTTP-to-HTTPS redirect listener.
pub const HTTP_REDIRECT_PORT: u16 = 80;

impl WebGui {
    /// True when served over TLS.
    pub fn https(&self) -> bool {
        self.protocol == WebProtocol::Https
    }

    /// The port the GUI listens on.
    pub fn listen_port(&self) -> u16 {
        match (self.port, self.protocol) {
            (Some(p), _) => p.get(),
            (None, WebProtocol::Https) => 443,
            (None, WebProtocol::Http) => 80,
        }
    }

    /// The redirect listener's port, when there is one.
    pub fn redirect_port(&self) -> Option<u16> {
        (self.https() && self.http_redirect && self.listen_port() != HTTP_REDIRECT_PORT)
            .then_some(HTTP_REDIRECT_PORT)
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
        let web = at.join("webgui");
        check::interfaces(ctx, &self.webgui.interfaces, &web.join("interfaces"), out);
        if self.webgui.https()
            && self.webgui.http_redirect
            && self.webgui.listen_port() == HTTP_REDIRECT_PORT
        {
            out.add(
                &web.join("port"),
                ValidatorKind::Constraint,
                "HTTPS on port 80 leaves no port for the HTTP redirect; choose another port or disable the redirect.",
            );
        }
        if self.ssh.enabled && self.ssh.port.get() == self.webgui.listen_port() {
            out.add(
                &web.join("port"),
                ValidatorKind::Constraint,
                "The web GUI port is already used by SSH.",
            );
        }
        if let Some(g) = &self.ssh.group
            && !ctx.has_group(g)
        {
            out.add(
                &ssh.join("group"),
                ValidatorKind::Callback,
                format!("Group {g} does not exist."),
            );
        }
        self.oidc.validate(ctx, &at.join("oidc"), out);
    }
}
