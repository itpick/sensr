//! TLS material for the web GUI (OPNsense `webgui_configure` /
//! `webgui_create_selfsigned`).
//!
//! The certificate comes from the trust store when `system.webgui.
//! certificate` names one with its key. Otherwise sensr serves a
//! certificate from its own local CA, created at first boot under
//! `<state>/tls/` (keys 0600): operators trust `ca.pem` once and the leaf
//! can be re-issued whenever the host name, domain or static addresses
//! change, without another browser warning. The leaf is re-issued when its
//! names no longer match the document or it nears expiry.
//!
//! The API process cannot read the state directory; it asks the agent for
//! the material over IPC ([`sensr_ipc::Op::WebListener`], trusted peers
//! only).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sensr_ipc::WebListener;
use sensr_schema::Document;
use sensr_schema::models::interfaces::{Ipv4Config, Ipv6Config};
use serde::{Deserialize, Serialize};

const CA_NAME: &str = "sensr local CA";
/// Leaf lifetime: under the 398 days browsers accept for server
/// certificates.
const LEAF_DAYS: i64 = 397;
/// Re-issue this long before expiry.
const RENEW_DAYS: i64 = 30;
const CA_YEARS: i32 = 20;
const DAY_SECS: i64 = 86_400;

/// Failures creating or reading certificates.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Disk I/O under the TLS directory.
    #[error("tls i/o at {path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// Certificate generation or parsing.
    #[error("certificate: {0}")]
    Cert(String),
}

fn cert_err(e: impl std::fmt::Display) -> TlsError {
    TlsError::Cert(e.to_string())
}

/// What the leaf was issued for, kept next to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LeafInfo {
    names: Vec<String>,
    not_after: i64,
}

/// A local CA and its current leaf.
#[derive(Debug, Clone)]
struct Issued {
    ca_pem: String,
    leaf_pem: String,
    leaf_key: String,
    info: LeafInfo,
}

/// sensr's own certificate authority for the web GUI. With a directory it
/// persists there; without one (tests) it lives in memory.
#[derive(Debug)]
pub struct LocalCa {
    dir: Option<PathBuf>,
    state: Mutex<Option<Issued>>,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// `(year, month, day)` of a Unix time (proleptic Gregorian, UTC).
fn civil(secs: i64) -> (i32, u8, u8) {
    // Howard Hinnant's days-to-civil.
    let z = secs.div_euclid(DAY_SECS) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        i32::try_from(y).unwrap_or(9999),
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
    )
}

/// Sets `p`'s validity to the days containing `from` and `to`.
fn validity(p: &mut CertificateParams, from: i64, to: (i32, u8, u8)) {
    let (y, m, d) = civil(from);
    p.not_before = rcgen::date_time_ymd(y, m, d);
    p.not_after = rcgen::date_time_ymd(to.0, to.1, to.2);
}

/// The names a generated certificate must cover: host name, FQDN,
/// `localhost`, loopback and every static interface address.
pub fn names(doc: &Document) -> Vec<String> {
    let mut out = BTreeSet::new();
    let host = doc.system.hostname.to_string();
    out.insert(format!("{host}.{}", doc.system.domain));
    out.insert(host);
    out.insert("localhost".into());
    out.insert("127.0.0.1".into());
    out.insert("::1".into());
    for (_, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
        if let Ipv4Config::Static { address, .. } = &i.ipv4 {
            out.insert(address.addr().to_string());
        }
        if let Ipv6Config::Static { address, .. } = &i.ipv6 {
            out.insert(address.addr().to_string());
        }
    }
    out.into_iter().collect()
}

fn ca_params(not_before: i64) -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    dn.push(DnType::OrganizationName, "sensr");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (y, m, d) = civil(not_before);
    validity(&mut p, not_before - DAY_SECS, (y + CA_YEARS, m, d.min(28)));
    p
}

fn write_private(path: &Path, text: &str, mode: u32) -> Result<(), TlsError> {
    use std::io::Write;
    let io = |source| TlsError::Io {
        path: path.to_owned(),
        source,
    };
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp).map_err(io)?;
    f.write_all(text.as_bytes()).map_err(io)?;
    f.sync_all().map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

fn read(path: &Path) -> Result<Option<String>, TlsError> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(TlsError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

impl LocalCa {
    /// A CA persisted in `dir` (created 0700 on first use), or in memory.
    pub fn new(dir: Option<PathBuf>) -> Self {
        Self {
            dir,
            state: Mutex::new(None),
        }
    }

    fn load(&self) -> Result<Option<Issued>, TlsError> {
        let Some(dir) = &self.dir else {
            return Ok(None);
        };
        let (Some(ca_pem), Some(leaf_pem), Some(leaf_key), Some(info)) = (
            read(&dir.join("ca.pem"))?,
            read(&dir.join("server.pem"))?,
            read(&dir.join("server.key"))?,
            read(&dir.join("server.json"))?,
        ) else {
            return Ok(None);
        };
        let Ok(info) = serde_json::from_str(&info) else {
            return Ok(None);
        };
        Ok(Some(Issued {
            ca_pem,
            leaf_pem,
            leaf_key,
            info,
        }))
    }

    /// The CA key and certificate, created when missing.
    fn ca(&self) -> Result<(KeyPair, String), TlsError> {
        let now = now_secs();
        if let Some(dir) = &self.dir
            && let (Some(key), Some(pem)) = (read(&dir.join("ca.key"))?, read(&dir.join("ca.pem"))?)
        {
            return Ok((KeyPair::from_pem(&key).map_err(cert_err)?, pem));
        }
        let key = KeyPair::generate().map_err(cert_err)?;
        let pem = ca_params(now).self_signed(&key).map_err(cert_err)?.pem();
        if let Some(dir) = &self.dir {
            std::fs::create_dir_all(dir).map_err(|source| TlsError::Io {
                path: dir.clone(),
                source,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
            write_private(&dir.join("ca.key"), &key.serialize_pem(), 0o600)?;
            write_private(&dir.join("ca.pem"), &pem, 0o644)?;
        }
        Ok((key, pem))
    }

    fn issue(&self, names: &[String]) -> Result<Issued, TlsError> {
        let (ca_key, ca_pem) = self.ca()?;
        // The issuer is rebuilt from the same distinguished name and key, so
        // a leaf issued later still chains to the stored CA certificate.
        let issuer = Issuer::new(ca_params(now_secs()), ca_key);
        let now = now_secs();
        let mut p = CertificateParams::new(names.to_vec()).map_err(cert_err)?;
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_else(|| "sensr".into()),
        );
        p.distinguished_name = dn;
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let not_after = now + LEAF_DAYS * DAY_SECS;
        validity(&mut p, now - DAY_SECS, civil(not_after));
        let key = KeyPair::generate().map_err(cert_err)?;
        let leaf_pem = p.signed_by(&key, &issuer).map_err(cert_err)?.pem();
        let issued = Issued {
            ca_pem,
            leaf_pem,
            leaf_key: key.serialize_pem(),
            info: LeafInfo {
                names: names.to_vec(),
                not_after,
            },
        };
        if let Some(dir) = &self.dir {
            write_private(&dir.join("server.key"), &issued.leaf_key, 0o600)?;
            write_private(&dir.join("server.pem"), &issued.leaf_pem, 0o644)?;
            let info = serde_json::to_string_pretty(&issued.info).map_err(cert_err)?;
            write_private(&dir.join("server.json"), &(info + "\n"), 0o644)?;
        }
        tracing::info!(names = ?names, "issued the web GUI certificate");
        Ok(issued)
    }

    /// The current leaf for `names`, re-issued when the names changed or it
    /// expires within [`RENEW_DAYS`].
    fn current(&self, names: &[String]) -> Result<Issued, TlsError> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.is_none() {
            *state = self.load()?;
        }
        let fresh = state.as_ref().is_some_and(|s| {
            s.info.names == names && s.info.not_after - now_secs() > RENEW_DAYS * DAY_SECS
        });
        if !fresh {
            *state = Some(self.issue(names)?);
        }
        Ok(state.clone().expect("set above"))
    }

    /// Ensures the CA and a leaf for `doc` exist (first boot).
    pub fn ensure(&self, doc: &Document) -> Result<(), TlsError> {
        self.current(&names(doc)).map(|_| ())
    }

    /// The listener for `doc`: its `system.webgui` settings and the
    /// certificate to serve.
    pub fn listener(&self, doc: &Document) -> Result<WebListener, TlsError> {
        let w = &doc.system.webgui;
        let mut devices: Vec<String> = w
            .interfaces
            .iter()
            .filter_map(|id| doc.interfaces.get(id))
            .filter(|i| i.enabled)
            .map(|i| i.device.as_str().to_owned())
            .collect();
        if !devices.is_empty() {
            // Local tools and the console always reach the GUI (OPNsense
            // binds lo0 too).
            devices.insert(0, "lo".into());
            devices.dedup();
        }
        let (cert_chain_pem, key_pem, ca_pem, certificate) = match trust_certificate(doc) {
            Some(t) => (t.0, t.1, None, t.2),
            None => {
                let issued = self.current(&names(doc))?;
                (
                    issued.leaf_pem,
                    issued.leaf_key,
                    Some(issued.ca_pem),
                    "generated".to_owned(),
                )
            }
        };
        Ok(WebListener {
            https: w.https(),
            port: w.listen_port(),
            redirect_port: w.redirect_port(),
            devices,
            cert_chain_pem,
            key_pem,
            ca_pem,
            certificate,
        })
    }
}

/// `(chain, key, description)` of the trust-store certificate the web GUI
/// names, when it is usable: a PEM certificate and a key that parses.
fn trust_certificate(doc: &Document) -> Option<(String, String, String)> {
    let r = doc.system.webgui.certificate.as_ref()?;
    let c = r.resolve(&doc.trust.certificates)?;
    let cert = c.certificate.as_ref()?.to_string();
    let key = c.private_key.as_ref()?.expose().to_string();
    let usable = cert.contains("-----BEGIN CERTIFICATE-----") && KeyPair::from_pem(&key).is_ok();
    if !usable {
        tracing::warn!(
            certificate = %c.description,
            "the web GUI certificate or its key does not parse; serving the generated one"
        );
        return None;
    }
    let mut chain = cert.trim_end().to_owned() + "\n";
    // Send the issuing CA along, as lighttpd's ssl.ca-file does.
    if let Some(ca) = c
        .issuer
        .as_ref()
        .and_then(|i| i.resolve(&doc.trust.authorities))
    {
        chain += ca.certificate.to_string().trim_end();
        chain.push('\n');
    }
    Some((chain, key, c.description.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::PathAccess;
    use serde_json::json;

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(1_763_251_200), (2025, 11, 16));
        assert_eq!(civil(951_782_400), (2000, 2, 29));
    }

    #[test]
    fn names_cover_host_domain_loopback_and_static_addresses() {
        let n = names(&Document::factory());
        for want in [
            "sensr",
            "sensr.internal",
            "localhost",
            "127.0.0.1",
            "::1",
            "192.168.1.1",
        ] {
            assert!(n.iter().any(|x| x == want), "{want} in {n:?}");
        }
    }

    #[test]
    fn generates_once_persists_and_reissues_on_rename() {
        let dir = tempfile::tempdir().unwrap();
        let tls = dir.path().join("tls");
        let ca = LocalCa::new(Some(tls.clone()));
        let mut doc = Document::factory();
        let a = ca.listener(&doc).unwrap();
        assert!(a.https && a.port == 443 && a.redirect_port == Some(80));
        assert!(a.devices.is_empty(), "all interfaces by default");
        assert!(a.cert_chain_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(a.certificate, "generated");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["ca.key", "server.key"] {
                let m = std::fs::metadata(tls.join(f)).unwrap().permissions().mode();
                assert_eq!(m & 0o777, 0o600, "{f}");
            }
        }
        // A new process reads the same material.
        let again = LocalCa::new(Some(tls.clone())).listener(&doc).unwrap();
        assert_eq!(again.cert_chain_pem, a.cert_chain_pem);
        // A rename re-issues the leaf under the same CA.
        doc.system.hostname = "edge".parse().unwrap();
        let b = ca.listener(&doc).unwrap();
        assert_ne!(b.cert_chain_pem, a.cert_chain_pem);
        assert_eq!(b.ca_pem, a.ca_pem);
        let info: LeafInfo =
            serde_json::from_str(&std::fs::read_to_string(tls.join("server.json")).unwrap())
                .unwrap();
        assert!(info.names.contains(&"edge.internal".to_owned()));
    }

    #[test]
    fn listener_follows_webgui_settings() {
        let ca = LocalCa::new(None);
        let mut doc = Document::factory();
        doc.set_by_path(
            "system.webgui",
            json!({"port": "8443", "interfaces": ["lan"], "http_redirect": false}),
        )
        .unwrap();
        let l = ca.listener(&doc).unwrap();
        assert_eq!((l.port, l.redirect_port), (8443, None));
        assert_eq!(l.devices, ["lo", "eth1"]);
        assert!(!format!("{l:?}").contains("PRIVATE"), "key not in Debug");
    }

    #[test]
    fn trust_store_certificate_is_served_when_usable() {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["fw.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let mut doc = Document::factory();
        let id = "5e450000-0000-4000-8000-0000000000c1";
        doc.set_by_path(
            &format!("trust.certificates.{id}"),
            json!({"refid": "abc123", "description": "Web GUI", "certificate": cert,
                   "private_key": key.serialize_pem()}),
        )
        .unwrap();
        doc.set_by_path("system.webgui.certificate", json!(id))
            .unwrap();
        assert!(doc.validate().is_empty(), "{}", doc.validate());
        let l = LocalCa::new(None).listener(&doc).unwrap();
        assert_eq!(l.certificate, "Web GUI");
        assert_eq!(l.ca_pem, None);
        assert!(l.cert_chain_pem.starts_with(cert.trim_end()));

        // A key that does not parse falls back to the generated certificate.
        doc.set_by_path(
            &format!("trust.certificates.{id}.private_key"),
            json!("-----BEGIN PRIVATE KEY-----\nbroken\n-----END PRIVATE KEY-----\n"),
        )
        .unwrap();
        assert_eq!(
            LocalCa::new(None).listener(&doc).unwrap().certificate,
            "generated"
        );
    }
}
