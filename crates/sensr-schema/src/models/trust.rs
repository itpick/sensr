//! The trust store: certificate authorities and certificates (OPNsense
//! `Trust/Ca.xml` and `Trust/Cert.xml`, the `ca` and `cert` sections).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::array::{ArrayField, Relation};
use crate::fields::{Description, Pem, Secret};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Authorities and certificates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    /// Certificate authorities (local or imported).
    #[serde(default)]
    pub authorities: ArrayField<CertAuthority>,
    /// Server and client certificates.
    #[serde(default)]
    pub certificates: ArrayField<Certificate>,
}

/// A certificate authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CertAuthority {
    /// OPNsense reference id, kept so imported references and exports match.
    pub refid: String,
    /// Display name.
    pub description: Description,
    /// The CA certificate.
    pub certificate: Pem,
    /// Its private key, when this box signs with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Secret<Pem>>,
    /// Next serial number to issue.
    #[serde(default)]
    pub serial: u64,
    /// The authority that signed this one (intermediate CAs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Relation<CertAuthority>>,
}

/// A certificate, or a pending signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    /// OPNsense reference id, kept so imported references and exports match.
    pub refid: String,
    /// Display name.
    pub description: Description,
    /// The certificate; `None` while only a request exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Pem>,
    /// A certificate signing request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Pem>,
    /// The private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Secret<Pem>>,
    /// The local authority that issued it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Relation<CertAuthority>>,
}

fn valid_refid(r: &str) -> bool {
    !r.is_empty() && r.len() <= 64 && r.bytes().all(|b| b.is_ascii_alphanumeric())
}

impl Validate for Trust {
    fn validate(&self, _ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let cas = at.join("authorities");
        let certs = at.join("certificates");
        let mut refids = std::collections::HashSet::new();
        let entries = self
            .authorities
            .iter()
            .map(|(id, c)| (cas.join(id), &c.refid, c.issuer.as_ref()))
            .chain(
                self.certificates
                    .iter()
                    .map(|(id, c)| (certs.join(id), &c.refid, c.issuer.as_ref())),
            );
        for (p, refid, issuer) in entries {
            if !valid_refid(refid) {
                out.add(
                    &p.join("refid"),
                    ValidatorKind::Regex,
                    "A reference id must be 1 to 64 letters or digits.",
                );
            } else if !refids.insert(refid.as_str()) {
                out.add(
                    &p.join("refid"),
                    ValidatorKind::Constraint,
                    "This reference id is already in use.",
                );
            }
            if let Some(i) = issuer
                && i.resolve(&self.authorities).is_none()
            {
                out.add(
                    &p.join("issuer"),
                    ValidatorKind::Callback,
                    "The issuing certificate authority does not exist.",
                );
            }
        }
        for (id, c) in &self.certificates {
            if c.certificate.is_none() && c.request.is_none() {
                out.add(
                    &certs.join(id).join("certificate"),
                    ValidatorKind::PresenceOf,
                    "A certificate or a signing request is required.",
                );
            }
        }
    }
}
