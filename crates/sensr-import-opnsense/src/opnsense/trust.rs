//! `ca` and `cert`: the trust store (legacy-mapped `Trust/Ca` and `Trust/Cert`
//! models). Certificates and keys are stored base64-encoded PEM in OPNsense.

use std::collections::HashMap;

use base64::Engine as _;
use sensr_schema::array::Relation;
use sensr_schema::fields::{Pem, Secret};
use sensr_schema::models::trust::{CertAuthority, Certificate};
use sensr_schema::{Document, Uuid};

use super::common::{description, item_uuid};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as XmlDocument, Element};

pub struct TrustMapper;

impl Mapper<Document> for TrustMapper {
    fn name(&self) -> &'static str {
        "trust"
    }

    fn sections(&self) -> &'static [&'static str] {
        // Mapped in finish(): certificates name their issuer by refid, so every CA
        // must be known first.
        &["ca", "cert"]
    }

    fn map<'doc>(&self, _: &'doc Element, _: &mut MapContext<'doc>, _: &mut Document) {}

    fn finish<'doc>(&self, doc: &'doc XmlDocument, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let mut by_refid: HashMap<String, Uuid> = HashMap::new();
        let mut cas = Vec::new();
        for c in doc.root.children_named("ca") {
            ctx.consume(c);
            match authority(c, ctx) {
                Some((id, ca, caref)) => {
                    by_refid.insert(ca.refid.clone(), id);
                    cas.push((c, id, ca, caref));
                }
                None => ctx.release(c),
            }
        }
        for (c, id, mut ca, caref) in cas {
            ca.issuer = issuer(ctx, c, caref, &by_refid);
            out.trust.authorities.insert(id, ca);
        }
        for c in doc.root.children_named("cert") {
            ctx.consume(c);
            match certificate(c, ctx, &by_refid) {
                Some((id, cert)) => {
                    out.trust.certificates.insert(id, cert);
                }
                None => ctx.release(c),
            }
        }
        webgui_certificate(doc, ctx, out);
    }
}

/// `system/webgui/ssl-certref`: the web GUI's certificate, by refid. A
/// certificate without its key cannot serve TLS; the listener then uses
/// sensr's own self-signed certificate.
fn webgui_certificate<'doc>(
    doc: &'doc XmlDocument,
    ctx: &mut MapContext<'doc>,
    out: &mut Document,
) {
    let Some(el) = doc
        .root
        .child("system")
        .and_then(|s| s.child("webgui"))
        .and_then(|w| w.child("ssl-certref"))
    else {
        return;
    };
    ctx.consume(el);
    let refid = el.text();
    let refid = refid.trim();
    if refid.is_empty() {
        return;
    }
    let found = out
        .trust
        .certificates
        .iter()
        .find(|(_, c)| c.refid == refid)
        .map(|(id, c)| (*id, c.certificate.is_some() && c.private_key.is_some()));
    match found {
        Some((id, true)) => out.system.webgui.certificate = Some(Relation::new(id)),
        Some((_, false)) => ctx.warn(
            el,
            Severity::Invalid,
            format!("web GUI certificate {refid} has no certificate or key; sensr's self-signed certificate is used"),
        ),
        None => ctx.warn(
            el,
            Severity::Invalid,
            format!("web GUI certificate {refid} is not in the trust store; sensr's self-signed certificate is used"),
        ),
    }
}

/// Decode a base64-wrapped PEM field; empty means absent.
fn pem<'doc>(
    ctx: &mut MapContext<'doc>,
    parent: &'doc Element,
    name: &str,
) -> Result<Option<Pem>, ()> {
    let Some(e) = parent.child(name) else {
        return Ok(None);
    };
    ctx.consume(e);
    let raw = e.text();
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    match decoded.map(|t| t.parse::<Pem>()) {
        Some(Ok(p)) => Ok(Some(p)),
        _ => {
            ctx.warn(
                e,
                Severity::Invalid,
                format!("{name} is not base64-encoded PEM; not imported"),
            );
            Err(())
        }
    }
}

fn issuer<'doc>(
    ctx: &mut MapContext<'doc>,
    at: &'doc Element,
    caref: Option<String>,
    by_refid: &HashMap<String, Uuid>,
) -> Option<Relation<CertAuthority>> {
    let r = caref?;
    match by_refid.get(&r) {
        Some(u) => Some(Relation::new(*u)),
        None => {
            ctx.warn(
                at,
                Severity::Degraded,
                format!("issuer {r} is not in the trust store; link dropped"),
            );
            None
        }
    }
}

type Staged = (Uuid, CertAuthority, Option<String>);

fn authority<'doc>(c: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<Staged> {
    let id = item_uuid(ctx, c);
    let refid = ctx.non_empty(c, "refid")?;
    let descr = ctx.text(c, "descr");
    let description = description(ctx, c, descr)?;
    let certificate = pem(ctx, c, "crt").ok()??;
    let private_key = pem(ctx, c, "prv").ok()?.map(Secret::new);
    let serial = ctx.parse::<u64>(c, "serial").unwrap_or(0);
    let caref = ctx.non_empty(c, "caref");
    Some((
        id,
        CertAuthority {
            refid,
            description,
            certificate,
            private_key,
            serial,
            issuer: None,
        },
        caref,
    ))
}

fn certificate<'doc>(
    c: &'doc Element,
    ctx: &mut MapContext<'doc>,
    by_refid: &HashMap<String, Uuid>,
) -> Option<(Uuid, Certificate)> {
    let id = item_uuid(ctx, c);
    let refid = ctx.non_empty(c, "refid")?;
    let descr = ctx.text(c, "descr");
    let description = description(ctx, c, descr)?;
    let certificate = pem(ctx, c, "crt").ok()?;
    let request = pem(ctx, c, "csr").ok()?;
    if certificate.is_none() && request.is_none() {
        ctx.warn(
            c,
            Severity::Invalid,
            "certificate without a certificate or signing request not imported",
        );
        return None;
    }
    let private_key = pem(ctx, c, "prv").ok()?.map(Secret::new);
    let caref = ctx.non_empty(c, "caref");
    Some((
        id,
        Certificate {
            refid,
            description,
            certificate,
            request,
            private_key,
            issuer: issuer(ctx, c, caref, by_refid),
        },
    ))
}
