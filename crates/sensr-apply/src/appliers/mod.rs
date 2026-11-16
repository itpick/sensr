//! Appliers for the routing vertical slice. Each takes a typed input model,
//! renders deterministic output (golden-tested), contributes to a
//! [`crate::plan::Plan`] so an unchanged model is a no-op, and runs its
//! backend's checker before anything goes live.
//!
//! Inputs are `sensr_schema` types resolved against the whole document
//! (devices for interface ids, Kea subnet ids, secrets as files):
//! [`SliceModels::from_document`] in [`convert`] builds them.
//!
//! Real-checker tests (`nft -c`, `kea-dhcp4 -t`, `unbound-checkconf`) skip
//! with a note when the tool is absent. To run them, e.g. on nixtop:
//! `nix shell nixpkgs#nftables nixpkgs#kea nixpkgs#unbound -c cargo test -p sensr-apply`.

pub mod convert;
pub mod interfaces;
pub mod kea;
pub mod nft;
pub mod qdisc;
pub mod sysctl;
pub mod unbound;
pub mod wireguard;

use crate::plan::{FileSpec, Plan, UnitAction, UnitSpec};
use crate::templates::{Staging, TemplateError, Templates};

/// Where the Kea config is rendered (the NixOS unit points `-c` here).
pub const KEA_CONF: &str = "run/sensr/kea/kea-dhcp4.conf";

/// The slice's typed inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SliceModels {
    /// Kernel tunables.
    pub sysctl: sysctl::SysctlModel,
    /// Queueing.
    pub qdisc: qdisc::QdiscModel,
    /// DHCPv4 server (`None`: disabled).
    pub kea: Option<kea::Dhcp4Model>,
    /// Resolver (`None`: disabled).
    pub unbound: Option<unbound::UnboundModel>,
    /// Tunnels.
    pub wireguard: wireguard::WireguardModel,
}

/// Failure to build the slice plan.
#[derive(Debug, thiserror::Error)]
pub enum SliceError {
    /// Sysctl model.
    #[error(transparent)]
    Sysctl(#[from] sysctl::SysctlError),
    /// Kea model.
    #[error(transparent)]
    Kea(#[from] kea::KeaError),
    /// Template rendering.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// WireGuard model/rendering.
    #[error(transparent)]
    Wireguard(#[from] wireguard::RenderError),
    /// Unbound model/rendering.
    #[error(transparent)]
    Unbound(#[from] unbound::RenderError),
    /// The nft ruleset writer.
    #[error("rendering the ruleset: {0}")]
    Nft(#[from] std::io::Error),
}

impl SliceModels {
    /// The desired-state plan for the slice. Diff it against the last applied
    /// plan to get the work; an unchanged model yields an empty delta.
    pub fn plan<R: nft::NftRuleset + ?Sized>(
        &self,
        templates: &Templates,
        staging: &Staging,
        ruleset: Option<(&R, &str)>,
    ) -> Result<Plan, SliceError> {
        let mut p = Plan::default();
        if let Some((rs, summary)) = ruleset {
            p.nft = Some(nft::plan_spec(rs, summary)?);
        }
        p.sysctls = self.sysctl.to_map()?;
        p.sysctls.extend(self.qdisc.sysctls());
        p.qdiscs = self.qdisc.plan_entries();
        if let Some(k) = &self.kea {
            let path = staging.live_dir(KEA_CONF);
            p.files.insert(
                path.clone(),
                FileSpec {
                    contents: k.render()?.into_bytes(),
                    mode: 0o644,
                },
            );
            p.units.insert(
                "kea-dhcp4-server.service".into(),
                UnitSpec {
                    action: UnitAction::Reload,
                    inputs: [path].into(),
                },
            );
        }
        if let Some(u) = &self.unbound {
            let files = staging.plan_files(&u.render(templates)?);
            p.units.insert(
                "unbound.service".into(),
                UnitSpec {
                    action: UnitAction::Reload,
                    inputs: files.keys().cloned().collect(),
                },
            );
            p.files.extend(files);
        }
        // networkd is driven by `WireguardModel::commands`, not a unit
        // reload, but its files still take part in the diff.
        p.files
            .extend(staging.plan_files(&self.wireguard.render(templates)?));
        p.hooks.insert(crate::hooks::HookLevel::Config);
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn models() -> SliceModels {
        convert::tests::slice_models()
    }

    #[test]
    fn slice_plan_golden_and_idempotent() {
        let t = Templates::builtin().unwrap();
        let s = Staging::new("/");
        let rs = br#"{"nftables":[]}"#.to_vec();
        let p = models().plan(&t, &s, Some((&rs, "0 rules"))).unwrap();
        assert!(p.diff(&p).is_empty());
        let again = models().plan(&t, &s, Some((&rs, "0 rules"))).unwrap();
        assert_eq!(p, again, "deterministic");
        insta::assert_snapshot!(p.diff(&Plan::default()).dry_run(&Plan::default()));

        // Changing only DHCP touches only Kea.
        let mut m = models();
        if let Some(k) = m.kea.as_mut() {
            k.valid_lifetime = 7200;
        }
        let d = m.plan(&t, &s, Some((&rs, "0 rules"))).unwrap().diff(&p);
        assert_eq!(d.files.len(), 1);
        assert_eq!(
            d.units.keys().collect::<Vec<_>>(),
            ["kea-dhcp4-server.service"]
        );
        assert!(d.nft.is_none() && d.sysctls.is_empty());
    }
}
