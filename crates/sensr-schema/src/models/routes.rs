//! Static routes (OPNsense `Routes/Route.xml`, mounted at `staticroutes`).

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::yes;
use crate::array::ArrayField;
use crate::fields::{Description, GatewayName, IpFamily};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Static routes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Routes {
    /// Routes, in order.
    #[serde(default)]
    pub routes: ArrayField<StaticRoute>,
}

impl Routes {
    /// True when no routes are configured.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// One static route: traffic for `network` goes to `gateway`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticRoute {
    /// Installed when true.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Destination network.
    #[schemars(with = "String")]
    pub network: IpNet,
    /// Next hop: a gateway by name.
    pub gateway: GatewayName,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

const GATEWAY_FAMILY: &str =
    "Specify a valid gateway from the list matching the networks ip protocol.";

impl Validate for Routes {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let at = at.join("routes");
        let mut seen = std::collections::HashMap::new();
        for (id, r) in &self.routes {
            let p = at.join(id);
            if !ctx.has_gateway(&r.gateway) {
                out.add(&p.join("gateway"), ValidatorKind::Callback, GATEWAY_FAMILY);
            } else if let Some(family) = ctx.gateway_family(&r.gateway) {
                // An IPv6 next hop for an IPv4 network is RFC 5549 and allowed;
                // the reverse is not.
                let ok = match r.network {
                    IpNet::V4(_) => family != IpFamily::Inet46,
                    IpNet::V6(_) => family == IpFamily::Inet6,
                };
                if !ok {
                    out.add(&p.join("gateway"), ValidatorKind::Callback, GATEWAY_FAMILY);
                }
            }
            if r.network != r.network.trunc() {
                out.add(
                    &p.join("network"),
                    ValidatorKind::Callback,
                    "Specify a valid network matching the gateways ip protocol.",
                );
            }
            if r.enabled
                && let Some(first) = seen.insert(r.network.trunc(), *id)
            {
                out.add(
                    &p.join("network"),
                    ValidatorKind::Constraint,
                    format!(
                        "Network {} already has a route (item {first}).",
                        r.network.trunc()
                    ),
                );
            }
        }
    }
}
