//! Rule registration, the counterpart of `Plugin::registerFilterRule`.

use crate::conf::{Conf, calc_rule_hash};
use crate::ir::FilterRule;
use crate::normalize::{self, Context};

/// Collects filter rules the way upstream's firewall plugin does.
#[derive(Clone, Debug, Default)]
pub struct Ruleset {
    /// settings-derived defaults merged under every rule
    /// (`disablereplyto`, `skip_rules_gw_down`)
    pub system_defaults: Conf,
    /// expanded rules in registration order
    pub rules: Vec<FilterRule>,
}

impl Ruleset {
    /// Registers one rule array at `prio`, merging `defaults` underneath and
    /// labelling it with `calcRuleHash` when it has no label.
    pub fn register_filter(
        &mut self,
        prio: u32,
        conf: &Conf,
        defaults: Option<&Conf>,
        ctx: &Context<'_>,
    ) {
        let mut c = self.system_defaults.merged_with(conf);
        if let Some(d) = defaults {
            c = d.merged_with(&c);
        }
        if c.is_empty_at("label") {
            let label = calc_rule_hash(&c);
            c.set("label", label);
        }
        self.rules.extend(normalize::filter_rule(&c, prio, ctx));
    }
}
