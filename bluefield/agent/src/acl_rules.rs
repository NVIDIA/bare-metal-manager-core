/*
 *   SPDX-FileCopyrightText: Copyright (c) 2023-2023. NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *   SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 *   NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 *   property and proprietary rights in and to this material, related
 *   documentation and any modifications thereto. Any use, reproduction,
 *   disclosure or distribution of this material and related documentation
 *   without an express license agreement from NVIDIA CORPORATION or
 *   its affiliates is strictly prohibited.
 */

use std::rc::Rc;

use ipnetwork::Ipv4Network;

use crate::config_model::acl::{chain, target};
use crate::config_model::acl::{IpTablesRule, IpTablesRuleset, RulesFile};

pub const PATH: &str = "etc/cumulus/acl/policy.d/60-forge.rules";
pub const RELOAD_CMD: &str = "cl-acltool -i";

pub struct AclConfig {
    // The interface these rules will be matched against. Should be the
    // interface that packets from our attached compute node/x86 machine appear
    // on.
    pub ingress_interfaces: Vec<String>,

    // The prefixes the instance is not allowed to talk to.
    pub deny_prefixes: Vec<String>,
}

/// Generate /etc/cumulus/acl/policy.d/60-forge.rules
pub fn build(conf: AclConfig) -> Result<String, eyre::Report> {
    let iptables_rules = make_forge_rules(conf);
    let rules_file = RulesFile::new(iptables_rules);

    let file_contents = rules_file.to_string();

    // eprintln!("{}", &file_contents);

    Ok(file_contents)
}

fn make_forge_rules(acl_config: AclConfig) -> IpTablesRuleset {
    let mut rules: Vec<IpTablesRule> = Vec::new();

    let tenant_interfaces: Vec<_> = acl_config
        .ingress_interfaces
        .iter()
        .map(|if_name| Rc::<str>::from(if_name.as_str()))
        .collect();

    let deny_prefixes: Vec<Ipv4Network> = acl_config
        .deny_prefixes
        .iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();

    rules.extend(make_deny_prefix_rules(
        tenant_interfaces.as_slice(),
        deny_prefixes.as_slice(),
    ));

    IpTablesRuleset::new_with_rules(rules)
}

fn make_deny_prefix_rules(
    tenant_interface_names: &[Rc<str>],
    deny_prefixes: &[Ipv4Network],
) -> Vec<IpTablesRule> {
    let deny_base_rule = IpTablesRule::new(chain::FORWARD, target::DROP);
    let mut rules: Vec<_> = deny_prefixes
        .iter()
        .flat_map(|prefix| {
            tenant_interface_names
                .iter()
                .cloned()
                .map(|interface_name| {
                    let mut rule = deny_base_rule.clone();
                    rule.set_ingress_interface(interface_name.clone());
                    rule.set_destination_prefix(prefix.to_owned());
                    rule
                })
        })
        .collect();
    if let Some(first_rule) = rules.first_mut() {
        let comment = String::from("Drop traffic to deny_prefix list");
        first_rule.set_comment_before(comment);
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::{build, AclConfig};

    #[test]
    fn test_write_acl() -> Result<(), Box<dyn std::error::Error>> {
        let params = AclConfig {
            ingress_interfaces: vec!["net1".into(), "net2".into()],
            deny_prefixes: vec![
                "192.0.2.0/24".into(),
                "198.51.100.0/24".into(),
                "203.0.113.0/24".into(),
            ],
        };
        let output = build(params)?;
        let expected = include_str!("../templates/tests/acl_rules.expected");
        let r = crate::util::compare_lines(output.as_str(), expected, None);
        eprint!("Diff output:\n{}", r.report());
        assert!(r.is_identical());

        Ok(())
    }
}
