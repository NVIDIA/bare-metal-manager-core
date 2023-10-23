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

use std::collections::BTreeMap;
use std::rc::Rc;

use ipnetwork::Ipv4Network;

use crate::config_model::acl::{chain, target};
use crate::config_model::acl::{IpTablesRule, IpTablesRuleset, RulesFile};

pub const PATH: &str = "etc/cumulus/acl/policy.d/60-forge.rules";
pub const RELOAD_CMD: &str = "cl-acltool -i";

pub struct AclConfig {
    // Per-interface ACL config.
    pub interfaces: BTreeMap<String, InterfaceRules>,

    // The prefixes the instance is not allowed to talk to.
    pub deny_prefixes: Vec<String>,
}

pub struct InterfaceRules {
    // All of the prefixes associated with this VPC.
    pub vpc_prefixes: Vec<Ipv4Network>,
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

    // Add VPC allow rules.
    rules.extend(
        acl_config
            .interfaces
            .iter()
            .flat_map(|(if_name, if_rules)| {
                let if_name: Rc<str> = Rc::from(if_name.as_str());
                make_vpc_rules(if_name, if_rules.vpc_prefixes.as_slice())
            }),
    );

    let tenant_interfaces: Vec<_> = acl_config
        .interfaces
        .keys()
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

// Generate rules allowing the instance on the other side of this interface to
// send packets to the prefixes associated with its VPC.
fn make_vpc_rules(interface_name: Rc<str>, vpc_prefixes: &[Ipv4Network]) -> Vec<IpTablesRule> {
    let vpc_base_rule = IpTablesRule::new(chain::FORWARD, target::ACCEPT);
    let mut rules: Vec<_> = vpc_prefixes
        .iter()
        .map(|prefix| {
            let mut rule = vpc_base_rule.clone();
            rule.set_ingress_interface(interface_name.clone());
            rule.set_destination_prefix(prefix.to_owned());
            rule
        })
        .collect();
    if let Some(first_rule) = rules.first_mut() {
        let comment =
            format!("Allow associated VPC prefixes for tenant interface {interface_name}");
        first_rule.set_comment_before(comment);
    }
    rules
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
    use super::Ipv4Network;
    use super::{build, AclConfig, InterfaceRules};

    #[test]
    fn test_write_acl() -> Result<(), Box<dyn std::error::Error>> {
        let interface_vpc_networks = [("net1", "192.0.2.8/29"), ("net2", "192.0.2.16/29")];
        let params = AclConfig {
            interfaces: interface_vpc_networks
                .into_iter()
                .map(|(if_name, vpc_prefix)| {
                    let if_name = String::from(if_name);
                    let vpc_prefix: Ipv4Network = vpc_prefix.parse().unwrap();
                    let if_rules = InterfaceRules {
                        vpc_prefixes: vec![vpc_prefix],
                    };
                    (if_name, if_rules)
                })
                .collect(),

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
