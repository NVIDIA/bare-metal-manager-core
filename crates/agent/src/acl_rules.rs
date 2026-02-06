/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::BTreeMap;

use ipnetwork::Ipv4Network;

use crate::acl::{Chain, IpTablesRule, IpTablesRuleset, RulesFile, Target};

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

    let mut file_contents = rules_file.to_string();
    append_arp_suppression_contents(&mut file_contents);
    Ok(file_contents)
}

fn make_forge_rules(acl_config: AclConfig) -> IpTablesRuleset {
    let mut rules: Vec<IpTablesRule> = Vec::new();

    let deny_prefixes: Vec<Ipv4Network> = acl_config
        .deny_prefixes
        .iter()
        .map(|prefix| prefix.parse().unwrap())
        .collect();

    // Generate the rules for each tenant interface.
    rules.extend(
        acl_config
            .interfaces
            .iter()
            .flat_map(|(if_name, if_rules)| {
                make_forge_interface_rules(
                    if_name,
                    if_rules.vpc_prefixes.as_slice(),
                    deny_prefixes.as_slice(),
                )
            }),
    );

    rules.push(make_block_nvued_rule());

    IpTablesRuleset::new_with_rules(rules)
}

// Create the Forge ruleset for a specific tenant-facing interface.
fn make_forge_interface_rules(
    interface_name: &str,
    vpc_prefixes: &[Ipv4Network],
    deny_prefixes: &[Ipv4Network],
) -> Vec<IpTablesRule> {
    let mut rules = Vec::new();
    rules.extend(make_vpc_rules(interface_name, vpc_prefixes));
    rules.extend(make_deny_prefix_rules(
        interface_name,
        deny_prefixes,
        vpc_prefixes,
    ));
    rules
}

fn make_block_nvued_rule() -> IpTablesRule {
    let mut r = IpTablesRule::new(Chain::Input, Target::Drop);
    r.set_destination_port(8765);
    r.set_protocol("tcp");
    r.set_comment_before("Block access to nvued API".to_string());
    r
}

// Generate rules allowing the instance on the other side of this interface to
// send packets to the prefixes associated with its VPC.
fn make_vpc_rules(interface_name: &str, vpc_prefixes: &[Ipv4Network]) -> Vec<IpTablesRule> {
    let vpc_base_rule = IpTablesRule::new(Chain::Forward, Target::Accept);
    let mut rules: Vec<_> = vpc_prefixes
        .iter()
        .map(|prefix| {
            let mut rule = vpc_base_rule.clone();
            rule.set_ingress_interface(interface_name.to_string());
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

// Generate rules denying traffic to the deny_prefixes list. We also check the
// vpc_prefixes list for this interface so that we can skip denying a prefix if
// it has already been allowed in its entirety (this avoids an HBN 1.5 bug).
fn make_deny_prefix_rules(
    interface_name: &str,
    deny_prefixes: &[Ipv4Network],
    vpc_prefixes: &[Ipv4Network],
) -> Vec<IpTablesRule> {
    let deny_base_rule = IpTablesRule::new(Chain::Forward, Target::Drop);
    let mut rules: Vec<_> = deny_prefixes
        .iter()
        .filter_map(|deny_prefix| {
            let is_not_vpc_prefix = !vpc_prefixes.contains(deny_prefix);
            // We will only emit a drop rule if this prefix has not been
            // used in a VPC network segment already (which would correspond
            // to an earlier ACCEPT rule). If we emit the same prefix as both
            // an ACCEPT and DROP, HBN 1.5 may process them in the wrong order.
            is_not_vpc_prefix.then(|| {
                let mut rule = deny_base_rule.clone();
                rule.set_ingress_interface(interface_name.to_owned());
                rule.set_destination_prefix(deny_prefix.to_owned());
                rule
            })
        })
        .collect();
    if let Some(first_rule) = rules.first_mut() {
        let comment =
            format!("Drop traffic to deny_prefix list for tenant interface {interface_name}");
        first_rule.set_comment_before(comment);
    }
    rules
}

fn append_arp_suppression_contents(file_buffer: &mut String) {
    file_buffer.push_str(ARP_SUPPRESSION_RULE);
}

pub const ARP_SUPPRESSION_RULE: &str = r"
[ebtables]
# Suppress ARP packets before they get encapsulated.
-A OUTPUT -o vxlan48 -p ARP -j DROP
";

#[cfg(test)]
mod tests {
    use super::{AclConfig, BTreeMap, InterfaceRules, Ipv4Network, build};

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

    #[test]
    // Check that when an entire site prefix is used in one network segment, we
    // don't emit both an ACCEPT and DROP rule.
    fn test_whole_site_prefix_in_single_segment() -> Result<(), Box<dyn std::error::Error>> {
        let interface = String::from("net1");
        let site_prefix: Ipv4Network = "192.0.2.0/24".parse().unwrap();
        let deny_prefixes = vec![
            site_prefix.to_string(),
            "198.51.100.0/24".into(),
            "203.0.113.0/24".into(),
        ];
        let interface_rules = InterfaceRules {
            vpc_prefixes: vec![site_prefix],
        };
        let interfaces = BTreeMap::from([(interface, interface_rules)]);
        let params = AclConfig {
            interfaces,
            deny_prefixes,
        };
        let output = build(params)?;
        let expected = include_str!(
            "../templates/tests/acl_rules_whole_site_prefix_in_single_segment.expected"
        );
        let r = crate::util::compare_lines(output.as_str(), expected, None);
        eprint!("Diff output:\n{}", r.report());
        assert!(r.is_identical());

        Ok(())
    }
}
