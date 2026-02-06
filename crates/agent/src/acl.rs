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
use std::fmt::Display;

use ipnetwork::Ipv4Network;

// A representation of a rules file that can be placed in the policy.d
// directory
pub struct RulesFile {
    iptables_rules: IpTablesRuleset,
}

impl RulesFile {
    pub fn new(iptables_rules: IpTablesRuleset) -> Self {
        Self { iptables_rules }
    }
}

// FIXME: Display is probably not quite the right interface to implement
// here but it's reasonably convenient for producing the format we write to
// a file.
impl Display for RulesFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "# This file is managed by the Forge DPU agent.")?;
        writeln!(f)?;
        write!(f, "{}", self.iptables_rules)
    }
}

// The ordered rules that live within an `[iptables]` section.
pub struct IpTablesRuleset {
    rules: Vec<IpTablesRule>,
}

impl IpTablesRuleset {
    pub fn new_with_rules(rules: Vec<IpTablesRule>) -> Self {
        Self { rules }
    }
}

impl Display for IpTablesRuleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[iptables]")?;
        self.rules.iter().try_for_each(|rule| writeln!(f, "{rule}"))
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpTablesRule {
    // INPUT, FORWARD, etc
    chain: Chain,

    // ACCEPT, DROP, etc
    jump_target: Target,

    ingress_interface: Option<String>,
    egress_interface: Option<String>,

    destination_prefix: Option<Ipv4Network>,
    destination_port: Option<u32>,

    protocol: Option<&'static str>,

    comment_before: Option<String>,
}

impl IpTablesRule {
    pub fn new(chain: Chain, jump_target: Target) -> Self {
        IpTablesRule {
            chain,
            jump_target,
            ..Default::default()
        }
    }

    pub fn set_ingress_interface(&mut self, interface: String) {
        self.ingress_interface = Some(interface)
    }

    pub fn set_egress_interface(&mut self, interface: String) {
        self.egress_interface = Some(interface)
    }

    pub fn set_destination_prefix(&mut self, prefix: Ipv4Network) {
        self.destination_prefix = Some(prefix)
    }

    pub fn set_destination_port(&mut self, port: u32) {
        self.destination_port = Some(port);
    }

    pub fn set_protocol(&mut self, protocol: &'static str) {
        self.protocol = Some(protocol);
    }

    pub fn set_comment_before(&mut self, comment: String) {
        self.comment_before = Some(comment)
    }
}

impl Display for IpTablesRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(comment) = self.comment_before.as_ref() {
            writeln!(f, "# {comment}")?;
        }

        write!(f, "-A {}", self.chain)?;

        if let Some(interface) = self.ingress_interface.as_ref() {
            write!(f, " -i {interface}")?;
        }

        if let Some(interface) = self.egress_interface.as_ref() {
            write!(f, " -o {interface}")?;
        }

        if let Some(protocol) = self.protocol {
            write!(f, " -p {protocol}")?;
        }

        if let Some(destination) = self.destination_prefix.as_ref() {
            write!(f, " -d {destination}")?;
        }

        if let Some(dport) = self.destination_port {
            write!(f, " --dport {dport}")?;
        }

        write!(f, " -j {}", self.jump_target)?;

        Ok(())
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub enum Chain {
    #[default]
    Forward,
    Input,
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Forward => write!(f, "FORWARD"),
            Chain::Input => write!(f, "INPUT"),
        }
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub enum Target {
    #[default]
    Accept,
    Drop,
}

impl Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Accept => write!(f, "ACCEPT"),
            Target::Drop => write!(f, "DROP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_outputs() {
        let mut rule = IpTablesRule::new(Chain::Forward, Target::Drop);

        let output = format!("{rule}");
        assert_eq!(output.as_str(), "-A FORWARD -j DROP");

        rule.set_ingress_interface("in1".to_string());
        let output = format!("{rule}");
        assert_eq!(output.as_str(), "-A FORWARD -i in1 -j DROP");

        rule.set_destination_prefix("192.0.2.0/24".parse().unwrap());
        let output = format!("{rule}");
        assert_eq!(output.as_str(), "-A FORWARD -i in1 -d 192.0.2.0/24 -j DROP");

        rule.set_egress_interface("out1".to_string());
        let output = format!("{rule}");
        assert_eq!(
            output.as_str(),
            "-A FORWARD -i in1 -o out1 -d 192.0.2.0/24 -j DROP"
        );
    }
}
