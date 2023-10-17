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

pub mod acl {
    use std::fmt::Display;
    use std::rc::Rc;

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

    #[derive(Clone, Debug)]
    pub struct IpTablesRule {
        // INPUT, FORWARD, etc
        chain: Rc<str>,

        // ACCEPT, DROP, etc
        jump_target: Rc<str>,

        ingress_interface: Option<Rc<str>>,
        egress_interface: Option<Rc<str>>,

        destination_prefix: Option<Ipv4Network>,

        comment_before: Option<String>,
    }

    impl IpTablesRule {
        pub fn new<T>(chain: T, jump_target: T) -> Self
        where
            T: Into<Rc<str>>,
        {
            let chain: Rc<str> = chain.into();
            let jump_target = jump_target.into();
            let ingress_interface = None;
            let egress_interface = None;
            let destination_prefix = None;
            let comment_before = None;
            IpTablesRule {
                chain,
                jump_target,
                ingress_interface,
                egress_interface,
                destination_prefix,
                comment_before,
            }
        }

        pub fn set_ingress_interface(&mut self, interface: Rc<str>) {
            self.ingress_interface = Some(interface)
        }

        pub fn set_egress_interface(&mut self, interface: Rc<str>) {
            self.egress_interface = Some(interface)
        }

        pub fn set_destination_prefix(&mut self, prefix: Ipv4Network) {
            self.destination_prefix = Some(prefix)
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

            if let Some(destination) = self.destination_prefix.as_ref() {
                write!(f, " -d {destination}")?;
            }

            write!(f, " -j {}", self.jump_target)?;

            Ok(())
        }
    }

    pub mod chain {
        pub const FORWARD: &str = "FORWARD";
    }

    pub mod target {
        pub const ACCEPT: &str = "ACCEPT";
        pub const DROP: &str = "DROP";
    }
}
