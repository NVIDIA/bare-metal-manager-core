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

use gtmpl_derive::Gtmpl;

pub const PATH: &str = "etc/cumulus/acl/policy.d/60-forge.rules";
const TEMPLATE: &str = include_str!("../templates/forge-acl-rules");
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
    let values = AclTemplateValues {
        IngressInterfaces: conf.ingress_interfaces,
        DenyPrefixes: conf.deny_prefixes,
    };
    let rendered = gtmpl::template(TEMPLATE, values)?;
    Ok(rendered)
}

#[allow(non_snake_case)]
#[derive(Gtmpl)]
struct AclTemplateValues {
    pub IngressInterfaces: Vec<String>,
    pub DenyPrefixes: Vec<String>,
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
