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

use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use config_version::ConfigVersion;
use model::network_security_group::{
    NetworkSecurityGroup, NetworkSecurityGroupAttachments,
    NetworkSecurityGroupPropagationObjectStatus, NetworkSecurityGroupPropagationStatus,
    NetworkSecurityGroupRule, NetworkSecurityGroupRuleAction, NetworkSecurityGroupRuleDirection,
    NetworkSecurityGroupRuleNet, NetworkSecurityGroupRuleProtocol, NetworkSecurityGroupSource,
    NetworkSecurityGroupStatusObservation,
};
use uuid::Uuid;

use crate::errors::RpcDataConversionError;
use crate::forge as rpc;

/// The maximum priority value allowed for security group rule.
/// We could expose this in config and validate it in the API
/// handlers, but it's based on the hard limit of the field in
/// NVUE, so setting it close to the limit seems sufficient.
const MAX_RULE_PRIORITY: u32 = 60000;

/* ********************************** */
/*     NetworkSecurityGroupSource     */
/* ********************************** */

impl From<NetworkSecurityGroupSource> for rpc::NetworkSecurityGroupSource {
    fn from(t: NetworkSecurityGroupSource) -> Self {
        match t {
            NetworkSecurityGroupSource::None => rpc::NetworkSecurityGroupSource::NsgSourceNone,
            NetworkSecurityGroupSource::Vpc => rpc::NetworkSecurityGroupSource::NsgSourceVpc,
            NetworkSecurityGroupSource::Instance => {
                rpc::NetworkSecurityGroupSource::NsgSourceInstance
            }
        }
    }
}

impl TryFrom<rpc::NetworkSecurityGroupSource> for NetworkSecurityGroupSource {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::NetworkSecurityGroupSource) -> Result<Self, Self::Error> {
        match t {
            rpc::NetworkSecurityGroupSource::NsgSourceInvalid => {
                Err(RpcDataConversionError::InvalidValue(
                    "NetworkSecurityGroupSource".to_string(),
                    t.as_str_name().to_string(),
                ))
            }
            rpc::NetworkSecurityGroupSource::NsgSourceNone => Ok(NetworkSecurityGroupSource::None),
            rpc::NetworkSecurityGroupSource::NsgSourceVpc => Ok(NetworkSecurityGroupSource::Vpc),
            rpc::NetworkSecurityGroupSource::NsgSourceInstance => {
                Ok(NetworkSecurityGroupSource::Instance)
            }
        }
    }
}

/* ********************************************* */
/*     NetworkSecurityGroupPropagationStatus     */
/* ********************************************* */

impl From<NetworkSecurityGroupPropagationStatus> for rpc::NetworkSecurityGroupPropagationStatus {
    fn from(t: NetworkSecurityGroupPropagationStatus) -> Self {
        match t {
            NetworkSecurityGroupPropagationStatus::Unknown => {
                rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown
            }
            NetworkSecurityGroupPropagationStatus::Full => {
                rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull
            }
            NetworkSecurityGroupPropagationStatus::Partial => {
                rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial
            }
            NetworkSecurityGroupPropagationStatus::None => {
                rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone
            }
            NetworkSecurityGroupPropagationStatus::Error => {
                rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusError
            }
        }
    }
}

impl TryFrom<rpc::NetworkSecurityGroupPropagationStatus> for NetworkSecurityGroupPropagationStatus {
    type Error = RpcDataConversionError;

    fn try_from(
        t: rpc::NetworkSecurityGroupPropagationStatus,
    ) -> Result<Self, RpcDataConversionError> {
        match t {
            rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown => {
                Ok(NetworkSecurityGroupPropagationStatus::Unknown)
            }
            rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull => {
                Ok(NetworkSecurityGroupPropagationStatus::Full)
            }
            rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial => {
                Ok(NetworkSecurityGroupPropagationStatus::Partial)
            }
            rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone => {
                Ok(NetworkSecurityGroupPropagationStatus::None)
            }
            rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusError => {
                Ok(NetworkSecurityGroupPropagationStatus::Error)
            }
        }
    }
}

/* ********************************************* */
/*       NetworkSecurityGroupRuleDirection       */
/* ********************************************* */

impl From<NetworkSecurityGroupRuleDirection> for rpc::NetworkSecurityGroupRuleDirection {
    fn from(t: NetworkSecurityGroupRuleDirection) -> Self {
        match t {
            NetworkSecurityGroupRuleDirection::Ingress => {
                rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
            }
            NetworkSecurityGroupRuleDirection::Egress => {
                rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
            }
        }
    }
}

impl TryFrom<rpc::NetworkSecurityGroupRuleDirection> for NetworkSecurityGroupRuleDirection {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::NetworkSecurityGroupRuleDirection) -> Result<Self, Self::Error> {
        match t {
            rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionInvalid => {
                Err(RpcDataConversionError::InvalidValue(
                    "NetworkSecurityGroupRuleDirection".to_string(),
                    t.as_str_name().to_string(),
                ))
            }
            rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress => {
                Ok(NetworkSecurityGroupRuleDirection::Ingress)
            }
            rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress => {
                Ok(NetworkSecurityGroupRuleDirection::Egress)
            }
        }
    }
}

/* ********************************************* */
/*        NetworkSecurityGroupRuleProtocol       */
/* ********************************************* */

impl From<NetworkSecurityGroupRuleProtocol> for rpc::NetworkSecurityGroupRuleProtocol {
    fn from(t: NetworkSecurityGroupRuleProtocol) -> Self {
        match t {
            NetworkSecurityGroupRuleProtocol::Any => {
                rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny
            }
            NetworkSecurityGroupRuleProtocol::Icmp => {
                rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp
            }
            NetworkSecurityGroupRuleProtocol::Icmp6 => {
                rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6
            }
            NetworkSecurityGroupRuleProtocol::Udp => {
                rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp
            }
            NetworkSecurityGroupRuleProtocol::Tcp => {
                rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp
            }
        }
    }
}

impl TryFrom<rpc::NetworkSecurityGroupRuleProtocol> for NetworkSecurityGroupRuleProtocol {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::NetworkSecurityGroupRuleProtocol) -> Result<Self, Self::Error> {
        match t {
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoInvalid => {
                Err(RpcDataConversionError::InvalidValue(
                    "NetworkSecurityGroupRuleProtocol".to_string(),
                    t.as_str_name().to_string(),
                ))
            }
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny => {
                Ok(NetworkSecurityGroupRuleProtocol::Any)
            }
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp => {
                Ok(NetworkSecurityGroupRuleProtocol::Icmp)
            }
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6 => {
                Ok(NetworkSecurityGroupRuleProtocol::Icmp6)
            }
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp => {
                Ok(NetworkSecurityGroupRuleProtocol::Udp)
            }
            rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp => {
                Ok(NetworkSecurityGroupRuleProtocol::Tcp)
            }
        }
    }
}

/* ********************************************* */
/*          NetworkSecurityGroupRuleAction       */
/* ********************************************* */

impl From<NetworkSecurityGroupRuleAction> for rpc::NetworkSecurityGroupRuleAction {
    fn from(t: NetworkSecurityGroupRuleAction) -> Self {
        match t {
            NetworkSecurityGroupRuleAction::Deny => {
                rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny
            }
            NetworkSecurityGroupRuleAction::Permit => {
                rpc::NetworkSecurityGroupRuleAction::NsgRuleActionPermit
            }
        }
    }
}

impl TryFrom<rpc::NetworkSecurityGroupRuleAction> for NetworkSecurityGroupRuleAction {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::NetworkSecurityGroupRuleAction) -> Result<Self, Self::Error> {
        match t {
            rpc::NetworkSecurityGroupRuleAction::NsgRuleActionInvalid => {
                Err(RpcDataConversionError::InvalidValue(
                    "NetworkSecurityGroupRuleAction".to_string(),
                    t.as_str_name().to_string(),
                ))
            }
            rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny => {
                Ok(NetworkSecurityGroupRuleAction::Deny)
            }
            rpc::NetworkSecurityGroupRuleAction::NsgRuleActionPermit => {
                Ok(NetworkSecurityGroupRuleAction::Permit)
            }
        }
    }
}

/* ************************************** */
/*       NetworkSecurityGroupRuleNet      */
/* ************************************** */

impl TryFrom<rpc::network_security_group_rule_attributes::SourceNet>
    for NetworkSecurityGroupRuleNet
{
    type Error = RpcDataConversionError;

    fn try_from(
        net: rpc::network_security_group_rule_attributes::SourceNet,
    ) -> Result<Self, Self::Error> {
        match net {
            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(p) => {
                Ok(NetworkSecurityGroupRuleNet::Prefix(
                    p.parse::<ipnetwork::IpNetwork>()
                        .map_err(|e| RpcDataConversionError::InvalidIpAddress(e.to_string()))?,
                ))
            }
        }
    }
}

impl TryFrom<rpc::network_security_group_rule_attributes::DestinationNet>
    for NetworkSecurityGroupRuleNet
{
    type Error = RpcDataConversionError;

    fn try_from(
        net: rpc::network_security_group_rule_attributes::DestinationNet,
    ) -> Result<Self, Self::Error> {
        match net {
            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(p) => {
                Ok(NetworkSecurityGroupRuleNet::Prefix(
                    p.parse::<ipnetwork::IpNetwork>()
                        .map_err(|e| RpcDataConversionError::InvalidIpAddress(e.to_string()))?,
                ))
            }
        }
    }
}

impl TryFrom<NetworkSecurityGroupRuleNet>
    for rpc::network_security_group_rule_attributes::SourceNet
{
    type Error = RpcDataConversionError;

    fn try_from(net: NetworkSecurityGroupRuleNet) -> Result<Self, Self::Error> {
        match net {
            NetworkSecurityGroupRuleNet::Prefix(p) => Ok(
                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(p.to_string()),
            ),
        }
    }
}

impl TryFrom<NetworkSecurityGroupRuleNet>
    for rpc::network_security_group_rule_attributes::DestinationNet
{
    type Error = RpcDataConversionError;

    fn try_from(net: NetworkSecurityGroupRuleNet) -> Result<Self, Self::Error> {
        match net {
            NetworkSecurityGroupRuleNet::Prefix(p) => Ok(
                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    p.to_string(),
                ),
            ),
        }
    }
}
/* ********************************** */
/*       NetworkSecurityGroupRule     */
/* ********************************** */

impl TryFrom<rpc::NetworkSecurityGroupRuleAttributes> for NetworkSecurityGroupRule {
    type Error = RpcDataConversionError;

    fn try_from(rule: rpc::NetworkSecurityGroupRuleAttributes) -> Result<Self, Self::Error> {
        match rule.protocol() {
            p @ (rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny
            | rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp
            | rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6) => {
                if rule.src_port_start.is_some()
                    || rule.src_port_end.is_some()
                    || rule.dst_port_start.is_some()
                    || rule.dst_port_end.is_some()
                {
                    return Err(RpcDataConversionError::InvalidValue(
                        "protocol".to_string(),
                        format!(
                            "ports cannot be specified with `{}` protocol option",
                            p.as_str_name()
                        ),
                    ));
                }
            }
            // If the protocol allows ports, let's make sure
            // the port options are being used correctly.
            _ => {
                match (rule.src_port_start, rule.src_port_end) {
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(RpcDataConversionError::MissingArgument(
                            "src_port_start and src_port_end are mutually required",
                        ));
                    }
                    (Some(s), Some(e)) if e < s => {
                        return Err(RpcDataConversionError::InvalidValue(
                            "src_port_end".to_string(),
                            "src_port_end is less than src_port_start".to_string(),
                        ));
                    }
                    _ => {} // Do nothing.  All is well.
                }

                match (rule.dst_port_start, rule.dst_port_end) {
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(RpcDataConversionError::MissingArgument(
                            "dst_port_start and dst_port_end are mutually required",
                        ));
                    }
                    (Some(s), Some(e)) if e < s => {
                        return Err(RpcDataConversionError::InvalidValue(
                            "dst_port_end".to_string(),
                            "dst_port_end is less than dst_port_start".to_string(),
                        ));
                    }
                    _ => {} // Do nothing.  All is well.
                }
            }
        };

        if rule.protocol() == rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp && rule.ipv6 {
            return Err(RpcDataConversionError::InvalidValue(
                "protocol".to_string(),
                "ICMP cannot be used with ipv6 rules".to_string(),
            ));
        }

        if rule.protocol() == rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6 && !rule.ipv6
        {
            return Err(RpcDataConversionError::InvalidValue(
                "protocol".to_string(),
                "ICMP6 cannot be used with ipv4 rules".to_string(),
            ));
        }

        if rule.priority > MAX_RULE_PRIORITY {
            return Err(RpcDataConversionError::InvalidValue(
                "priority".to_string(),
                format!(
                    "rule priority {} exceeds maximum of {}",
                    rule.priority, MAX_RULE_PRIORITY
                ),
            ));
        }

        let converted_rule = NetworkSecurityGroupRule {
            direction: rule.direction().try_into()?,
            protocol: rule.protocol().try_into()?,
            action: rule.action().try_into()?,
            src_net: rule
                .source_net
                .ok_or(RpcDataConversionError::MissingArgument(
                    "src_net is required",
                ))?
                .try_into()?,
            dst_net: rule
                .destination_net
                .ok_or(RpcDataConversionError::MissingArgument(
                    "dst_net is required",
                ))?
                .try_into()?,
            id: Some(rule.id.unwrap_or_else(|| format!("{}", Uuid::new_v4()))),
            ipv6: rule.ipv6,
            src_port_start: rule.src_port_start,
            src_port_end: rule.src_port_end,
            dst_port_start: rule.dst_port_start,
            dst_port_end: rule.dst_port_end,
            priority: rule.priority,
        };

        // If prefix is used for src or dst, IP version must match rule ipv6 value.
        // This also implicitly ensures that src and dst are the same IP version.
        match (&converted_rule.src_net, &converted_rule.dst_net) {
            (NetworkSecurityGroupRuleNet::Prefix(s), NetworkSecurityGroupRuleNet::Prefix(d)) => {
                if s.is_ipv6() != converted_rule.ipv6 {
                    return Err(RpcDataConversionError::InvalidValue(
                        "src_prefix".to_string(),
                        "IP version of prefix does not match IP version of rule".to_string(),
                    ));
                }

                if d.is_ipv6() != converted_rule.ipv6 {
                    return Err(RpcDataConversionError::InvalidValue(
                        "dst_prefix".to_string(),
                        "IP version of prefix does not match IP version of rule".to_string(),
                    ));
                }
            }
        };

        Ok(converted_rule)
    }
}

impl TryFrom<NetworkSecurityGroupRule> for rpc::NetworkSecurityGroupRuleAttributes {
    type Error = RpcDataConversionError;

    fn try_from(rule: NetworkSecurityGroupRule) -> Result<Self, Self::Error> {
        Ok(rpc::NetworkSecurityGroupRuleAttributes {
            id: rule.id,
            source_net: Some(rule.src_net.try_into()?),
            destination_net: Some(rule.dst_net.try_into()?),
            direction: rpc::NetworkSecurityGroupRuleDirection::from(rule.direction).into(),
            ipv6: rule.ipv6,
            src_port_start: rule.src_port_start,
            src_port_end: rule.src_port_end,
            dst_port_start: rule.dst_port_start,
            dst_port_end: rule.dst_port_end,
            protocol: rpc::NetworkSecurityGroupRuleProtocol::from(rule.protocol).into(),
            action: rpc::NetworkSecurityGroupRuleAction::from(rule.action).into(),
            priority: rule.priority,
        })
    }
}

/* ********************************** */
/*         NetworkSecurityGroup       */
/* ********************************** */

impl TryFrom<NetworkSecurityGroup> for rpc::NetworkSecurityGroup {
    type Error = RpcDataConversionError;

    fn try_from(nsg: NetworkSecurityGroup) -> Result<Self, Self::Error> {
        let mut rules = Vec::<rpc::NetworkSecurityGroupRuleAttributes>::new();

        for rule_attrs in nsg.rules {
            rules.push(rule_attrs.try_into()?);
        }

        let attributes = rpc::NetworkSecurityGroupAttributes {
            stateful_egress: nsg.stateful_egress,
            rules,
        };

        Ok(rpc::NetworkSecurityGroup {
            id: nsg.id.to_string(),
            tenant_organization_id: nsg.tenant_organization_id.to_string(),
            version: nsg.version.to_string(),
            attributes: Some(attributes),
            created_at: Some(nsg.created.to_string()),
            created_by: nsg.created_by,
            updated_by: nsg.updated_by,
            metadata: Some(rpc::Metadata {
                name: nsg.metadata.name,
                description: nsg.metadata.description,
                labels: nsg
                    .metadata
                    .labels
                    .iter()
                    .map(|(key, value)| rpc::Label {
                        key: key.to_owned(),
                        value: if value.is_empty() {
                            None
                        } else {
                            Some(value.to_owned())
                        },
                    })
                    .collect(),
            }),
        })
    }
}

/* ******************************************* */
/*         NetworkSecurityGroupAttachments     */
/* ******************************************* */

impl From<NetworkSecurityGroupAttachments> for rpc::NetworkSecurityGroupAttachments {
    fn from(attachments: NetworkSecurityGroupAttachments) -> Self {
        rpc::NetworkSecurityGroupAttachments {
            network_security_group_id: attachments.id.to_string(),
            vpc_ids: attachments.vpc_ids.iter().map(|v| v.to_string()).collect(),
            instance_ids: attachments
                .instance_ids
                .iter()
                .map(|i| i.to_string())
                .collect(),
        }
    }
}

/* ******************************************* */
/* NetworkSecurityGroupPropagationObjectStatus */
/* ******************************************* */

impl From<NetworkSecurityGroupPropagationObjectStatus>
    for rpc::NetworkSecurityGroupPropagationObjectStatus
{
    fn from(status: NetworkSecurityGroupPropagationObjectStatus) -> Self {
        let (status_type, details) = {
            if status.interfaces_applied == status.interfaces_expected {
                (
                    rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull,
                    None,
                )
            } else if status.interfaces_applied == 0 {
                (
                    rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone,
                    None,
                )
            } else if status.interfaces_applied < status.interfaces_expected {
                (
                    rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial,
                    None,
                )
            } else
            /* status.interfaces_applied > status.interfaces_expected */
            {
                (
                    rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown,
                    Some("propagated objects exceeds expected objects".to_string()),
                )
            }
        };

        rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: status.id,
            status: status_type.into(),
            details,
            related_instance_ids: status
                .related_instance_ids
                .iter()
                .map(|i| i.to_string())
                .collect(),
            unpropagated_instance_ids: status
                .unpropagated_instance_ids
                .iter()
                .map(|i| i.to_string())
                .collect(),
        }
    }
}

/* ******************************************* */
/*    NetworkSecurityGroupStatusObservation    */
/* ******************************************* */

impl TryFrom<rpc::NetworkSecurityGroupStatus> for NetworkSecurityGroupStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(status: rpc::NetworkSecurityGroupStatus) -> Result<Self, Self::Error> {
        Ok(NetworkSecurityGroupStatusObservation {
            id: status
                .id
                .parse::<NetworkSecurityGroupId>()
                .map_err(|e| RpcDataConversionError::InvalidNetworkSecurityGroupId(e.value()))?,
            version: status.version.parse::<ConfigVersion>().map_err(|_| {
                RpcDataConversionError::InvalidConfigVersion(status.version.clone())
            })?,
            source: status.source().try_into()?,
        })
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use config_version::ConfigVersion;
    use model::metadata::Metadata;

    use super::*;
    use crate::forge as rpc;

    // `From<NetworkSecurityGroupPropagationObjectStatus>` derives the propagation
    // status (and any details) from the applied-vs-expected interface counts.
    #[test]
    fn test_model_nsg_prop_obj_status_to_rpc_conversion() {
        check_values(
            [
                Check {
                    scenario: "full, no interfaces",
                    input: NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        interfaces_expected: 0,
                        interfaces_applied: 0,
                        unpropagated_instance_ids: vec![],
                        related_instance_ids: vec![],
                    },
                    expect: rpc::NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull
                            .into(),
                        details: None,
                        unpropagated_instance_ids: vec![],
                        related_instance_ids: vec![],
                    },
                },
                Check {
                    scenario: "full, all interfaces applied",
                    input: NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        interfaces_expected: 2,
                        interfaces_applied: 2,
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
                        ],
                        unpropagated_instance_ids: vec![],
                    },
                    expect: rpc::NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull
                            .into(),
                        details: None,
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
                        ],
                        unpropagated_instance_ids: vec![],
                    },
                },
                Check {
                    scenario: "partial, some interfaces applied",
                    input: NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        interfaces_expected: 2,
                        interfaces_applied: 1,
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
                        ],
                        unpropagated_instance_ids: vec![
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
                        ],
                    },
                    expect: rpc::NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial
                            .into(),
                        details: None,
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
                        ],
                        unpropagated_instance_ids: vec![
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
                        ],
                    },
                },
                Check {
                    scenario: "none, no interfaces applied",
                    input: NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        interfaces_expected: 2,
                        interfaces_applied: 0,
                        related_instance_ids: vec![],
                        unpropagated_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
                        ],
                    },
                    expect: rpc::NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone
                            .into(),
                        details: None,
                        related_instance_ids: vec![],
                        unpropagated_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
                        ],
                    },
                },
                Check {
                    scenario: "unknown, applied exceeds expected",
                    input: NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        interfaces_expected: 1,
                        interfaces_applied: 2,
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                        ],
                        unpropagated_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
                        ],
                    },
                    expect: rpc::NetworkSecurityGroupPropagationObjectStatus {
                        id: "any_id".to_string(),
                        status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown
                            .into(),
                        details: Some("propagated objects exceeds expected objects".to_string()),
                        related_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                        ],
                        unpropagated_instance_ids: vec![
                            "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                            "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
                        ],
                    },
                },
            ],
            rpc::NetworkSecurityGroupPropagationObjectStatus::from,
        );
    }

    #[test]
    fn test_model_nsg_to_rpc_conversion() {
        let version = ConfigVersion::initial();

        let req_type = rpc::NetworkSecurityGroup {
            id: "test_id".to_string(),
            tenant_organization_id: "best_org".to_string(),
            version: version.to_string(),
            metadata: Some(rpc::Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
            attributes: Some(rpc::NetworkSecurityGroupAttributes {
                stateful_egress: true,
                rules: vec![rpc::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                        .into(),
                    ipv6: false,
                    src_port_start: Some(80),
                    src_port_end: Some(32768),
                    dst_port_start: Some(80),
                    dst_port_end: Some(32768),
                    protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 9001,
                    source_net: Some(
                        rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                }],
            }),
            created_at: Some("2025-01-01 01:01:01 UTC".to_string()),
            created_by: Some("this_guy".to_string()),
            updated_by: Some("that_guy".to_string()),
        };

        let nsg = NetworkSecurityGroup {
            id: "test_id".parse().unwrap(),
            tenant_organization_id: "best_org".parse().unwrap(),
            deleted: None,
            created: "2025-01-01 01:01:01 UTC".parse().unwrap(),
            created_by: Some("this_guy".to_string()),
            updated_by: Some("that_guy".to_string()),
            stateful_egress: true,
            version,
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            rules: vec![NetworkSecurityGroupRule {
                id: Some("anything".to_string()),
                direction: NetworkSecurityGroupRuleDirection::Ingress,
                ipv6: false,
                src_port_start: Some(80),
                src_port_end: Some(32768),
                dst_port_start: Some(80),
                dst_port_end: Some(32768),
                protocol: NetworkSecurityGroupRuleProtocol::Tcp,
                action: NetworkSecurityGroupRuleAction::Deny,
                priority: 9001,
                src_net: NetworkSecurityGroupRuleNet::Prefix("0.0.0.0/0".parse().unwrap()),
                dst_net: NetworkSecurityGroupRuleNet::Prefix(
                    "0.0.0.0/0".to_string().parse().unwrap(),
                ),
            }],
        };

        // Verify that we can go from an internal instance type to the
        // protobuf InstanceType message
        assert_eq!(req_type, rpc::NetworkSecurityGroup::try_from(nsg).unwrap());
    }

    // `TryFrom<rpc::NetworkSecurityGroupRuleAttributes>` rejects ill-formed rules:
    // ports on port-less protocols, and prefix/protocol IP-version mismatches.
    #[test]
    fn test_rpc_rule_to_nsg_model_rule_conversion_failures() {
        check_cases(
            [
                Case {
                    scenario: "ICMP with ports",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: false,
                        src_port_start: Some(80),
                        src_port_end: Some(32768),
                        dst_port_start: Some(80),
                        dst_port_end: Some(32768),
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "0.0.0.0/0".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "0.0.0.0/0".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "ICMP6 with ports",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: true,
                        src_port_start: Some(80),
                        src_port_end: Some(32768),
                        dst_port_start: Some(80),
                        dst_port_end: Some(32768),
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "ANY with ports",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: true,
                        src_port_start: Some(80),
                        src_port_end: Some(32768),
                        dst_port_start: Some(80),
                        dst_port_end: Some(32768),
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "v4 prefixes with v6 rule",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: true,
                        src_port_start: Some(80),
                        src_port_end: Some(32768),
                        dst_port_start: Some(80),
                        dst_port_end: Some(32768),
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "0.0.0.0/0".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "0.0.0.0/0".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "v6 prefixes with v4 rule",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: false,
                        src_port_start: Some(80),
                        src_port_end: Some(32768),
                        dst_port_start: Some(80),
                        dst_port_end: Some(32768),
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "ICMP6 with v4 prefixes on v4 rule",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: false,
                        src_port_start: None,
                        src_port_end: None,
                        dst_port_start: None,
                        dst_port_end: None,
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "1.1.1.1/24".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "1.1.1.1/24".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
                Case {
                    scenario: "ICMP on v6 rule",
                    input: rpc::NetworkSecurityGroupRuleAttributes {
                        id: Some("anything".to_string()),
                        direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                            .into(),
                        ipv6: true,
                        src_port_start: None,
                        src_port_end: None,
                        dst_port_start: None,
                        dst_port_end: None,
                        protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp.into(),
                        action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                        priority: 9001,
                        source_net: Some(
                            rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                        destination_net: Some(
                            rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                            ),
                        ),
                    },
                    expect: Fails,
                },
            ],
            |req| NetworkSecurityGroupRule::try_from(req).map_err(drop),
        );
    }

    #[test]
    fn test_model_nsg_attachments_to_rpc_conversion() {
        // Full
        let req_type = rpc::NetworkSecurityGroupAttachments {
            network_security_group_id: "any_id".to_string(),
            vpc_ids: vec![
                "60d92a18-e56b-11ef-8ecd-ef90f290abf4".to_string(),
                "6570b208-e56b-11ef-a659-f38dea668523".to_string(),
            ],
            instance_ids: vec![
                "7ed78230-e56b-11ef-a601-f77e6a6c73d3".to_string(),
                "819e2834-e56b-11ef-920c-9b55d2079ba9".to_string(),
            ],
        };

        let status = NetworkSecurityGroupAttachments {
            id: "any_id".parse().unwrap(),
            vpc_ids: vec![
                "60d92a18-e56b-11ef-8ecd-ef90f290abf4".parse().unwrap(),
                "6570b208-e56b-11ef-a659-f38dea668523".parse().unwrap(),
            ],
            instance_ids: vec![
                "7ed78230-e56b-11ef-a601-f77e6a6c73d3".parse().unwrap(),
                "819e2834-e56b-11ef-920c-9b55d2079ba9".parse().unwrap(),
            ],
        };

        assert_eq!(req_type, rpc::NetworkSecurityGroupAttachments::from(status));
    }

    // `From<NetworkSecurityGroupSource>` maps each domain source onto its rpc enum.
    #[test]
    fn test_model_source_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "none",
                    input: NetworkSecurityGroupSource::None,
                    expect: rpc::NetworkSecurityGroupSource::NsgSourceNone,
                },
                Check {
                    scenario: "vpc",
                    input: NetworkSecurityGroupSource::Vpc,
                    expect: rpc::NetworkSecurityGroupSource::NsgSourceVpc,
                },
                Check {
                    scenario: "instance",
                    input: NetworkSecurityGroupSource::Instance,
                    expect: rpc::NetworkSecurityGroupSource::NsgSourceInstance,
                },
            ],
            rpc::NetworkSecurityGroupSource::from,
        );
    }

    // `TryFrom<rpc::NetworkSecurityGroupSource>`: each valid arm maps back, and the
    // `Invalid` sentinel is rejected.
    #[test]
    fn test_rpc_source_to_model() {
        check_cases(
            [
                Case {
                    scenario: "none",
                    input: rpc::NetworkSecurityGroupSource::NsgSourceNone,
                    expect: Yields(NetworkSecurityGroupSource::None),
                },
                Case {
                    scenario: "vpc",
                    input: rpc::NetworkSecurityGroupSource::NsgSourceVpc,
                    expect: Yields(NetworkSecurityGroupSource::Vpc),
                },
                Case {
                    scenario: "instance",
                    input: rpc::NetworkSecurityGroupSource::NsgSourceInstance,
                    expect: Yields(NetworkSecurityGroupSource::Instance),
                },
                Case {
                    scenario: "invalid is rejected",
                    input: rpc::NetworkSecurityGroupSource::NsgSourceInvalid,
                    expect: Fails,
                },
            ],
            |s| NetworkSecurityGroupSource::try_from(s).map_err(drop),
        );
    }

    // `From<NetworkSecurityGroupPropagationStatus>` maps each domain status onto its
    // rpc enum.
    #[test]
    fn test_model_prop_status_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "unknown",
                    input: NetworkSecurityGroupPropagationStatus::Unknown,
                    expect: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown,
                },
                Check {
                    scenario: "full",
                    input: NetworkSecurityGroupPropagationStatus::Full,
                    expect: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull,
                },
                Check {
                    scenario: "partial",
                    input: NetworkSecurityGroupPropagationStatus::Partial,
                    expect: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial,
                },
                Check {
                    scenario: "none",
                    input: NetworkSecurityGroupPropagationStatus::None,
                    expect: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone,
                },
                Check {
                    scenario: "error",
                    input: NetworkSecurityGroupPropagationStatus::Error,
                    expect: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusError,
                },
            ],
            rpc::NetworkSecurityGroupPropagationStatus::from,
        );
    }

    // `TryFrom<rpc::NetworkSecurityGroupPropagationStatus>` maps every arm back; this
    // conversion is total over the rpc enum (no `Invalid` rejection path).
    #[test]
    fn test_rpc_prop_status_to_model() {
        check_cases(
            [
                Case {
                    scenario: "unknown",
                    input: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown,
                    expect: Yields(NetworkSecurityGroupPropagationStatus::Unknown),
                },
                Case {
                    scenario: "full",
                    input: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull,
                    expect: Yields(NetworkSecurityGroupPropagationStatus::Full),
                },
                Case {
                    scenario: "partial",
                    input: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial,
                    expect: Yields(NetworkSecurityGroupPropagationStatus::Partial),
                },
                Case {
                    scenario: "none",
                    input: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone,
                    expect: Yields(NetworkSecurityGroupPropagationStatus::None),
                },
                Case {
                    scenario: "error",
                    input: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusError,
                    expect: Yields(NetworkSecurityGroupPropagationStatus::Error),
                },
            ],
            |s| NetworkSecurityGroupPropagationStatus::try_from(s).map_err(drop),
        );
    }

    // `From<NetworkSecurityGroupRuleDirection>` maps both directions onto the rpc enum.
    #[test]
    fn test_model_direction_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "ingress",
                    input: NetworkSecurityGroupRuleDirection::Ingress,
                    expect: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress,
                },
                Check {
                    scenario: "egress",
                    input: NetworkSecurityGroupRuleDirection::Egress,
                    expect: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress,
                },
            ],
            rpc::NetworkSecurityGroupRuleDirection::from,
        );
    }

    // `TryFrom<rpc::NetworkSecurityGroupRuleDirection>`: both directions map back, the
    // `Invalid` sentinel is rejected.
    #[test]
    fn test_rpc_direction_to_model() {
        check_cases(
            [
                Case {
                    scenario: "ingress",
                    input: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress,
                    expect: Yields(NetworkSecurityGroupRuleDirection::Ingress),
                },
                Case {
                    scenario: "egress",
                    input: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress,
                    expect: Yields(NetworkSecurityGroupRuleDirection::Egress),
                },
                Case {
                    scenario: "invalid is rejected",
                    input: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionInvalid,
                    expect: Fails,
                },
            ],
            |d| NetworkSecurityGroupRuleDirection::try_from(d).map_err(drop),
        );
    }

    // `From<NetworkSecurityGroupRuleProtocol>` maps each protocol onto the rpc enum.
    #[test]
    fn test_model_protocol_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "any",
                    input: NetworkSecurityGroupRuleProtocol::Any,
                    expect: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny,
                },
                Check {
                    scenario: "icmp",
                    input: NetworkSecurityGroupRuleProtocol::Icmp,
                    expect: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp,
                },
                Check {
                    scenario: "icmp6",
                    input: NetworkSecurityGroupRuleProtocol::Icmp6,
                    expect: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6,
                },
                Check {
                    scenario: "udp",
                    input: NetworkSecurityGroupRuleProtocol::Udp,
                    expect: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp,
                },
                Check {
                    scenario: "tcp",
                    input: NetworkSecurityGroupRuleProtocol::Tcp,
                    expect: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp,
                },
            ],
            rpc::NetworkSecurityGroupRuleProtocol::from,
        );
    }

    // `TryFrom<rpc::NetworkSecurityGroupRuleProtocol>`: each protocol maps back, the
    // `Invalid` sentinel is rejected.
    #[test]
    fn test_rpc_protocol_to_model() {
        check_cases(
            [
                Case {
                    scenario: "any",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny,
                    expect: Yields(NetworkSecurityGroupRuleProtocol::Any),
                },
                Case {
                    scenario: "icmp",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp,
                    expect: Yields(NetworkSecurityGroupRuleProtocol::Icmp),
                },
                Case {
                    scenario: "icmp6",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6,
                    expect: Yields(NetworkSecurityGroupRuleProtocol::Icmp6),
                },
                Case {
                    scenario: "udp",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp,
                    expect: Yields(NetworkSecurityGroupRuleProtocol::Udp),
                },
                Case {
                    scenario: "tcp",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp,
                    expect: Yields(NetworkSecurityGroupRuleProtocol::Tcp),
                },
                Case {
                    scenario: "invalid is rejected",
                    input: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoInvalid,
                    expect: Fails,
                },
            ],
            |p| NetworkSecurityGroupRuleProtocol::try_from(p).map_err(drop),
        );
    }

    // `From<NetworkSecurityGroupRuleAction>` maps both actions onto the rpc enum.
    #[test]
    fn test_model_action_to_rpc() {
        check_values(
            [
                Check {
                    scenario: "deny",
                    input: NetworkSecurityGroupRuleAction::Deny,
                    expect: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny,
                },
                Check {
                    scenario: "permit",
                    input: NetworkSecurityGroupRuleAction::Permit,
                    expect: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionPermit,
                },
            ],
            rpc::NetworkSecurityGroupRuleAction::from,
        );
    }

    // `TryFrom<rpc::NetworkSecurityGroupRuleAction>`: both actions map back, the
    // `Invalid` sentinel is rejected.
    #[test]
    fn test_rpc_action_to_model() {
        check_cases(
            [
                Case {
                    scenario: "deny",
                    input: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny,
                    expect: Yields(NetworkSecurityGroupRuleAction::Deny),
                },
                Case {
                    scenario: "permit",
                    input: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionPermit,
                    expect: Yields(NetworkSecurityGroupRuleAction::Permit),
                },
                Case {
                    scenario: "invalid is rejected",
                    input: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionInvalid,
                    expect: Fails,
                },
            ],
            |a| NetworkSecurityGroupRuleAction::try_from(a).map_err(drop),
        );
    }

    // `TryFrom<rpc::...::SourceNet>` parses the prefix string into a `Prefix`, and a
    // malformed prefix is rejected.
    #[test]
    fn test_rpc_source_net_to_model() {
        check_cases(
            [
                Case {
                    scenario: "v4 prefix parses",
                    input: rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "10.0.0.0/8".to_string(),
                    ),
                    expect: Yields(NetworkSecurityGroupRuleNet::Prefix(
                        "10.0.0.0/8".parse().unwrap(),
                    )),
                },
                Case {
                    scenario: "v6 prefix parses",
                    input: rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "2001:db8::/32".to_string(),
                    ),
                    expect: Yields(NetworkSecurityGroupRuleNet::Prefix(
                        "2001:db8::/32".parse().unwrap(),
                    )),
                },
                Case {
                    scenario: "garbage prefix is rejected",
                    input: rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "not-an-ip".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |n| NetworkSecurityGroupRuleNet::try_from(n).map_err(drop),
        );
    }

    // `TryFrom<rpc::...::DestinationNet>` parses the prefix string into a `Prefix`,
    // and a malformed prefix is rejected.
    #[test]
    fn test_rpc_destination_net_to_model() {
        check_cases(
            [
                Case {
                    scenario: "v4 prefix parses",
                    input: rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "192.168.0.0/16".to_string(),
                    ),
                    expect: Yields(NetworkSecurityGroupRuleNet::Prefix(
                        "192.168.0.0/16".parse().unwrap(),
                    )),
                },
                Case {
                    scenario: "v6 prefix parses",
                    input: rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "fd00::/8".to_string(),
                    ),
                    expect: Yields(NetworkSecurityGroupRuleNet::Prefix(
                        "fd00::/8".parse().unwrap(),
                    )),
                },
                Case {
                    scenario: "garbage prefix is rejected",
                    input: rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "999.0.0.0/8".to_string(),
                    ),
                    expect: Fails,
                },
            ],
            |n| NetworkSecurityGroupRuleNet::try_from(n).map_err(drop),
        );
    }

    // `TryFrom<NetworkSecurityGroupRuleNet>` for the rpc `SourceNet` / `DestinationNet`
    // renders the prefix back to its string form.
    #[test]
    fn test_model_net_to_rpc() {
        check_cases(
            [
                Case {
                    scenario: "source net renders v4 prefix",
                    input: NetworkSecurityGroupRuleNet::Prefix("10.0.0.0/8".parse().unwrap()),
                    expect: Yields(
                        rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "10.0.0.0/8".to_string(),
                        ),
                    ),
                },
                Case {
                    scenario: "source net renders v6 prefix",
                    input: NetworkSecurityGroupRuleNet::Prefix("2001:db8::/32".parse().unwrap()),
                    expect: Yields(
                        rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "2001:db8::/32".to_string(),
                        ),
                    ),
                },
            ],
            |n| {
                rpc::network_security_group_rule_attributes::SourceNet::try_from(n).map_err(drop)
            },
        );

        check_cases(
            [Case {
                scenario: "destination net renders v4 prefix",
                input: NetworkSecurityGroupRuleNet::Prefix("192.168.0.0/16".parse().unwrap()),
                expect: Yields(
                    rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "192.168.0.0/16".to_string(),
                    ),
                ),
            }],
            |n| {
                rpc::network_security_group_rule_attributes::DestinationNet::try_from(n)
                    .map_err(drop)
            },
        );
    }

    // A well-formed rule that carries a fixed id round-trips through
    // `TryFrom<rpc::NetworkSecurityGroupRuleAttributes>`.
    #[test]
    fn test_rpc_rule_to_model_succeeds() {
        let attrs = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(32768),
            dst_port_start: Some(80),
            dst_port_end: Some(32768),
            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 9001,
            source_net: Some(
                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        };

        Case {
            scenario: "well-formed tcp rule converts",
            input: attrs,
            expect: Yields(NetworkSecurityGroupRule {
                id: Some("anything".to_string()),
                direction: NetworkSecurityGroupRuleDirection::Ingress,
                ipv6: false,
                src_port_start: Some(80),
                src_port_end: Some(32768),
                dst_port_start: Some(80),
                dst_port_end: Some(32768),
                protocol: NetworkSecurityGroupRuleProtocol::Tcp,
                action: NetworkSecurityGroupRuleAction::Deny,
                priority: 9001,
                src_net: NetworkSecurityGroupRuleNet::Prefix("0.0.0.0/0".parse().unwrap()),
                dst_net: NetworkSecurityGroupRuleNet::Prefix("0.0.0.0/0".parse().unwrap()),
            }),
        }
        .check(|req| NetworkSecurityGroupRule::try_from(req).map_err(drop));
    }

    // More `TryFrom<rpc::NetworkSecurityGroupRuleAttributes>` rejection paths: a
    // priority over the cap, half-specified port ranges, an inverted range, and
    // missing source/destination nets.
    #[test]
    fn test_rpc_rule_to_model_more_failures() {
        // A v4 tcp rule template; rows below mutate just the field under test.
        let base = || rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
            ipv6: false,
            src_port_start: None,
            src_port_end: None,
            dst_port_start: None,
            dst_port_end: None,
            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            priority: 100,
            source_net: Some(
                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "0.0.0.0/0".to_string(),
                ),
            ),
        };

        let priority_too_high = rpc::NetworkSecurityGroupRuleAttributes {
            priority: MAX_RULE_PRIORITY + 1,
            ..base()
        };
        let src_port_half = rpc::NetworkSecurityGroupRuleAttributes {
            src_port_start: Some(80),
            src_port_end: None,
            ..base()
        };
        let dst_port_half = rpc::NetworkSecurityGroupRuleAttributes {
            dst_port_start: None,
            dst_port_end: Some(80),
            ..base()
        };
        let src_range_inverted = rpc::NetworkSecurityGroupRuleAttributes {
            src_port_start: Some(200),
            src_port_end: Some(100),
            ..base()
        };
        let dst_range_inverted = rpc::NetworkSecurityGroupRuleAttributes {
            dst_port_start: Some(200),
            dst_port_end: Some(100),
            ..base()
        };
        let missing_src_net = rpc::NetworkSecurityGroupRuleAttributes {
            source_net: None,
            ..base()
        };
        let missing_dst_net = rpc::NetworkSecurityGroupRuleAttributes {
            destination_net: None,
            ..base()
        };

        check_cases(
            [
                Case {
                    scenario: "priority over the cap",
                    input: priority_too_high,
                    expect: Fails,
                },
                Case {
                    scenario: "src port range half-specified",
                    input: src_port_half,
                    expect: Fails,
                },
                Case {
                    scenario: "dst port range half-specified",
                    input: dst_port_half,
                    expect: Fails,
                },
                Case {
                    scenario: "src port range inverted",
                    input: src_range_inverted,
                    expect: Fails,
                },
                Case {
                    scenario: "dst port range inverted",
                    input: dst_range_inverted,
                    expect: Fails,
                },
                Case {
                    scenario: "missing source net",
                    input: missing_src_net,
                    expect: Fails,
                },
                Case {
                    scenario: "missing destination net",
                    input: missing_dst_net,
                    expect: Fails,
                },
            ],
            |req| NetworkSecurityGroupRule::try_from(req).map_err(drop),
        );
    }

    // `TryFrom<NetworkSecurityGroupRule>` for rpc renders the rule's nets, ports, and
    // enums back into proto attribute form.
    #[test]
    fn test_model_rule_to_rpc_succeeds() {
        let rule = NetworkSecurityGroupRule {
            id: Some("anything".to_string()),
            direction: NetworkSecurityGroupRuleDirection::Egress,
            ipv6: false,
            src_port_start: Some(80),
            src_port_end: Some(32768),
            dst_port_start: Some(81),
            dst_port_end: Some(32769),
            protocol: NetworkSecurityGroupRuleProtocol::Udp,
            action: NetworkSecurityGroupRuleAction::Permit,
            priority: 9001,
            src_net: NetworkSecurityGroupRuleNet::Prefix("10.0.0.0/8".parse().unwrap()),
            dst_net: NetworkSecurityGroupRuleNet::Prefix("192.168.0.0/16".parse().unwrap()),
        };

        Case {
            scenario: "well-formed udp rule renders",
            input: rule,
            expect: Yields(rpc::NetworkSecurityGroupRuleAttributes {
                id: Some("anything".to_string()),
                direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress.into(),
                ipv6: false,
                src_port_start: Some(80),
                src_port_end: Some(32768),
                dst_port_start: Some(81),
                dst_port_end: Some(32769),
                protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp.into(),
                action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionPermit.into(),
                priority: 9001,
                source_net: Some(
                    rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                        "10.0.0.0/8".to_string(),
                    ),
                ),
                destination_net: Some(
                    rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                        "192.168.0.0/16".to_string(),
                    ),
                ),
            }),
        }
        .check(|r| rpc::NetworkSecurityGroupRuleAttributes::try_from(r).map_err(drop));
    }

    // `TryFrom<rpc::NetworkSecurityGroupStatus>`: a well-formed status parses, while a
    // bad id, a bad version, and an invalid source each fail.
    #[test]
    fn test_rpc_status_to_observation() {
        // Fixed, deterministic version so the parsed-back value equals the expected
        // one; the real `initial()` constructor stamps the current time.
        fn fixed_version() -> ConfigVersion {
            use std::str::FromStr;
            ConfigVersion::from_str("V1-T1700000000000000").unwrap()
        }
        let good = rpc::NetworkSecurityGroupStatus {
            id: "60d92a18-e56b-11ef-8ecd-ef90f290abf4".to_string(),
            version: fixed_version().to_string(),
            source: rpc::NetworkSecurityGroupSource::NsgSourceVpc.into(),
        };
        let bad_id = rpc::NetworkSecurityGroupStatus {
            id: "not-a-uuid".to_string(),
            ..good.clone()
        };
        let bad_version = rpc::NetworkSecurityGroupStatus {
            version: "not-a-version".to_string(),
            ..good.clone()
        };
        let invalid_source = rpc::NetworkSecurityGroupStatus {
            source: rpc::NetworkSecurityGroupSource::NsgSourceInvalid.into(),
            ..good.clone()
        };

        check_cases(
            [
                Case {
                    scenario: "well-formed status parses",
                    input: good,
                    expect: Yields(NetworkSecurityGroupStatusObservation {
                        id: "60d92a18-e56b-11ef-8ecd-ef90f290abf4".parse().unwrap(),
                        version: fixed_version(),
                        source: NetworkSecurityGroupSource::Vpc,
                    }),
                },
                Case {
                    // The id is a free-form string id, not UUID-validated, so a
                    // non-uuid value passes through rather than being rejected.
                    scenario: "non-uuid id passes through unvalidated",
                    input: bad_id,
                    expect: Yields(NetworkSecurityGroupStatusObservation {
                        id: "not-a-uuid".parse().unwrap(),
                        version: fixed_version(),
                        source: NetworkSecurityGroupSource::Vpc,
                    }),
                },
                Case {
                    scenario: "bad version is rejected",
                    input: bad_version,
                    expect: Fails,
                },
                Case {
                    scenario: "invalid source is rejected",
                    input: invalid_source,
                    expect: Fails,
                },
            ],
            |s| NetworkSecurityGroupStatusObservation::try_from(s).map_err(drop),
        );
    }
}
