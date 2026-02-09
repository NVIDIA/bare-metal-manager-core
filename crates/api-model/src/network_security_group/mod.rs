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
use std::collections::HashMap;
use std::fmt;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use carbide_uuid::vpc::VpcId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use ipnetwork;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use super::tenant::TenantOrganizationId;
use crate::metadata::Metadata;

/// The maximum priority value allowed for security group rule.
/// We could expose this in config and validate it in the API
/// handlers, but it's based on the hard limit of the field in
/// NVUE, so setting it close to the limit seems sufficient.
const MAX_RULE_PRIORITY: u32 = 60000;

/* ********************************** */
/*     NetworkSecurityGroupSource     */
/* ********************************** */

/// NetworkSecurityGroupSource describes where a
/// machine's security rules were originally defined,
/// either on an NSG attached to the instance or a VPC.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub enum NetworkSecurityGroupSource {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "VPC")]
    Vpc,
    #[serde(rename = "INSTANCE")]
    Instance,
}

impl fmt::Display for NetworkSecurityGroupSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkSecurityGroupSource::None => write!(f, "NONE"),
            NetworkSecurityGroupSource::Vpc => write!(f, "VPC"),
            NetworkSecurityGroupSource::Instance => write!(f, "INSTANCE"),
        }
    }
}

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

/// NetworkSecurityGroupPropagationStatus describes the degree
/// to which propagation of NSG changes has succeeded accross
/// a set of instances (really instance DPUs).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum NetworkSecurityGroupPropagationStatus {
    Unknown,
    Full,
    Partial,
    None,
    Error,
}

impl fmt::Display for NetworkSecurityGroupPropagationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkSecurityGroupPropagationStatus::Unknown => write!(f, "UNKNOWN"),
            NetworkSecurityGroupPropagationStatus::Full => write!(f, "FULL"),
            NetworkSecurityGroupPropagationStatus::Partial => write!(f, "PARTIAL"),
            NetworkSecurityGroupPropagationStatus::None => write!(f, "NONE"),
            NetworkSecurityGroupPropagationStatus::Error => write!(f, "ERROR"),
        }
    }
}

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

/// NetworkSecurityGroupRuleDirection describes whether a rule
/// is being applied to ingress or egress traffic.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum NetworkSecurityGroupRuleDirection {
    Ingress,
    Egress,
}

impl fmt::Display for NetworkSecurityGroupRuleDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkSecurityGroupRuleDirection::Ingress => write!(f, "INGRESS"),
            NetworkSecurityGroupRuleDirection::Egress => write!(f, "EGRESS"),
        }
    }
}

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

/// NetworkSecurityGroupRuleProtocol describes the
/// protocol on which the rule should match/act.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum NetworkSecurityGroupRuleProtocol {
    Any,
    Icmp,
    Icmp6,
    Udp,
    Tcp,
}

impl fmt::Display for NetworkSecurityGroupRuleProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkSecurityGroupRuleProtocol::Any => write!(f, "ANY"),
            NetworkSecurityGroupRuleProtocol::Icmp => write!(f, "ICMP"),
            NetworkSecurityGroupRuleProtocol::Icmp6 => write!(f, "ICMP6"),
            NetworkSecurityGroupRuleProtocol::Udp => write!(f, "UDP"),
            NetworkSecurityGroupRuleProtocol::Tcp => write!(f, "TCP"),
        }
    }
}

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

/// NetworkSecurityGroupRuleAction describes the
/// action that should be taken when a rule matches.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum NetworkSecurityGroupRuleAction {
    Deny,
    Permit,
}

impl fmt::Display for NetworkSecurityGroupRuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkSecurityGroupRuleAction::Deny => write!(f, "DENY"),
            NetworkSecurityGroupRuleAction::Permit => write!(f, "PERMIT"),
        }
    }
}

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
/// NetworkSecurityGroupRuleNet describes a source or
/// destination network to look for when matching
/// network traffic. It can be either an explicit prefix
/// or defined by an object ID.
///
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum NetworkSecurityGroupRuleNet {
    Prefix(ipnetwork::IpNetwork),
    // Not yet supported.  We hide this in the proto spec.
    // Implementation wouldn't be hard, but it would be hard
    // to manage operationally because this would allow users
    // to create a rule that does not exceed any limits but
    // later silently exceeds limits by adding more prefixes
    // to a VPC without ever touching the NSG.  It would be
    // dangerous/irresponsible to simply allow the overflow
    // (the behavior on the DPU could be undefined), or trim
    // out anything beyond our limits.
    // We either need some job checking the state of things
    // and alerting, or the DPU needs to alert when limits
    // are exceeded, but the damage is already done by the
    // time something is alerting.
    // This also perhaps opens a security issue unless we
    // restrict the prefixes that a tenant is allowed to add
    // to a VPC.  Otherwise, If I allow (VPC ID 123), then
    // it means I allow whatever random prefixes the owner
    // of that VPC attaches.  It implicitly hands off part of
    // "my" ACL control over to the other side.
    // VpcId(VpcId),
}

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

/// NetworkSecurityGroupRule holds the details of a
/// single rule that will be applied on a DPU to restrict
/// traffic.
///
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct NetworkSecurityGroupRule {
    pub id: Option<String>,
    pub src_net: NetworkSecurityGroupRuleNet,
    pub dst_net: NetworkSecurityGroupRuleNet,
    pub direction: NetworkSecurityGroupRuleDirection,
    pub ipv6: bool,
    pub src_port_start: Option<u32>,
    pub src_port_end: Option<u32>,
    pub dst_port_start: Option<u32>,
    pub dst_port_end: Option<u32>,
    pub protocol: NetworkSecurityGroupRuleProtocol,
    pub action: NetworkSecurityGroupRuleAction,
    pub priority: u32,
}

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

/// NetworkSecurityGroup represents a collection of L4 traffic
/// ACLs to permit or deny network traffic based on a set of
/// matching properties.
///
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkSecurityGroup {
    pub id: NetworkSecurityGroupId,
    pub tenant_organization_id: TenantOrganizationId,
    pub stateful_egress: bool,
    pub rules: Vec<NetworkSecurityGroupRule>,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub metadata: Metadata,
    pub created_by: Option<String>,
    pub updated_by: Option<String>,
}

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

/// NetworkSecurityGroupAttachments holds lists of objects that have
/// the NetworkSecurityGroup attached.
///
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkSecurityGroupAttachments {
    pub id: NetworkSecurityGroupId,
    pub vpc_ids: Vec<VpcId>,
    pub instance_ids: Vec<InstanceId>,
}

impl NetworkSecurityGroupAttachments {
    pub fn has_attachments(&self) -> bool {
        !(self.vpc_ids.is_empty() && self.instance_ids.is_empty())
    }
}

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

/// NetworkSecurityGroupPropagationObjectStatus holds
/// the propagation status of a single object (vpc, instance, etc)
/// The status of propagation depends on the propagation of all
/// underlying objects that do not have a more specific NSG applied.
/// For example, for a VPC to be fully propagated, all interfaces
/// of all instances under that VPC must be fully propagated.
///
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkSecurityGroupPropagationObjectStatus {
    pub id: String,
    pub interfaces_expected: u32,
    pub interfaces_applied: u32,
    pub related_instance_ids: Vec<InstanceId>,
    pub unpropagated_instance_ids: Vec<InstanceId>,
}

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

/// NetworkSecurityGroupStatusObservation holds he
/// network security group details observed on an
/// interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSecurityGroupStatusObservation {
    pub id: NetworkSecurityGroupId,
    pub version: ConfigVersion,
    pub source: NetworkSecurityGroupSource,
}

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

impl<'r> sqlx::FromRow<'r, PgRow> for NetworkSecurityGroupAttachments {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let vpc_ids: sqlx::types::Json<Vec<VpcId>> = row.try_get("vpc_ids")?;
        let instance_ids: sqlx::types::Json<Vec<InstanceId>> = row.try_get("instance_ids")?;

        Ok(NetworkSecurityGroupAttachments {
            id: row.try_get("id")?,
            vpc_ids: vpc_ids.0,
            instance_ids: instance_ids.0,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for NetworkSecurityGroupPropagationObjectStatus {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let expected: i32 = row.try_get("interfaces_expected")?;
        let applied: i32 = row.try_get("interfaces_applied")?;

        let related_instance_ids: sqlx::types::Json<Vec<InstanceId>> =
            row.try_get("related_instance_ids")?;
        let unpropagated_instance_ids: sqlx::types::Json<Vec<InstanceId>> =
            row.try_get("unpropagated_instance_ids")?;

        Ok(NetworkSecurityGroupPropagationObjectStatus {
            id: row.try_get("id")?,
            interfaces_expected: expected
                .try_into()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            interfaces_applied: applied
                .try_into()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            related_instance_ids: related_instance_ids.0,
            unpropagated_instance_ids: unpropagated_instance_ids.0,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for NetworkSecurityGroup {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: labels.0,
        };

        let rules: sqlx::types::Json<Vec<NetworkSecurityGroupRule>> = row.try_get("rules")?;
        let tenant_organization_id: String = row.try_get("tenant_organization_id")?;

        Ok(NetworkSecurityGroup {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            stateful_egress: row.try_get("stateful_egress")?,
            tenant_organization_id: tenant_organization_id
                .parse::<TenantOrganizationId>()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            created: row.try_get("created")?,
            deleted: row.try_get("deleted")?,
            created_by: row.try_get("created_by")?,
            updated_by: row.try_get("updated_by")?,
            metadata,
            rules: rules.0,
        })
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ::rpc::forge as rpc;
    use config_version::ConfigVersion;

    use super::*;

    #[test]
    fn test_model_nsg_prop_obj_status_to_rpc_conversion() {
        // Full
        let req_type = rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            unpropagated_instance_ids: vec![],
            related_instance_ids: vec![],
        };

        let status = NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            interfaces_expected: 0,
            interfaces_applied: 0,
            unpropagated_instance_ids: vec![],
            related_instance_ids: vec![],
        };

        assert_eq!(
            req_type,
            rpc::NetworkSecurityGroupPropagationObjectStatus::from(status)
        );

        let req_type = rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusFull.into(),
            details: None,
            related_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
            ],
            unpropagated_instance_ids: vec![],
        };

        let status = NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            interfaces_expected: 2,
            interfaces_applied: 2,
            related_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
            ],
            unpropagated_instance_ids: vec![],
        };

        assert_eq!(
            req_type,
            rpc::NetworkSecurityGroupPropagationObjectStatus::from(status)
        );

        // Partial
        let req_type = rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusPartial.into(),
            details: None,
            related_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
            ],
            unpropagated_instance_ids: vec!["fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string()],
        };

        let status = NetworkSecurityGroupPropagationObjectStatus {
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
        };

        assert_eq!(
            req_type,
            rpc::NetworkSecurityGroupPropagationObjectStatus::from(status)
        );

        // None
        let req_type = rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusNone.into(),
            details: None,
            related_instance_ids: vec![],
            unpropagated_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
            ],
        };

        let status = NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            interfaces_expected: 2,
            interfaces_applied: 0,
            related_instance_ids: vec![],
            unpropagated_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
            ],
        };

        assert_eq!(
            req_type,
            rpc::NetworkSecurityGroupPropagationObjectStatus::from(status)
        );

        // Unknown
        let req_type = rpc::NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            status: rpc::NetworkSecurityGroupPropagationStatus::NsgPropStatusUnknown.into(),
            details: Some("propagated objects exceeds expected objects".to_string()),
            related_instance_ids: vec!["200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap()],
            unpropagated_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".to_string(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".to_string(),
            ],
        };

        let status = NetworkSecurityGroupPropagationObjectStatus {
            id: "any_id".to_string(),
            interfaces_expected: 1,
            interfaces_applied: 2,
            related_instance_ids: vec!["200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap()],
            unpropagated_instance_ids: vec![
                "200f1043-1653-426d-bd0e-97f5b06bdb3f".parse().unwrap(),
                "fb02b51c-3f18-46b8-b2f1-bc4a6e9b2f3d".parse().unwrap(),
            ],
        };

        assert_eq!(
            req_type,
            rpc::NetworkSecurityGroupPropagationObjectStatus::from(status)
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

    #[test]
    fn test_rpc_rule_to_nsg_model_rule_conversion_failures() {
        // ICMP with ports should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // ICMP6 with ports should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // ANY with ports should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // v4 prefixes with v6 rule should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // v6 prefixes with v4 rule should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
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
                    "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                ),
            ),
            destination_net: Some(
                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                    "2001:db8:1234::f350:2256:f3dd/64".to_string(),
                ),
            ),
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // ICMP6 with v4 rule should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();

        // ICMP6 with v4 rule should fail
        let req = rpc::NetworkSecurityGroupRuleAttributes {
            id: Some("anything".to_string()),
            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress.into(),
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
        };
        NetworkSecurityGroupRule::try_from(req).unwrap_err();
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
}
