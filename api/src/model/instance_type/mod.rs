/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::ConfigVersion;
use forge_uuid::instance_type::InstanceTypeId;
use serde::{Deserialize, Serialize};

use crate::{model::metadata::Metadata, CarbideError};

/* ********************************** */
/* InstanceTypeMachineCapabilityType  */
/* ********************************** */

/// InstanceTypeMachineCapabilityType represents a category
/// of machine component
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum InstanceTypeMachineCapabilityType {
    Cpu,
    Gpu,
    Memory,
    Storage,
    Network,
    Infiniband,
    Dpu,
}

impl fmt::Display for InstanceTypeMachineCapabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstanceTypeMachineCapabilityType::Cpu => write!(f, "CPU"),
            InstanceTypeMachineCapabilityType::Gpu => write!(f, "GPU"),
            InstanceTypeMachineCapabilityType::Memory => write!(f, "MEMORY"),
            InstanceTypeMachineCapabilityType::Storage => write!(f, "STORAGE"),
            InstanceTypeMachineCapabilityType::Network => write!(f, "NETWORK"),
            InstanceTypeMachineCapabilityType::Infiniband => write!(f, "INFINIBAND"),
            InstanceTypeMachineCapabilityType::Dpu => write!(f, "DPU"),
        }
    }
}

impl From<InstanceTypeMachineCapabilityType> for rpc::InstanceTypeMachineCapabilityType {
    fn from(t: InstanceTypeMachineCapabilityType) -> Self {
        match t {
            InstanceTypeMachineCapabilityType::Cpu => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeCpu
            }
            InstanceTypeMachineCapabilityType::Gpu => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeGpu
            }
            InstanceTypeMachineCapabilityType::Memory => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeMemory
            }
            InstanceTypeMachineCapabilityType::Storage => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeStorage
            }
            InstanceTypeMachineCapabilityType::Network => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeNetwork
            }
            InstanceTypeMachineCapabilityType::Infiniband => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeInfiniband
            }
            InstanceTypeMachineCapabilityType::Dpu => {
                rpc::InstanceTypeMachineCapabilityType::CapTypeDpu
            }
        }
    }
}

impl TryFrom<rpc::InstanceTypeMachineCapabilityType> for InstanceTypeMachineCapabilityType {
    type Error = CarbideError;

    fn try_from(t: rpc::InstanceTypeMachineCapabilityType) -> Result<Self, Self::Error> {
        match t {
            rpc::InstanceTypeMachineCapabilityType::CapTypeInvalid => Err(CarbideError::from(
                crate::model::ConfigValidationError::InvalidValue(t.as_str_name().to_string()),
            )),
            rpc::InstanceTypeMachineCapabilityType::CapTypeCpu => {
                Ok(InstanceTypeMachineCapabilityType::Cpu)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeGpu => {
                Ok(InstanceTypeMachineCapabilityType::Gpu)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeMemory => {
                Ok(InstanceTypeMachineCapabilityType::Memory)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeStorage => {
                Ok(InstanceTypeMachineCapabilityType::Storage)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeNetwork => {
                Ok(InstanceTypeMachineCapabilityType::Network)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeInfiniband => {
                Ok(InstanceTypeMachineCapabilityType::Infiniband)
            }
            rpc::InstanceTypeMachineCapabilityType::CapTypeDpu => {
                Ok(InstanceTypeMachineCapabilityType::Dpu)
            }
        }
    }
}

/* ********************************** */
/*    InstanceTypeMachineCapability   */
/* ********************************** */

/// InstanceTypeMachineCapability holds the details of a
/// single desired capability of a machine.  This could technically
/// represent more than one physical component, such as a server
/// with multiple CPUs of the exact same type.
///
/// For example, type=cpu, name=xeon, count=2
/// could represent a single CPU capability for a machine.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct InstanceTypeMachineCapability {
    pub capability_type: InstanceTypeMachineCapabilityType,
    pub name: Option<String>,
    pub frequency: Option<String>,
    pub capacity: Option<String>,
    pub vendor: Option<String>,
    pub count: Option<u32>,
    pub hardware_revision: Option<String>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
}

impl TryFrom<rpc::InstanceTypeMachineCapabilityAttributes> for InstanceTypeMachineCapability {
    type Error = CarbideError;

    fn try_from(cap: rpc::InstanceTypeMachineCapabilityAttributes) -> Result<Self, Self::Error> {
        Ok(InstanceTypeMachineCapability {
            capability_type: cap.capability_type().try_into()?,
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
        })
    }
}

impl TryFrom<InstanceTypeMachineCapability> for rpc::InstanceTypeMachineCapabilityAttributes {
    type Error = CarbideError;

    fn try_from(cap: InstanceTypeMachineCapability) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceTypeMachineCapabilityAttributes {
            capability_type: rpc::InstanceTypeMachineCapabilityType::from(cap.capability_type)
                .into(),
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
        })
    }
}

/* ********************************** */
/*            InstanceType            */
/* ********************************** */

/// InstanceType represents a collection of _desired_
/// machine capabilities.
/// An InstanceType is used to create pools of "allocatable"
/// machines based on their capabilities.
///
/// A provider would define an InstanceType and then define
/// an allocation constraint with that InstanceType to define
/// how many instances of a given InstanceType a tenant can
/// create/allocate.
///
/// When an instance allocation is requested, the InstanceType
/// is then used to filter machines to select an available
/// machine that matches the set of desired capabilities.
#[derive(Clone, Debug, PartialEq)]
pub struct InstanceType {
    pub id: InstanceTypeId,
    pub desired_capabilities: Vec<InstanceTypeMachineCapability>,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub metadata: Metadata,
}

impl TryFrom<InstanceType> for rpc::InstanceType {
    type Error = CarbideError;

    fn try_from(inst_type: InstanceType) -> Result<Self, Self::Error> {
        let mut desired_capabilities = Vec::<rpc::InstanceTypeMachineCapabilityAttributes>::new();

        for cap_attrs in inst_type.desired_capabilities {
            desired_capabilities.push(cap_attrs.try_into()?);
        }

        let attributes = rpc::InstanceTypeAttributes {
            desired_capabilities,
        };

        Ok(rpc::InstanceType {
            id: inst_type.id.to_string(),
            version: inst_type.version.to_string(),
            attributes: Some(attributes),
            created_at: Some(inst_type.created.to_string()),
            metadata: Some(rpc::Metadata {
                name: inst_type.metadata.name,
                description: inst_type.metadata.description,
                labels: inst_type
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
    fn test_model_instance_type_to_rpc_conversion() {
        let version = ConfigVersion::initial();

        let req_type = rpc::InstanceType {
            id: "test_id".to_string(),
            version: version.to_string(),
            metadata: Some(rpc::Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
            attributes: Some(rpc::InstanceTypeAttributes {
                desired_capabilities: vec![rpc::InstanceTypeMachineCapabilityAttributes {
                    capability_type: rpc::InstanceTypeMachineCapabilityType::CapTypeCpu.into(),
                    name: Some("pentium 4 HT".to_string()),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: Some("9001 GB".to_string()),
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: Some("rev 9001".to_string()),
                    cores: Some(1),
                    threads: Some(2),
                }],
            }),
            created_at: Some("2023-01-01 00:00:00 UTC".to_string()),
        };

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version,
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapability {
                capability_type: rpc::InstanceTypeMachineCapabilityType::CapTypeCpu
                    .try_into()
                    .unwrap(),
                name: Some("pentium 4 HT".to_string()),
                frequency: Some("1.3 GHz".to_string()),
                capacity: Some("9001 GB".to_string()),
                vendor: Some("intel".to_string()),
                count: Some(1),
                hardware_revision: Some("rev 9001".to_string()),
                cores: Some(1),
                threads: Some(2),
            }],
        };

        // Verify that we can go from an internal instance type to the
        // protobuf InstanceType message
        assert_eq!(req_type, rpc::InstanceType::try_from(inst_type).unwrap());
    }
}
