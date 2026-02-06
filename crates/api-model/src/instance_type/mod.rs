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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::{common as rpc_common, forge as rpc};
use carbide_uuid::instance_type::InstanceTypeId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::PgRow;

use super::machine::capabilities::{
    self as machine_caps, MachineCapabilitiesSet, MachineCapabilityDeviceType,
    MachineCapabilityType,
};
use crate::metadata::Metadata;

/* **************************************** */
/*    InstanceTypeMachineCapabilityFilter   */
/* **************************************** */

/// InstanceTypeMachineCapabilityFilter holds the details of a
/// single desired capability of a machine.  This could technically
/// represent more than one physical component, such as a server
/// with multiple CPUs of the exact same type.
///
/// For example, type=cpu, name=xeon, count=2
/// could represent a single CPU capability for a machine.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct InstanceTypeMachineCapabilityFilter {
    pub capability_type: MachineCapabilityType,
    pub name: Option<String>,
    pub frequency: Option<String>,
    pub capacity: Option<String>,
    pub vendor: Option<String>,
    pub count: Option<u32>,
    pub hardware_revision: Option<String>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
    pub inactive_devices: Option<Vec<u32>>,
    pub device_type: Option<MachineCapabilityDeviceType>,
}

impl InstanceTypeMachineCapabilityFilter {
    fn matches_machine_cpu_capability(&self, mac_cap: &machine_caps::MachineCapabilityCpu) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (self.cores, mac_cap.cores) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (self.threads, mac_cap.threads) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }

    fn matches_machine_gpu_capability(&self, mac_cap: &machine_caps::MachineCapabilityGpu) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (self.cores, mac_cap.cores) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (self.threads, mac_cap.threads) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.frequency, &mac_cap.frequency) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.capacity, &mac_cap.memory_capacity) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }

    fn matches_machine_memory_capability(
        &self,
        mac_cap: &machine_caps::MachineCapabilityMemory,
    ) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.capacity, &mac_cap.capacity) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }

    fn matches_machine_storage_capability(
        &self,
        mac_cap: &machine_caps::MachineCapabilityStorage,
    ) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.capacity, &mac_cap.capacity) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }

    fn matches_machine_network_capability(
        &self,
        mac_cap: &machine_caps::MachineCapabilityNetwork,
    ) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        }) && (match (&self.device_type, &mac_cap.device_type) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }

    fn matches_machine_infiniband_capability(
        &self,
        mac_cap: &machine_caps::MachineCapabilityInfiniband,
    ) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.vendor, &mac_cap.vendor) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.inactive_devices, &mac_cap.inactive_devices) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        })
    }

    fn matches_machine_dpu_capability(&self, mac_cap: &machine_caps::MachineCapabilityDpu) -> bool {
        (match (&self.name, &mac_cap.name) {
            (None, _) => true,
            (Some(c), mc) => c == mc,
        }) && (match (&self.hardware_revision, &mac_cap.hardware_revision) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(c), Some(mc)) => c == mc,
        })
    }
}

impl TryFrom<rpc::InstanceTypeMachineCapabilityFilterAttributes>
    for InstanceTypeMachineCapabilityFilter
{
    type Error = RpcDataConversionError;

    fn try_from(
        cap: rpc::InstanceTypeMachineCapabilityFilterAttributes,
    ) -> Result<Self, Self::Error> {
        Ok(InstanceTypeMachineCapabilityFilter {
            capability_type: cap.capability_type().try_into()?,
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
            inactive_devices: cap.inactive_devices.map(|l| l.items),
            device_type: cap
                .device_type
                .map(|dt| {
                    rpc::MachineCapabilityDeviceType::try_from(dt)
                        .map_err(|_| {
                            RpcDataConversionError::InvalidValue(
                                "MachineCapabilityDeviceType".to_string(),
                                dt.to_string(),
                            )
                        })
                        .and_then(|rpc_dt| rpc_dt.try_into())
                })
                .transpose()?,
        })
    }
}

impl TryFrom<InstanceTypeMachineCapabilityFilter>
    for rpc::InstanceTypeMachineCapabilityFilterAttributes
{
    type Error = RpcDataConversionError;

    fn try_from(cap: InstanceTypeMachineCapabilityFilter) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceTypeMachineCapabilityFilterAttributes {
            capability_type: rpc::MachineCapabilityType::from(cap.capability_type).into(),
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
            inactive_devices: cap
                .inactive_devices
                .map(|l| rpc_common::Uint32List { items: l }),
            device_type: cap
                .device_type
                .map(|dt| rpc::MachineCapabilityDeviceType::from(dt).into()),
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
    pub desired_capabilities: Vec<InstanceTypeMachineCapabilityFilter>,
    pub version: ConfigVersion,
    pub created: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub metadata: Metadata,
}

impl<'r> sqlx::FromRow<'r, PgRow> for InstanceType {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: labels.0,
        };

        let desired_capabilities: sqlx::types::Json<Vec<InstanceTypeMachineCapabilityFilter>> =
            row.try_get("desired_capabilities")?;

        Ok(InstanceType {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            created: row.try_get("created")?,
            deleted: row.try_get("deleted")?,
            metadata,
            desired_capabilities: desired_capabilities.0,
        })
    }
}

impl InstanceType {
    /// Check whether a set of capabilities satisfies the
    /// requirements of an InstanceType
    ///
    /// * `machine_caps` - A reference to a MachineCapabilitiesSet struct with the capabilities to check
    pub fn matches_capability_set(&self, machine_caps: &MachineCapabilitiesSet) -> bool {
        for cap in self.desired_capabilities.iter() {
            match cap.capability_type {
                MachineCapabilityType::Cpu => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps.cpu.iter().try_fold(0, |found_cnt: u32, c| {
                            if !cap.matches_machine_cpu_capability(c) {
                                return Some(found_cnt);
                            }

                            // Update the found count.
                            match found_cnt.overflowing_add(c.count) {
                                (_, true) => None, // overflow
                                (found_cnt, _) if found_cnt > desired_cnt => None,
                                (found_cnt, _) => Some(found_cnt),
                            }
                        }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .cpu
                        .iter()
                        .any(|c| cap.matches_machine_cpu_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }
                MachineCapabilityType::Gpu => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps.gpu.iter().try_fold(0, |found_cnt: u32, c| {
                            if !cap.matches_machine_gpu_capability(c) {
                                return Some(found_cnt);
                            }

                            // Update the found count.
                            match found_cnt.overflowing_add(c.count) {
                                (_, true) => None, // overflow
                                (found_cnt, _) if found_cnt > desired_cnt => None,
                                (found_cnt, _) => Some(found_cnt),
                            }
                        }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch.
                        }
                    } else if !machine_caps
                        .gpu
                        .iter()
                        .any(|c| cap.matches_machine_gpu_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }
                MachineCapabilityType::Memory => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps.memory.iter().try_fold(0, |found_cnt: u32, c| {
                            if !cap.matches_machine_memory_capability(c) {
                                return Some(found_cnt);
                            }

                            // Update the found count.
                            match found_cnt.overflowing_add(c.count) {
                                (_, true) => None, // overflow
                                (found_cnt, _) if found_cnt > desired_cnt => None,
                                (found_cnt, _) => Some(found_cnt),
                            }
                        }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .memory
                        .iter()
                        .any(|c| cap.matches_machine_memory_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }
                MachineCapabilityType::Storage => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps
                            .storage
                            .iter()
                            .try_fold(0, |found_cnt: u32, c| {
                                if !cap.matches_machine_storage_capability(c) {
                                    return Some(found_cnt);
                                }

                                // Update the found count.
                                match found_cnt.overflowing_add(c.count) {
                                    (_, true) => None, // overflow
                                    (found_cnt, _) if found_cnt > desired_cnt => None,
                                    (found_cnt, _) => Some(found_cnt),
                                }
                            }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .storage
                        .iter()
                        .any(|c| cap.matches_machine_storage_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }

                MachineCapabilityType::Network => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps
                            .network
                            .iter()
                            .try_fold(0, |found_cnt: u32, c| {
                                if !cap.matches_machine_network_capability(c) {
                                    return Some(found_cnt);
                                }

                                // Update the found count.
                                match found_cnt.overflowing_add(c.count) {
                                    (_, true) => None, // overflow
                                    (found_cnt, _) if found_cnt > desired_cnt => None,
                                    (found_cnt, _) => Some(found_cnt),
                                }
                            }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .network
                        .iter()
                        .any(|c| cap.matches_machine_network_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }

                MachineCapabilityType::Infiniband => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps
                            .infiniband
                            .iter()
                            .try_fold(0, |found_cnt: u32, c| {
                                if !cap.matches_machine_infiniband_capability(c) {
                                    return Some(found_cnt);
                                }

                                // Update the found count.
                                match found_cnt.overflowing_add(c.count) {
                                    (_, true) => None, // overflow
                                    (found_cnt, _) if found_cnt > desired_cnt => None,
                                    (found_cnt, _) => Some(found_cnt),
                                }
                            }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .infiniband
                        .iter()
                        .any(|c| cap.matches_machine_infiniband_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }

                MachineCapabilityType::Dpu => {
                    if let Some(desired_cnt) = cap.count {
                        match machine_caps.dpu.iter().try_fold(0, |found_cnt: u32, c| {
                            if !cap.matches_machine_dpu_capability(c) {
                                return Some(found_cnt);
                            }

                            // Update the found count.
                            match found_cnt.overflowing_add(c.count) {
                                (_, true) => None, // overflow
                                (found_cnt, _) if found_cnt > desired_cnt => None,
                                (found_cnt, _) => Some(found_cnt),
                            }
                        }) {
                            Some(found_cnt) if found_cnt == desired_cnt => {} // Do nothing.
                            _ => return false, // Desired count was exceeded or count mismatch
                        }
                    } else if !machine_caps
                        .dpu
                        .iter()
                        .any(|c| cap.matches_machine_dpu_capability(c))
                    {
                        return false; // We just needed to find at least one match, but there were zero.
                    }
                }
            }
        }

        true
    }
}

impl TryFrom<InstanceType> for rpc::InstanceType {
    type Error = RpcDataConversionError;

    fn try_from(inst_type: InstanceType) -> Result<Self, Self::Error> {
        let mut desired_capabilities =
            Vec::<rpc::InstanceTypeMachineCapabilityFilterAttributes>::new();

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
    use crate::machine::capabilities;
    use crate::machine::capabilities::MachineCapabilityDeviceType;

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
                desired_capabilities: vec![rpc::InstanceTypeMachineCapabilityFilterAttributes {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.into(),
                    name: Some("pentium 4 HT".to_string()),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: Some("9001 GB".to_string()),
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: Some("rev 9001".to_string()),
                    cores: Some(1),
                    threads: Some(2),
                    inactive_devices: Some(rpc_common::Uint32List { items: vec![2, 4] }),
                    device_type: Some(rpc::MachineCapabilityDeviceType::Unknown as i32),
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
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                name: Some("pentium 4 HT".to_string()),
                frequency: Some("1.3 GHz".to_string()),
                capacity: Some("9001 GB".to_string()),
                vendor: Some("intel".to_string()),
                count: Some(1),
                hardware_revision: Some("rev 9001".to_string()),
                cores: Some(1),
                threads: Some(2),
                inactive_devices: Some(vec![2, 4]),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
        };

        // Verify that we can go from an internal instance type to the
        // protobuf InstanceType message
        assert_eq!(req_type, rpc::InstanceType::try_from(inst_type).unwrap());
    }

    #[test]
    fn test_model_instance_type_match_fails_on_empty_machine() {
        //
        // Verify that an empty capability set fails to match.
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                ..Default::default()
            }],
        };

        let machine_cap_set = MachineCapabilitiesSet {
            cpu: vec![],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(!inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_loose_type_match() {
        //
        // Verify that a general match works on just type
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                ..Default::default()
            }],
        };

        let machine_cap_set = MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_zero_count_match() {
        //
        // Verify that a general match works on just type
        // with a zero-count InstanceType filter
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    count: Some(0),
                    ..Default::default()
                },
            ],
        };

        let machine_cap_set = MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_specific_match() {
        //
        // Verify that a more specific capability set matches
        //

        let machine_cap_set = MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![capabilities::MachineCapabilityGpu {
                name: "rtx6000".to_string(),
                frequency: None,
                vendor: Some("nvidia".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
                memory_capacity: Some("12 GB".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
            memory: vec![capabilities::MachineCapabilityMemory {
                name: "ddr4".to_string(),
                vendor: Some("micron".to_string()),
                count: 1,
                capacity: Some("16 GB".to_string()),
            }],
            storage: vec![capabilities::MachineCapabilityStorage {
                name: "HDD".to_string(),
                vendor: Some("western digital".to_string()),
                count: 1,
                capacity: Some("2 TB".to_string()),
            }],
            network: vec![
                capabilities::MachineCapabilityNetwork {
                    name: "e1000".to_string(),
                    vendor: Some("intel".to_string()),
                    count: 2,
                    device_type: Some(MachineCapabilityDeviceType::Unknown),
                },
                capabilities::MachineCapabilityNetwork {
                    name: "e10000".to_string(),
                    vendor: Some("intel".to_string()),
                    count: 1,
                    device_type: Some(MachineCapabilityDeviceType::Unknown),
                },
            ],
            infiniband: vec![capabilities::MachineCapabilityInfiniband {
                name: "connectx7".to_string(),
                vendor: "nvidia".to_string(),
                count: 1,
                inactive_devices: vec![2, 4],
            }],
            dpu: vec![capabilities::MachineCapabilityDpu {
                name: "bluefield3".to_string(),
                hardware_revision: Some("abc123".to_string()),
                count: 1,
            }],
        };

        // First test with a simple InstanceType

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                name: Some("pentium 4 HT".to_string()),
                frequency: Some("1.3 GHz".to_string()),
                capacity: None,
                vendor: Some("intel".to_string()),
                count: Some(1),
                hardware_revision: None,
                cores: Some(1),
                threads: Some(2),
                inactive_devices: None,
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));

        // Then a fuller instance type

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    name: Some("pentium 4 HT".to_string()),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: None,
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: None,
                    cores: Some(1),
                    threads: Some(2),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeGpu.try_into().unwrap(),
                    name: Some("rtx6000".to_string()),
                    frequency: None,
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    cores: Some(1),
                    threads: Some(2),
                    capacity: Some("12 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeMemory
                        .try_into()
                        .unwrap(),
                    name: Some("ddr4".to_string()),
                    vendor: Some("micron".to_string()),
                    count: Some(1),
                    capacity: Some("16 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeStorage
                        .try_into()
                        .unwrap(),
                    name: Some("HDD".to_string()),
                    vendor: Some("western digital".to_string()),
                    count: Some(1),
                    capacity: Some("2 TB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeNetwork
                        .try_into()
                        .unwrap(),
                    name: Some("e10000".to_string()),
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeInfiniband
                        .try_into()
                        .unwrap(),
                    name: Some("connectx7".to_string()),
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    inactive_devices: Some(vec![2, 4]),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    name: Some("bluefield3".to_string()),
                    hardware_revision: Some("abc123".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
            ],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));

        // Then a fuller instance type but without caring about name/model

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    name: None,
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: None,
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: None,
                    cores: Some(1),
                    threads: Some(2),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeGpu.try_into().unwrap(),
                    frequency: None,
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    cores: Some(1),
                    threads: Some(2),
                    capacity: Some("12 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeMemory
                        .try_into()
                        .unwrap(),
                    vendor: Some("micron".to_string()),
                    count: Some(1),
                    capacity: Some("16 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeStorage
                        .try_into()
                        .unwrap(),
                    vendor: Some("western digital".to_string()),
                    count: Some(1),
                    capacity: Some("2 TB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeNetwork
                        .try_into()
                        .unwrap(),
                    vendor: Some("intel".to_string()),
                    count: Some(3), // There are two intel nics of different speeds.  2x of one and 1x of the other.

                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeInfiniband
                        .try_into()
                        .unwrap(),
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    inactive_devices: Some(vec![2, 4]),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    hardware_revision: Some("abc123".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
            ],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }
}
