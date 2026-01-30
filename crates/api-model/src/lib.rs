/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Describes the Forge site controller internal data model
//!
//! The model described here is used in both internal decision logic and might
//! be stored in database fields.
//! Data inside this module therefore needs to be backward compatible with previous
//! versions of Forge that are deployed.
//!
//! The module should only contain data definitions and associated helper functions,
//! but no actual business logic.

use std::fmt;
use std::ops::{Deref, DerefMut};

use carbide_uuid::network::NetworkSegmentId;
use instance::config::network::InterfaceFunctionId;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

pub mod address_selection_strategy;
pub mod attestation;
pub mod bmc_info;
pub mod controller_outcome;
pub mod dhcp_entry;
pub mod dhcp_record;
pub mod dns;
pub mod dpa_interface;
pub mod dpu_machine_update;
pub mod dpu_remediation;
pub mod errors;
pub mod expected_machine;
pub mod expected_power_shelf;
pub mod expected_switch;
pub mod extension_service;
pub mod firmware;
pub mod hardware_info;
pub mod host_machine_update;
pub mod ib;
pub mod ib_partition;
pub mod instance;
pub mod instance_address;
pub mod instance_type;
pub mod machine;
pub mod machine_boot_override;
pub mod machine_interface_address;
pub mod machine_update_module;
pub mod machine_validation;
pub mod metadata;
pub mod network_devices;
pub mod network_prefix;
pub mod network_security_group;
pub mod network_segment;
pub mod network_segment_state_history;
pub mod os;
pub mod power_manager;
pub mod power_shelf;
pub mod predicted_machine_interface;
pub mod pxe;
pub mod rack;
pub mod rack_state_history;
pub mod redfish;
pub mod resource_pool;
pub mod route_server;
pub mod site_explorer;
pub mod sku;
pub mod storage;
pub mod switch;
pub mod tenant;
pub mod vpc;
pub mod vpc_prefix;

/// Converts a `Vec<T>` of any type `T` that is convertible to a type `R`
/// into a `Vec<R>`.
pub fn try_convert_vec<T, R, E>(source: Vec<T>) -> Result<Vec<R>, E>
where
    R: TryFrom<T, Error = E>,
{
    source.into_iter().map(R::try_from).collect()
}

/// Error that is returned when we validate various configurations that are obtained
/// from Forge users.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ConfigValidationError {
    /// A configuration value is invalid
    #[error("Invalid value: {0}")]
    InvalidValue(String),

    #[error("Found unknown segments.")]
    UnknownSegments,

    #[error("Segment is still not updated for {0:?}.")]
    MissingSegment(InterfaceFunctionId),

    #[error("No Vpc is attached to segment {0}.")]
    VpcNotAttachedToSegment(NetworkSegmentId),

    #[error("Found segments attached to multiple VPCs.")]
    MultipleVpcFound,

    #[error("IP addresses / IP networks not configured for the same prefixes.")]
    NetworkPrefixAllocationMismatch,

    #[error("Segment {0} is not yet ready. Current state: {1}")]
    NetworkSegmentNotReady(NetworkSegmentId, String),

    #[error("Segment {0} is requested to be deleted.")]
    NetworkSegmentToBeDeleted(NetworkSegmentId),

    #[error("Configuration value cannot be modified: {0}")]
    ConfigCanNotBeModified(String),

    #[error("Duplicate Tenant KeySet ID found: {0}")]
    DuplicateTenantKeysetId(String),

    #[error("More than {0} Tenant KeySet IDs are not allowed")]
    TenantKeysetIdsOverMax(usize),

    #[error("Storage Volumes defined {0} > 8")]
    StorageVolumeCountExceeded(usize),

    #[error("Instance cannot connect to multiple storage clusters")]
    StorageClusterInvalid,

    #[error("Specified network is not available on the requested host")]
    NetworkSegmentUnavailableOnHost,

    #[error("Another instance network config update is already in progress.")]
    InstanceNetworkConfigUpdateAlreadyInProgress,

    #[error("Instance deletion request is already received.")]
    InstanceDeletionIsRequested,

    #[error("Instance is not Ready yet. Can't apply the config.")]
    InvalidState,
}

impl ConfigValidationError {
    /// Creates a [ConfigValidationError::InvalidValue] variant
    pub fn invalid_value<T: Into<String>>(value: T) -> Self {
        Self::InvalidValue(value.into())
    }
}

// Error that is returned when we validate various status that are obtained
/// from Forge system components
#[derive(Debug, thiserror::Error, Clone)]
pub enum StatusValidationError {
    /// A configuration value is invalid
    #[error("Invalid value: {0}")]
    InvalidValue(String),
}

/// A transparent wrapper around [`MacAddress`] that enables serde serialization
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SerializableMacAddress(MacAddress);

impl Deref for SerializableMacAddress {
    type Target = MacAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SerializableMacAddress {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<MacAddress> for SerializableMacAddress {
    fn from(mac: MacAddress) -> Self {
        SerializableMacAddress(mac)
    }
}

impl From<SerializableMacAddress> for MacAddress {
    fn from(mac: SerializableMacAddress) -> Self {
        mac.0
    }
}

#[cfg(test)]
impl SerializableMacAddress {
    /// Converts the wrapper into a plain `MacAddress`
    pub fn into_inner(self) -> MacAddress {
        self.0
    }
}

impl Serialize for SerializableMacAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SerializableMacAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let mac: MacAddress = str_value
            .parse()
            .map_err(|_| Error::custom(format!("Invalid MAC address: {str_value}")))?;
        Ok(SerializableMacAddress(mac))
    }
}

/// Specifies the SLA for a resource in a specific state
#[derive(Default, Debug, Clone)]
pub struct StateSla {
    /// The SLA for the current state
    /// This field will be absent if there is no SLA defined for a field
    /// A value of 0 (instead of absent) will indicate the `time_in_state` will always
    /// be above SLA. This can happen for certain states that should never be entered
    /// for correct operation.
    pub sla: ::core::option::Option<std::time::Duration>,
    /// Whether the object has been in the state for a longer time than permitted
    /// by the SLA.
    pub time_in_state_above_sla: bool,
}

impl StateSla {
    /// Creates a `StateSla` object which indicates that no SLA applies for the state
    pub fn no_sla() -> Self {
        Self {
            sla: None,
            time_in_state_above_sla: false,
        }
    }

    /// Creates a new StateSla object with the SLA that immediately evaluates
    /// if a certain time is above the SLA
    pub fn with_sla(sla: std::time::Duration, time_in_state: std::time::Duration) -> Self {
        Self {
            time_in_state_above_sla: time_in_state > sla,
            sla: Some(sla),
        }
    }
}

impl From<StateSla> for rpc::forge::StateSla {
    fn from(value: StateSla) -> Self {
        rpc::forge::StateSla {
            sla: value.sla.map(|sla| sla.into()),
            time_in_state_above_sla: value.time_in_state_above_sla,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn serialize_mac_address() {
        let mac = MacAddress::new([1, 2, 3, 4, 5, 6]);
        let serialized = serde_json::to_string(&SerializableMacAddress::from(mac)).unwrap();
        assert_eq!(serialized, "\"01:02:03:04:05:06\"");
        assert_eq!(
            serde_json::from_str::<SerializableMacAddress>(&serialized)
                .unwrap()
                .into_inner(),
            mac
        );
    }
}

/// DPU related config.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DpuModel {
    BlueField2,
    BlueField3,
    Unknown,
}

impl<T> From<T> for DpuModel
where
    T: AsRef<str>,
{
    fn from(model: T) -> Self {
        match model.as_ref().to_lowercase().replace("-", " ") {
            value if value.contains("bluefield 2") => DpuModel::BlueField2,
            value if value.contains("bluefield 3") => DpuModel::BlueField3,
            _ => DpuModel::Unknown,
        }
    }
}

impl fmt::Display for DpuModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", format!("{self:?}").to_lowercase())
    }
}
