/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use std::ops::{Deref, DerefMut};

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

pub mod config_version;
pub mod hardware_info;
pub mod instance;
pub mod machine;
pub mod network_segment;

/// Enumerates errors that can occur when converting from the RPC data format
/// into the internal data model
#[derive(Debug, thiserror::Error)]
pub enum RpcDataConversionError {
    #[error("Field {0} is not valid base64")]
    InvalidBase64Data(&'static str),
    #[error("Virtual Function ID of value {0} is not in the expected range 1-16")]
    InvalidVirtualFunctionId(usize),
    #[error("IP Address {0} is not valid")]
    InvalidIpAddress(String),
    #[error("MAC address {0} is not valid")]
    InvalidMacAddress(String),
    #[error("Version string {0} is not valid")]
    InvalidConfigVersion(String),
    #[error("Timestamp {0} is not valid")]
    InvalidTimestamp(String),
    #[error("Tenant Org {0} is not valid")]
    InvalidTenantOrg(String),
    #[error("Interface Function Type {0} is not valid")]
    InvalidInterfaceFunctionType(i32),
    #[error("Invalid UUID for field {0}")]
    InvalidUuid(&'static str),
    #[error("Argument {0} is missing")]
    MissingArgument(&'static str),
}

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

    #[error("No Vpc is attached to segment {0}.")]
    VpcNotAttachedToSegment(uuid::Uuid),

    #[error("Found segments attached to multiple VPCs.")]
    MultipleVpcFound,

    #[error("Segment {0} is not yet ready. Current state: {1}")]
    NetworkSegmentNotReady(uuid::Uuid, String),

    #[error("Segment {0} is requested to be deleted.")]
    NetworkSegmentToBeDeleted(uuid::Uuid),
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

impl StatusValidationError {
    /// Creates a [StatusValidationError::InvalidValue] variant
    pub fn invalid_value<T: Into<String>>(value: T) -> Self {
        Self::InvalidValue(value.into())
    }
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
            .map_err(|_| Error::custom(format!("Invalid MAC address: {}", str_value)))?;
        Ok(SerializableMacAddress(mac))
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
