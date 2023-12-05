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

use serde::{Deserialize, Serialize};

/// Data that we gathered about a particular endpoint during site exploration
/// This data is stored as JSON in the Database. Therefore the format can
/// only be adjusted in a backward compatible fashion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EndpointExplorationReport {
    /// The type of the endpoint
    pub endpoint_type: EndpointType,
    /// If the endpoint could not be explored, this contains the last error
    pub last_exploration_error: Option<EndpointExplorationError>,
    /// Vendor as reported by Redfish
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    /// `Managers` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managers: Vec<Manager>,
    /// `Systems` reported by Redfish
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub systems: Vec<ComputerSystem>,
}

impl EndpointExplorationReport {
    /// Returns a report for an endpoint that is not reachable and could therefore
    /// not be explored
    pub fn new_with_error(e: EndpointExplorationError) -> Self {
        Self {
            endpoint_type: EndpointType::Unknown,
            last_exploration_error: Some(e),
            managers: Vec::new(),
            systems: Vec::new(),
            vendor: None,
        }
    }
}

/// Describes errors that might have been encountered during exploring an endpoint
#[derive(thiserror::Error, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "Type", rename_all = "PascalCase")]
pub enum EndpointExplorationError {
    /// It was not possible to establish a connection to the endpoint
    #[error("The endpoint was not reachable")]
    Unreachable,
    /// A generic redfish error. No additional details are available
    #[error("Error while performing Redfish request: {details}")]
    #[serde(rename_all = "PascalCase")]
    RedfishError { details: String },
    /// The endpoint returned a 401 Unauthorized Status
    #[error("Unauthorized: {details}")]
    #[serde(rename_all = "PascalCase")]
    Unauthorized { details: String },
    /// Credentials for the Host are not available
    #[error("Credentials for the Host are not available")]
    MissingCredentials,
    /// An error which is not further detailed
    #[error("Error: {details}")]
    #[serde(rename_all = "PascalCase")]
    Other { details: String },
}

/// The type of the endpoint
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EndpointType {
    Bmc,
    Unknown,
}

/// `ComputerSystem` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ComputerSystem {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ethernet_interfaces: Vec<EthernetInterface>,
    pub id: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

/// `ComputerSystem` definition. Matches redfish definition
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Manager {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ethernet_interfaces: Vec<EthernetInterface>,
    pub id: String,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EthernetInterface {
    pub description: Option<String>,
    pub id: Option<String>,
    pub interface_enabled: Option<bool>,
    #[serde(rename = "MACAddress")]
    pub mac_address: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_endpoint_exloration_error() {
        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::Unreachable);

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"Unreachable"}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );

        let report =
            EndpointExplorationReport::new_with_error(EndpointExplorationError::RedfishError {
                details: "test".to_string(),
            });

        let serialized = serde_json::to_string(&report).unwrap();
        assert_eq!(
            serialized,
            r#"{"EndpointType":"Unknown","LastExplorationError":{"Type":"RedfishError","Details":"test"}}"#
        );
        assert_eq!(
            serde_json::from_str::<EndpointExplorationReport>(&serialized).unwrap(),
            report
        );
    }
}
