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
//! Carbide gRPC and protobuf module
//!
//! This module contains the gRPC and protocol buffer definitions to generate a client or server to
//! interact with the API Service
//!

use std::fmt::Display;
use std::ops::Deref;
use std::ops::DerefMut;
use std::str::FromStr;

use mac_address::{MacAddress, MacParseError};
use prost::Message;

pub use crate::protos::forge::{
    self, forge_agent_control_response, machine_credentials_update_request::CredentialPurpose,
    machine_discovery_info::DiscoveryData, CredentialType, Domain, DomainList,
    ForgeScoutErrorReport, ForgeScoutErrorReportResult, Instance, InstanceAllocationRequest,
    InstanceConfig, InstanceInterfaceConfig, InstanceInterfaceStatus,
    InstanceInterfaceStatusObservation, InstanceList, InstanceNetworkConfig, InstanceNetworkStatus,
    InstanceNetworkStatusObservation, InstanceReleaseRequest, InstanceSearchQuery, InstanceStatus,
    InstanceTenantStatus, InterfaceFunctionType, Machine, MachineCleanupInfo, MachineDiscoveryInfo,
    MachineEvent, MachineId, MachineInterface, MachineList, NetworkPrefixEvent, NetworkSegment,
    NetworkSegmentList, ObservedInstanceNetworkStatusRecordResult, ResourcePoolType, SyncState,
    TenantConfig, TenantState, Uuid,
};
pub use crate::protos::forge::{
    IbPartition, IbPartitionCreationRequest, IbPartitionDeletionRequest, IbPartitionDeletionResult,
    IbPartitionList, IbPartitionQuery, InstanceIbInterfaceConfig, InstanceIbInterfaceStatus,
    InstanceInfinibandConfig, InstanceInfinibandStatus,
};
pub use crate::protos::machine_discovery::{
    self, BlockDevice, Cpu, DiscoveryInfo, DmiData, NetworkInterface, NvmeDevice,
    PciDeviceProperties,
};
pub use crate::protos::site_explorer;

pub mod forge_tls_client;
pub mod protos;

pub mod forge_resolver;
pub const REFLECTION_API_SERVICE_DESCRIPTOR: &[u8] = tonic::include_file_descriptor_set!("forge");

pub fn get_encoded_reflection_service_fd() -> Vec<u8> {
    let mut expected = Vec::new();
    prost_types::FileDescriptorSet::decode(REFLECTION_API_SERVICE_DESCRIPTOR)
        .expect("decode reflection service file descriptor set")
        .file[0]
        .encode(&mut expected)
        .expect("encode reflection service file descriptor");
    expected
}

/// A wrapper around the prost timestamp which allows for serde serialization
/// and has helper methods to convert from and into std::time::SystemTime and DateTime
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct Timestamp(prost_types::Timestamp);

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for Timestamp {
    type Target = prost_types::Timestamp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Timestamp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<prost_types::Timestamp> for Timestamp {
    fn from(ts: prost_types::Timestamp) -> Self {
        Self(ts)
    }
}

impl From<Timestamp> for prost_types::Timestamp {
    fn from(ts: Timestamp) -> prost_types::Timestamp {
        ts.0
    }
}

impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    fn from(time: chrono::DateTime<chrono::Utc>) -> Self {
        Self::from(std::time::SystemTime::from(time))
    }
}

impl From<std::time::SystemTime> for Timestamp {
    fn from(time: std::time::SystemTime) -> Self {
        Self(prost_types::Timestamp::from(time))
    }
}

impl TryFrom<Timestamp> for std::time::SystemTime {
    type Error = prost_types::TimestampError;

    fn try_from(ts: Timestamp) -> Result<Self, Self::Error> {
        std::time::SystemTime::try_from(ts.0)
    }
}

impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = prost_types::TimestampError;

    fn try_from(ts: Timestamp) -> Result<Self, Self::Error> {
        std::time::SystemTime::try_from(ts.0).map(|t| t.into())
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // We serialize the timestamp as chrono string
        match chrono::DateTime::<chrono::Utc>::try_from(self.clone()) {
            Ok(ts) => ts.serialize(s),
            Err(_) => chrono::DateTime::<chrono::Utc>::default().serialize(s),
        }
    }
}

impl prost::Message for Timestamp {
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: prost::bytes::BufMut,
        Self: Sized,
    {
        self.0.encode_raw(buf)
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut B,
        ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError>
    where
        B: prost::bytes::Buf,
        Self: Sized,
    {
        self.0.merge_field(tag, wire_type, buf, ctx)
    }

    fn encoded_len(&self) -> usize {
        self.0.encoded_len()
    }

    fn clear(&mut self) {
        self.0.clear()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DiscriminantError(i32);

impl std::error::Error for DiscriminantError {}

impl std::fmt::Display for DiscriminantError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid enum value: {}", self.0)
    }
}

impl From<uuid::Uuid> for forge::Uuid {
    fn from(uuid: uuid::Uuid) -> forge::Uuid {
        forge::Uuid {
            value: uuid.hyphenated().to_string(),
        }
    }
}

impl From<String> for forge::MachineId {
    fn from(machine_id: String) -> forge::MachineId {
        forge::MachineId { id: machine_id }
    }
}

impl TryFrom<forge::Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl TryFrom<&forge::Uuid> for uuid::Uuid {
    type Error = uuid::Error;
    fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
        uuid::Uuid::parse_str(&uuid.value)
    }
}

impl Display for forge::Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match uuid::Uuid::try_from(self) {
            Ok(uuid) => write!(f, "{}", uuid),
            Err(err) => write!(f, "<uuid error: {}>", err),
        }
    }
}

impl Display for forge::MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.id.fmt(f)
    }
}

/// Custom Serializer implementation which omits the notion of the wrapper in gRPC
/// and just serializes the MachineId itself
impl serde::Serialize for forge::MachineId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.id.serialize(serializer)
    }
}

/// Custom Deserializer implementation which omits the notion of the wrapper in gRPC
/// and just serializes the MachineId itself
impl<'de> serde::Deserialize<'de> for forge::MachineId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = serde::Deserialize::deserialize(deserializer)?;

        Ok(MachineId { id })
    }
}

impl MachineInterface {
    pub fn parsed_mac_address(&self) -> Result<Option<MacAddress>, MacParseError> {
        Ok(Some(MacAddress::from_str(&self.mac_address)?))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_serialize_timestamp() {
        let ts = std::time::SystemTime::now();

        let proto_ts = Timestamp::from(ts);
        let encoded = proto_ts.encode_to_vec();

        let decoded = Timestamp::decode(&encoded[..]).unwrap();
        let decoded_system_time: std::time::SystemTime = decoded.try_into().unwrap();
        assert_eq!(ts, decoded_system_time);
    }

    #[test]
    fn test_serialize_timestamp_as_json() {
        let ts = std::time::SystemTime::UNIX_EPOCH;
        let proto_ts = Timestamp::from(ts);
        assert_eq!(
            "\"1970-01-01T00:00:00Z\"",
            serde_json::to_string(&proto_ts).unwrap()
        );
    }

    #[test]
    fn test_serialize_machine_id_as_json() {
        let id = MachineId::from("fms100ABCD".to_string());
        assert_eq!("\"fms100ABCD\"", serde_json::to_string(&id).unwrap());
    }

    /// Test to check that serializing a type with a custom Timestamp implementation works
    #[test]
    fn test_serialize_domain() {
        let uuid = uuid::uuid!("91609f10-c91d-470d-a260-1234560c0000");
        let ts = std::time::SystemTime::now();
        let ts2 = ts.checked_add(Duration::from_millis(1500)).unwrap();

        let domain = Domain {
            id: Some(uuid.into()),
            name: "MyDomain".to_string(),
            created: Some(ts.into()),
            updated: Some(ts2.into()),
            deleted: None,
        };

        let encoded = domain.encode_to_vec();
        let decoded = Domain::decode(&encoded[..]).unwrap();

        let deserialized_uuid: uuid::Uuid = decoded.id.unwrap().try_into().unwrap();
        let created_system_time: std::time::SystemTime =
            decoded.created.unwrap().try_into().unwrap();
        let updated_system_time: std::time::SystemTime =
            decoded.updated.unwrap().try_into().unwrap();
        assert_eq!(uuid, deserialized_uuid);
        assert_eq!(ts, created_system_time);
        assert_eq!(ts2, updated_system_time);
    }
}
