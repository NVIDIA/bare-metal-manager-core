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

extern crate core;

use std::cmp::Ordering;
use std::fmt::Display;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use dns_record::DnsResourceRecordReply;
use errors::RpcDataConversionError;
use mac_address::{MacAddress, MacParseError};
use prost::{Message, UnknownEnumValue};
use serde::ser::Error;
use serde_json::{Value, json};
use tokio_stream::Stream;

pub use crate::protos::common::{self, Uuid};
pub use crate::protos::dns::{self};
pub use crate::protos::forge::machine_credentials_update_request::CredentialPurpose;
pub use crate::protos::forge::machine_discovery_info::DiscoveryData;
pub use crate::protos::forge::{
    self, CredentialType, Domain, DomainList, ForgeScoutErrorReport, ForgeScoutErrorReportResult,
    IbPartition, IbPartitionCreationRequest, IbPartitionDeletionRequest, IbPartitionDeletionResult,
    IbPartitionList, Instance, InstanceAllocationRequest, InstanceConfig,
    InstanceIbInterfaceConfig, InstanceIbInterfaceStatus, InstanceInfinibandConfig,
    InstanceInfinibandStatus, InstanceInterfaceConfig, InstanceInterfaceStatus,
    InstanceInterfaceStatusObservation, InstanceList, InstanceNetworkConfig, InstanceNetworkStatus,
    InstanceNvLinkStatus, InstanceReleaseRequest, InstanceStatus, InstanceTenantStatus,
    InterfaceFunctionType, Machine, MachineCleanupInfo, MachineDiscoveryInfo, MachineEvent,
    MachineInterface, MachineList, Metadata, NetworkSegment, NetworkSegmentList, NvLinkPartition,
    NvLinkPartitionList, NvLinkPartitionQuery, ResourcePoolType, SyncState, TenantConfig,
    TenantState, forge_agent_control_response,
};
pub use crate::protos::machine_discovery::{
    self, BlockDevice, Cpu, DiscoveryInfo, DmiData, NetworkInterface, NvmeDevice,
    PciDeviceProperties,
};
pub use crate::protos::{health, site_explorer};

pub mod errors;
pub mod forge_tls_client;
pub mod protos;

#[cfg(feature = "cli")]
pub mod admin_cli;

pub mod forge_api_client;
pub mod forge_resolver;
pub mod nmx_c_client;
pub mod rack_manager_client;

pub const REFLECTION_API_SERVICE_DESCRIPTOR: &[u8] = tonic::include_file_descriptor_set!("forge");
pub const MAX_ERR_MSG_SIZE: i32 = 1500;

// DynForge exists because, now that we have >= streaming interface,
// simply passing around `dyn Forge` doesn't work anymore. As any additional
// streaming interfaces are added, we just toss in type defs here, and
// any users of DynForge don't need to worry about it.
pub type DynForge = dyn forge::forge_server::Forge<
        ScoutStreamStream = Pin<
            Box<
                dyn Stream<Item = Result<forge::ScoutStreamScoutBoundMessage, tonic::Status>>
                    + Send,
            >,
        >,
    >;

pub fn get_encoded_reflection_service_fd() -> Vec<u8> {
    let mut expected = Vec::new();
    prost_types::FileDescriptorSet::decode(REFLECTION_API_SERVICE_DESCRIPTOR)
        .expect("decode reflection service file descriptor set")
        .file[0]
        .encode(&mut expected)
        .expect("encode reflection service file descriptor");
    expected
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .seconds
            .cmp(&other.0.seconds)
            .then_with(|| self.0.nanos.cmp(&other.0.nanos))
    }
}

/// A wrapper around the prost timestamp which allows for serde serialization
/// and has helper methods to convert from and into std::time::SystemTime and DateTime
#[derive(Clone, PartialEq, Copy, Eq, Default, Debug, Hash)]
pub struct Timestamp(prost_types::Timestamp);

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

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
        match chrono::DateTime::<chrono::Utc>::try_from(*self) {
            Ok(ts) => ts.serialize(s),
            Err(_) => chrono::DateTime::<chrono::Utc>::default().serialize(s),
        }
    }
}

impl<'a> serde::Deserialize<'a> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        let dt =
            DateTime::<Utc>::from_str(&s).unwrap_or_else(|_e| DateTime::<chrono::Utc>::default());
        Ok(dt.into())
    }
}

impl prost::Message for Timestamp {
    fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut)
    where
        Self: Sized,
    {
        self.0.encode_raw(buf)
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut impl prost::bytes::Buf,
        ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError>
    where
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

/// A wrapper around the prost Duration which allows for serde serialization
/// and has helper methods to convert from and into std::time::Duration
#[derive(Clone, PartialEq, Copy, Default, Debug, Eq, Hash)]
pub struct Duration(prost_types::Duration);

impl std::fmt::Display for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for Duration {
    type Target = prost_types::Duration;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Duration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<prost_types::Duration> for Duration {
    fn from(ts: prost_types::Duration) -> Self {
        Self(ts)
    }
}

impl From<Duration> for prost_types::Duration {
    fn from(ts: Duration) -> prost_types::Duration {
        ts.0
    }
}

impl TryFrom<Duration> for std::time::Duration {
    type Error = prost_types::DurationError;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        std::time::Duration::try_from(duration.0)
    }
}

impl TryFrom<Duration> for chrono::TimeDelta {
    type Error = prost_types::DurationError;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        let std_duration = std::time::Duration::try_from(duration.0)?;
        chrono::TimeDelta::from_std(std_duration)
            .map_err(|_| prost_types::DurationError::OutOfRange)
    }
}

impl From<std::time::Duration> for Duration {
    fn from(duration: std::time::Duration) -> Self {
        // Realistically we will never deal with a `time::Duration` that can't be
        // natively converted. But if we do - clamp it to the maximum allowed value
        prost_types::Duration::try_from(duration)
            .unwrap_or(prost_types::Duration {
                seconds: i64::MAX,
                nanos: 999_999_999,
            })
            .into()
    }
}

impl From<chrono::TimeDelta> for Duration {
    fn from(duration: chrono::TimeDelta) -> Self {
        duration.to_std().unwrap_or(std::time::Duration::MAX).into()
    }
}

impl serde::Serialize for Duration {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // We serialize the duration as std::time::Duration
        match std::time::Duration::try_from(*self) {
            Ok(duration) => duration.serialize(s),
            Err(_) => std::time::Duration::ZERO.serialize(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Duration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let duration: std::time::Duration = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self::from(duration))
    }
}

impl prost::Message for Duration {
    fn encode_raw(&self, buf: &mut impl prost::bytes::BufMut)
    where
        Self: Sized,
    {
        self.0.encode_raw(buf)
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut impl prost::bytes::Buf,
        ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError>
    where
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

impl TryFrom<common::Uuid> for ::uuid::Uuid {
    type Error = ::uuid::Error;
    fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
        ::uuid::Uuid::parse_str(&uuid.value)
    }
}

impl TryFrom<&common::Uuid> for ::uuid::Uuid {
    type Error = ::uuid::Error;
    fn try_from(uuid: &Uuid) -> Result<Self, Self::Error> {
        ::uuid::Uuid::parse_str(&uuid.value)
    }
}

impl Display for common::Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match ::uuid::Uuid::try_from(self) {
            Ok(uuid) => write!(f, "{uuid}"),
            Err(err) => write!(f, "<uuid error: {err}>"),
        }
    }
}

impl MachineInterface {
    pub fn parsed_mac_address(&self) -> Result<Option<MacAddress>, MacParseError> {
        Ok(Some(MacAddress::from_str(&self.mac_address)?))
    }
}

impl From<health_report::HealthProbeSuccess> for health::HealthProbeSuccess {
    fn from(success: health_report::HealthProbeSuccess) -> Self {
        Self {
            id: success.id.to_string(),
            target: success.target,
        }
    }
}

impl TryFrom<health::HealthProbeSuccess> for health_report::HealthProbeSuccess {
    type Error = health_report::HealthReportConversionError;
    fn try_from(success: health::HealthProbeSuccess) -> Result<Self, Self::Error> {
        Ok(Self {
            id: success.id.parse()?,
            target: success.target.clone(),
        })
    }
}

impl From<health_report::HealthProbeAlert> for health::HealthProbeAlert {
    fn from(alert: health_report::HealthProbeAlert) -> Self {
        Self {
            id: alert.id.to_string(),
            target: alert.target.clone(),
            in_alert_since: alert.in_alert_since.map(Timestamp::from),
            message: alert.message,
            tenant_message: alert.tenant_message,
            classifications: alert
                .classifications
                .into_iter()
                .map(|c| c.to_string())
                .collect(),
        }
    }
}

impl TryFrom<health::HealthProbeAlert> for health_report::HealthProbeAlert {
    type Error = health_report::HealthReportConversionError;
    fn try_from(alert: health::HealthProbeAlert) -> Result<Self, Self::Error> {
        let mut classifications = Vec::new();
        for c in alert.classifications {
            classifications.push(c.parse()?);
        }

        Ok(Self {
            id: alert.id.parse()?,
            target: match alert.target {
                Some(target) if !target.is_empty() => Some(target),
                _ => None,
            },
            in_alert_since: alert
                .in_alert_since
                .map(TryInto::try_into)
                .transpose()
                .map_err(|_| health_report::HealthReportConversionError::TimestampParseError)?,
            message: alert.message,
            tenant_message: alert.tenant_message,
            classifications,
        })
    }
}

impl From<health_report::HealthReport> for health::HealthReport {
    fn from(report: health_report::HealthReport) -> Self {
        let mut successes = Vec::new();
        let mut alerts = Vec::new();
        for success in report.successes {
            successes.push(success.into());
        }
        for alert in report.alerts {
            alerts.push(alert.into());
        }

        Self {
            source: report.source,
            observed_at: report.observed_at.map(Timestamp::from),
            successes,
            alerts,
        }
    }
}

impl TryFrom<health::HealthReport> for health_report::HealthReport {
    type Error = health_report::HealthReportConversionError;
    fn try_from(report: health::HealthReport) -> Result<Self, Self::Error> {
        if report.source.is_empty() {
            return Err(health_report::HealthReportConversionError::MissingSource);
        }
        let mut successes = Vec::new();
        let mut alerts = Vec::new();
        for success in report.successes {
            successes.push(success.try_into()?);
        }
        for alert in report.alerts {
            alerts.push(alert.try_into()?);
        }

        Ok(Self {
            source: report.source,
            observed_at: report
                .observed_at
                .map(DateTime::<Utc>::try_from)
                .transpose()
                .map_err(|_| health_report::HealthReportConversionError::TimestampParseError)?,
            successes,
            alerts,
        })
    }
}

impl From<forge::OverrideMode> for health_report::OverrideMode {
    fn from(value: forge::OverrideMode) -> Self {
        match value {
            forge::OverrideMode::Merge => health_report::OverrideMode::Merge,
            forge::OverrideMode::Replace => health_report::OverrideMode::Replace,
        }
    }
}

impl From<DnsResourceRecordReply> for crate::protos::dns::DnsResourceRecord {
    fn from(value: DnsResourceRecordReply) -> Self {
        Self {
            qtype: value.qtype,
            qname: value.qname,
            ttl: value.ttl,
            content: value.content,
            auth: value.auth,
            domain_id: value.domain_id,
            scope_mask: value.scope_mask,
        }
    }
}

pub struct JsonDnsResourceRecord(pub crate::protos::dns::DnsResourceRecord);

impl From<JsonDnsResourceRecord> for Value {
    fn from(wrapper: JsonDnsResourceRecord) -> Self {
        let json_value = json!({
            "qtype": wrapper.0.qtype,
            "qname": wrapper.0.qname,
            "ttl": wrapper.0.ttl,
            "content": wrapper.0.content,
            "domain_id": wrapper.0.domain_id,
            "scope_mask": wrapper.0.scope_mask,
            "auth": wrapper.0.auth,
        });
        json_value
    }
}

impl FromStr for forge::OperatingSystem {
    type Err = RpcDataConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|e| RpcDataConversionError::JsonConversionFailure(e.to_string()))
    }
}

impl FromStr for forge::InstanceInfinibandConfig {
    type Err = RpcDataConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|e| RpcDataConversionError::JsonConversionFailure(e.to_string()))
    }
}

impl FromStr for forge::InstanceNvLinkConfig {
    type Err = RpcDataConversionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
            .map_err(|e| RpcDataConversionError::JsonConversionFailure(e.to_string()))
    }
}

/*  ****************************************************** */
// Serialization/deserialization helpers for network
// security group enums to let admin CLI callers describe
// rules with friendly property values intead of i32.
/* ******************************************************* */

impl forge::NetworkSecurityGroupRuleDirection {
    pub fn from_string<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        match s.to_uppercase().as_str() {
            "INGRESS" => Ok(Self::NsgRuleDirectionIngress as i32),
            "EGRESS" => Ok(Self::NsgRuleDirectionEgress as i32),
            _ => Ok(0),
        }
    }

    pub fn serialize_from_enum_i32<S>(v: &i32, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(
            &forge::NetworkSecurityGroupRuleDirection::to_string_from_enum_i32(*v)
                .map_err(Error::custom)?,
        )
    }

    pub fn to_string_from_enum_i32(v: i32) -> Result<String, UnknownEnumValue> {
        let t: forge::NetworkSecurityGroupRuleDirection = (v).try_into()?;

        Ok(match t {
            forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress => {
                "INGRESS".to_string()
            }
            forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress => {
                "EGRESS".to_string()
            }
            forge::NetworkSecurityGroupRuleDirection::NsgRuleDirectionInvalid => {
                "INVALID".to_string()
            }
        })
    }
}

impl forge::NetworkSecurityGroupRuleProtocol {
    pub fn from_string<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        match s.to_uppercase().as_str() {
            "ANY" => Ok(Self::NsgRuleProtoAny as i32),
            "ICMP" => Ok(Self::NsgRuleProtoIcmp as i32),
            "ICMP6" => Ok(Self::NsgRuleProtoIcmp6 as i32),
            "UDP" => Ok(Self::NsgRuleProtoUdp as i32),
            "TCP" => Ok(Self::NsgRuleProtoTcp as i32),
            _ => Ok(0),
        }
    }

    pub fn serialize_from_enum_i32<S>(v: &i32, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(
            &forge::NetworkSecurityGroupRuleProtocol::to_string_from_enum_i32(*v)
                .map_err(Error::custom)?,
        )
    }

    pub fn to_string_from_enum_i32(v: i32) -> Result<String, UnknownEnumValue> {
        let t: forge::NetworkSecurityGroupRuleProtocol = (v).try_into()?;

        Ok(match t {
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny => "ANY".to_string(),
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp => "ICMP".to_string(),
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoIcmp6 => "ICMP6".to_string(),
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp => "UDP".to_string(),
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp => "TCP".to_string(),
            forge::NetworkSecurityGroupRuleProtocol::NsgRuleProtoInvalid => "INVALID".to_string(),
        })
    }
}

impl forge::NetworkSecurityGroupRuleAction {
    pub fn from_string<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        match s.to_uppercase().as_str() {
            "PERMIT" => Ok(Self::NsgRuleActionPermit as i32),
            "DENY" => Ok(Self::NsgRuleActionDeny as i32),
            _ => Ok(0),
        }
    }

    pub fn serialize_from_enum_i32<S>(v: &i32, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(
            &forge::NetworkSecurityGroupRuleAction::to_string_from_enum_i32(*v)
                .map_err(Error::custom)?,
        )
    }

    pub fn to_string_from_enum_i32(v: i32) -> Result<String, UnknownEnumValue> {
        let t: forge::NetworkSecurityGroupRuleAction = (v).try_into()?;

        Ok(match t {
            forge::NetworkSecurityGroupRuleAction::NsgRuleActionPermit => "PERMIT".to_string(),
            forge::NetworkSecurityGroupRuleAction::NsgRuleActionDeny => "DENY".to_string(),
            forge::NetworkSecurityGroupRuleAction::NsgRuleActionInvalid => "INVALID".to_string(),
        })
    }
}

impl forge::MachineCapabilityType {
    pub fn from_string<'de, D>(deserializer: D) -> Result<i32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        match s.to_uppercase().as_str() {
            "CPU" => Ok(forge::MachineCapabilityType::CapTypeCpu as i32),
            "GPU" => Ok(forge::MachineCapabilityType::CapTypeGpu as i32),
            "MEMORY" => Ok(forge::MachineCapabilityType::CapTypeMemory as i32),
            "STORAGE" => Ok(forge::MachineCapabilityType::CapTypeStorage as i32),
            "NETWORK" => Ok(forge::MachineCapabilityType::CapTypeNetwork as i32),
            "INFINIBAND" => Ok(forge::MachineCapabilityType::CapTypeInfiniband as i32),
            "DPU" => Ok(forge::MachineCapabilityType::CapTypeDpu as i32),
            _ => Ok(0),
        }
    }

    pub fn serialize_from_enum_i32<S>(v: &i32, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(
            &forge::MachineCapabilityType::to_string_from_enum_i32(*v).map_err(Error::custom)?,
        )
    }

    pub fn to_string_from_enum_i32(v: i32) -> Result<String, UnknownEnumValue> {
        let t: forge::MachineCapabilityType = (v).try_into()?;

        Ok(match t {
            forge::MachineCapabilityType::CapTypeCpu => "CPU".to_string(),
            forge::MachineCapabilityType::CapTypeGpu => "GPU".to_string(),
            forge::MachineCapabilityType::CapTypeMemory => "MEMORY".to_string(),
            forge::MachineCapabilityType::CapTypeStorage => "STORAGE".to_string(),
            forge::MachineCapabilityType::CapTypeNetwork => "NETWORK".to_string(),
            forge::MachineCapabilityType::CapTypeInfiniband => "INFINIBAND".to_string(),
            forge::MachineCapabilityType::CapTypeDpu => "DPU".to_string(),
            forge::MachineCapabilityType::CapTypeInvalid => "INVALID".to_string(),
        })
    }
}

impl forge::MachineCapabilityDeviceType {
    pub fn from_string<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;

        Ok(Some(match s.to_uppercase().as_str() {
            "DPU" => Self::Dpu as i32,
            "UNKNOWN" => Self::Unknown as i32,
            _ => 0,
        }))
    }

    pub fn serialize_from_enum_i32<S>(v: &Option<i32>, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match v {
            Some(val) => s.serialize_str(
                &forge::MachineCapabilityDeviceType::to_string_from_enum_i32(*val)
                    .map_err(Error::custom)?,
            ),
            None => s.serialize_none(),
        }
    }

    pub fn to_string_from_enum_i32(v: i32) -> Result<String, UnknownEnumValue> {
        let t: forge::MachineCapabilityDeviceType = (v).try_into()?;

        Ok(match t {
            forge::MachineCapabilityDeviceType::Dpu => "DPU".to_string(),
            forge::MachineCapabilityDeviceType::Unknown => "UNKNOWN".to_string(),
            forge::MachineCapabilityDeviceType::Nvlink => "NVLINK".to_string(),
        })
    }
}

impl forge::ScoutStreamScoutBoundMessage {
    pub fn new_flow(msg: forge::scout_stream_scout_bound_message::Payload) -> Self {
        Self {
            flow_uuid: Some(uuid::Uuid::new_v4().into()),
            payload: Some(msg),
        }
    }
}

impl forge::ScoutStreamApiBoundMessage {
    pub fn from_flow(
        flow_uuid: uuid::Uuid,
        msg: forge::scout_stream_api_bound_message::Payload,
    ) -> Self {
        Self {
            flow_uuid: Some(flow_uuid.into()),
            payload: Some(msg),
        }
    }
}

#[cfg(feature = "cli")]
// This impl allows us to use the RPC RouteServerSourceType type
// as a first class enum with clap, for the purpose of allowing
// users to set --source-type with the forge-admin-cli.
impl clap::ValueEnum for forge::RouteServerSourceType {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::AdminApi, Self::ConfigFile]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::AdminApi => clap::builder::PossibleValue::new("admin_api"),
            Self::ConfigFile => clap::builder::PossibleValue::new("config_file"),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use carbide_uuid::machine::MachineId;

    use self::forge::operating_system::Variant;
    use self::forge::{InlineIpxe, OperatingSystem};
    use super::*;
    use crate::protos::dns::{Domain, Metadata};

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
        let id = MachineId::from_str("fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g")
            .unwrap();
        assert_eq!(
            "\"fm100htjsaledfasinabqqer70e2ua5ksqj4kfjii0v0a90vulps48c1h7g\"",
            serde_json::to_string(&id).unwrap()
        );
    }

    #[test]
    fn test_serialize_os() {
        let os = OperatingSystem {
            phone_home_enabled: true,
            run_provisioning_instructions_on_every_boot: true,
            user_data: Some("def".to_string()),
            variant: Some(Variant::Ipxe(InlineIpxe {
                ipxe_script: "abc".to_string(),
                user_data: Some("def".to_string()),
            })),
        };

        assert_eq!(
            "{\"phone_home_enabled\":true,\"run_provisioning_instructions_on_every_boot\":true,\"user_data\":\"def\",\"variant\":{\"Ipxe\":{\"ipxe_script\":\"abc\",\"user_data\":\"def\"}}}",
            serde_json::to_string(&os).unwrap()
        );
    }

    /// Test to check that serializing a type with a custom Timestamp implementation works
    #[test]
    fn test_serialize_domain() {
        let uuid =
            carbide_uuid::domain::DomainId(::uuid::uuid!("91609f10-c91d-470d-a260-1234560c0000"));
        let ts = std::time::SystemTime::now();
        let ts2 = ts.checked_add(Duration::from_millis(1500)).unwrap();

        let domain_metadata = Metadata {
            allow_axfr_from: vec![],
        };
        let domain = Domain {
            id: Some(uuid),
            name: "MyDomain".to_string(),
            created: Some(ts.into()),
            updated: Some(ts2.into()),
            deleted: None,
            soa: None,
            metadata: Some(domain_metadata),
        };

        let encoded = domain.encode_to_vec();
        let decoded = Domain::decode(&encoded[..]).unwrap();

        let deserialized_uuid: carbide_uuid::domain::DomainId = decoded.id.unwrap();
        let created_system_time: std::time::SystemTime =
            decoded.created.unwrap().try_into().unwrap();
        let updated_system_time: std::time::SystemTime =
            decoded.updated.unwrap().try_into().unwrap();
        assert_eq!(uuid, deserialized_uuid);
        assert_eq!(ts, created_system_time);
        assert_eq!(ts2, updated_system_time);
    }
}
