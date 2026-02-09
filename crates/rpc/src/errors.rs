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
use std::backtrace::{Backtrace, BacktraceStatus};

use tonic::Status;

/// RpcDataConversionError enumerates errors that can occur when
/// converting from the RPC data format into the internal data model.
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
    #[error("Machine ID {0} is not valid")]
    InvalidMachineId(String),
    #[error("Network Security Group ID {0} is not valid")]
    InvalidNetworkSecurityGroupId(String),
    #[error("Instance Type ID {0} is not valid")]
    InvalidInstanceTypeId(String),
    #[error("Timestamp {0} is not valid")]
    InvalidTimestamp(String),
    #[error("Tenant Org {0} is not valid")]
    InvalidTenantOrg(String),
    #[error("Interface Function Type {0} is not valid")]
    InvalidInterfaceFunctionType(i32),
    #[error("Invalid UUID for field of type {0}: {1}")]
    InvalidUuid(&'static str, String),
    #[error("Invalid value {1} for {0}")]
    InvalidValue(String, String),
    #[error("Argument is invalid: {0}")]
    InvalidArgument(String),
    #[error("Argument {0} is missing")]
    MissingArgument(&'static str),
    #[error(
        "A unique identifier was specified for a new object.  When creating a new object of type {0}, do not specify an identifier"
    )]
    IdentifierSpecifiedForNewObject(String),
    #[error("Machine state {0} is invalid")]
    InvalidMachineState(String),
    #[error("Invalid NetworkSegmentType {0} is received.")]
    InvalidNetworkSegmentType(i32),
    #[error("Pci Device Info {0} is invalid")]
    InvalidPciDeviceInfo(String),
    #[error("VpcVirtualizationType {0} is invalid")]
    InvalidVpcVirtualizationType(i32),
    #[error("Invalid enum value received for critical error type: {0}")]
    InvalidCriticalErrorType(i32),
    #[error("Instance ID {0} is not valid")]
    InvalidInstanceId(String),
    #[error("Remediation ID {0} is not valid")]
    InvalidRemediationId(String),
    #[error("VPC ID {0} is not valid")]
    InvalidVpcId(String),
    #[error("VPC peering ID {0} is not valid")]
    InvalidVpcPeeringId(String),
    #[error("IB Partition ID {0} is not valid")]
    InvalidIbPartitionId(String),
    #[error("PowerShelf ID {0} is not valid")]
    InvalidPowerShelfId(String),
    #[error("Switch ID {0} is not valid")]
    InvalidSwitchId(String),
    #[error("Network Segment ID {0} is not valid")]
    InvalidNetworkSegmentId(String),
    #[error("CIDR {0} is not valid")]
    InvalidCidr(String),
    #[error("Label is not valid: {0}")]
    InvalidLabel(String),
    #[error("Invalid DnsResourceRecordType: {0}")]
    InvalidDnsResourceRecordType(String),
    #[error("Invalid Soa Record: {0}")]
    InvalidSoaRecord(String),
    #[error("Could not obtain object from json: {0}")]
    JsonConversionFailure(String),
    #[error("JSON Parse failure - {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Unable to parse string into IP Network: {0}")]
    NetworkParseError(#[from] ipnetwork::IpNetworkError),
    #[error("Tenant Routing Profile Type {0} is not valid")]
    InvalidRoutingProfileType(String),
    #[error("NVL Partition ID {0} is not valid")]
    InvalidNvlPartitionId(String),
    #[error("Logical Partition ID {0} is not valid")]
    InvalidLogicalPartitionId(String),
}

impl From<RpcDataConversionError> for tonic::Status {
    fn from(from: RpcDataConversionError) -> Self {
        // If env RUST_BACKTRACE is set extract handler and err location
        // If it's not set `Backtrace::capture()` is very cheap to call
        let b = Backtrace::capture();
        let printed = if b.status() == BacktraceStatus::Captured {
            let b_str = b.to_string();
            let f = b_str
                .lines()
                .skip(1)
                .skip_while(|l| !l.contains("carbide"))
                .take(2)
                .collect::<Vec<&str>>();
            if f.len() == 2 {
                let handler = f[0].trim();
                let location = f[1].trim().replace("at ", "");
                tracing::error!("{from} location={location} handler='{handler}'");
                true
            } else {
                false
            }
        } else {
            false
        };

        if !printed {
            tracing::error!("{from}");
        }

        Status::invalid_argument(from.to_string())
    }
}
