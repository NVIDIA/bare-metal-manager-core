/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

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
    #[error("Argument {0} is missing")]
    MissingArgument(&'static str),
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
    #[error("VPC ID {0} is not valid")]
    InvalidVpcId(String),
    #[error("VPC peering ID {0} is not valid")]
    InvalidVpcPeeringId(String),
    #[error("IB Partition ID {0} is not valid")]
    InvalidIbPartitionId(String),
    #[error("Network Segment ID {0} is not valid")]
    InvalidNetworkSegmentId(String),
    #[error("CIDR {0} is not valid")]
    InvalidCidr(String),
    #[error("Label is not valid: {0}")]
    InvalidLabel(String),
    #[error("Could not obtain object from json: {0}")]
    JsonConversionFailure(String),
}
