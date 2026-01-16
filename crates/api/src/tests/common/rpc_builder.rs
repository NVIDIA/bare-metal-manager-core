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

use crate::tests::common::api_fixtures::instance::{default_os_config, default_tenant_config};

// Reflection of rpc::forge::DhcpDiscovery. It should contain exactly
// the same fields as rpc::forge::DhcpDiscovery. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct DhcpDiscovery {
    pub mac_address: ::prost::alloc::string::String,
    pub relay_address: ::prost::alloc::string::String,
    pub vendor_string: ::core::option::Option<::prost::alloc::string::String>,
    pub link_address: ::core::option::Option<::prost::alloc::string::String>,
    pub circuit_id: ::core::option::Option<::prost::alloc::string::String>,
    pub remote_id: ::core::option::Option<::prost::alloc::string::String>,
    pub desired_address: ::core::option::Option<::prost::alloc::string::String>,
}

// Reflection of rpc::forge::VpcCreationRequest. It should contain exactly
// the same fields as rpc::forge::VpcCreationRequest. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct VpcCreationRequest {
    pub name: ::prost::alloc::string::String,
    pub tenant_organization_id: ::prost::alloc::string::String,
    pub tenant_keyset_id: ::core::option::Option<::prost::alloc::string::String>,
    pub network_virtualization_type: ::core::option::Option<i32>,
    pub id: ::core::option::Option<::carbide_uuid::vpc::VpcId>,
    pub metadata: ::core::option::Option<rpc::forge::Metadata>,
    pub network_security_group_id: ::core::option::Option<::prost::alloc::string::String>,
    pub default_nvlink_logical_partition_id:
        ::core::option::Option<::carbide_uuid::nvlink::NvLinkLogicalPartitionId>,
}

// Reflection of rpc::forge::VpcUpdateRequest. It should contain exactly
// the same fields as rpc::forge::VpcUpdateRequest. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct VpcUpdateRequest {
    pub id: ::core::option::Option<::carbide_uuid::vpc::VpcId>,
    pub if_version_match: ::core::option::Option<::prost::alloc::string::String>,
    pub name: ::prost::alloc::string::String,
    pub metadata: ::core::option::Option<::rpc::forge::Metadata>,
    pub network_security_group_id: ::core::option::Option<::prost::alloc::string::String>,
    pub default_nvlink_logical_partition_id:
        ::core::option::Option<::carbide_uuid::nvlink::NvLinkLogicalPartitionId>,
}

// Reflection of rpc::forge::VpcCreationRequest. It should contain exactly
// the same fields as rpc::forge::VpcDeletionRequest. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct VpcDeletionRequest {
    pub id: ::core::option::Option<::carbide_uuid::vpc::VpcId>,
}

// Reflection of rpc::forge::InstanceAllocationRequest. It should contain exactly
// the same fields as rpc::forge::InstanceAllocationRequest. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct InstanceAllocationRequest {
    pub machine_id: ::core::option::Option<::carbide_uuid::machine::MachineId>,
    pub config: ::core::option::Option<::rpc::forge::InstanceConfig>,
    pub instance_id: ::core::option::Option<::carbide_uuid::instance::InstanceId>,
    pub instance_type_id: ::core::option::Option<::prost::alloc::string::String>,
    pub metadata: ::core::option::Option<::rpc::forge::Metadata>,
    pub allow_unhealthy_machine: bool,
}

// Reflection of rpc::forge::InstanceConfig. It should contain exactly
// the same fields as rpc::forge::InstanceConfig. Otherwise it will
// produce error on carbide_prost_builder::Builder derivation.
#[derive(carbide_prost_builder::Builder)]
pub struct InstanceConfig {
    pub tenant: ::core::option::Option<::rpc::forge::TenantConfig>,
    pub os: ::core::option::Option<::rpc::forge::OperatingSystem>,
    pub network: ::core::option::Option<rpc::forge::InstanceNetworkConfig>,
    pub infiniband: ::core::option::Option<::rpc::forge::InstanceInfinibandConfig>,
    pub network_security_group_id: ::core::option::Option<::prost::alloc::string::String>,
    pub dpu_extension_services:
        ::core::option::Option<::rpc::forge::InstanceDpuExtensionServicesConfig>,
    pub nvlink: ::core::option::Option<::rpc::forge::InstanceNvLinkConfig>,
}

impl InstanceConfig {
    pub fn default_tenant_and_os() -> Self {
        Self::builder()
            .tenant(default_tenant_config())
            .os(default_os_config())
    }
}
