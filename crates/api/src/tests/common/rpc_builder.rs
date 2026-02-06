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
