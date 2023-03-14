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
use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LeafSpec defines the desired state of Leaf
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "networkfabric.vpc.forge.gitlab-master.nvidia.com",
    version = "v1alpha1",
    kind = "Leaf",
    plural = "leafs"
)]
#[kube(namespaced)]
#[kube(status = "LeafStatus")]
pub struct LeafSpec {
    /// Control specifies the ways to interact with this Leaf device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<LeafControl>,
    /// HostAdminIPs are host IPs when hosts are not part of any tenant networks, but still need to access the network for host discovery, imaging, etc. The key-value pair is the leaf port and the IP address assigned to the host interface connecting to the leaf port
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostAdminIPs"
    )]
    pub host_admin_i_ps: Option<BTreeMap<String, String>>,
    /// HostInterfaces are host interfaces connected to this Leaf. The key value pair is the host interface identifier and the leaf port connected to the host interface.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostInterfaces"
    )]
    pub host_interfaces: Option<BTreeMap<String, String>>,
}

/// Control specifies the ways to interact with this Leaf device.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct LeafControl {
    /// MaintenanceMode is set to true when the controller no longer actively configures the device.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maintenanceMode"
    )]
    pub maintenance_mode: Option<bool>,
    /// ManagementIP is the management interface IP to access this network device.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "managementIP"
    )]
    pub management_ip: Option<String>,
    /// SshCredentialKVPath is path to access ssh credential saved in a kv store.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "sshCredentialKVPath"
    )]
    pub ssh_credential_kv_path: Option<String>,
    /// Vendor is this network device's vendor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
}

/// LeafStatus defines the observed state of Leaf
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct LeafStatus {
    /// ASN assigned to this leaf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<i64>,
    /// Conditions are the conditions of this Leaf device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<LeafStatusConditions>>,
    /// HostAdminDHCPServers are the DHCPServers for hosts in un-assigned state.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostAdminDHCPServers"
    )]
    pub host_admin_dhcp_servers: Option<Vec<String>>,
    /// HostAdminIPs are host IPs in un-assigned state.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostAdminIPs"
    )]
    pub host_admin_i_ps: Option<BTreeMap<String, String>>,
    /// LoobackIP assigned to this leaf.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "loopbackIP"
    )]
    pub loopback_ip: Option<String>,
    /// NetworkPolicies applied to this Leaf.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "networkPolicies"
    )]
    pub network_policies: Option<Vec<String>>,
}

/// NetworkDeviceCondition indicates the transactions with the network device.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct LeafStatusConditions {
    /// LastTransitionTime is the last transaction time for this ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastTransitionTime"
    )]
    pub last_transition_time: Option<String>,
    /// Message is the response received from the network device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Status is the network device status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Type is the network device condition type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}
