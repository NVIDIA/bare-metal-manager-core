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
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ResourceGroupSpec defines the desired state of ResourceGroup.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "resource.vpc.forge.gitlab-master.nvidia.com",
    version = "v1alpha1",
    kind = "ResourceGroup",
    plural = "resourcegroups"
)]
#[kube(namespaced)]
#[kube(status = "ResourceGroupStatus")]
pub struct ResourceGroupSpec {
    /// DHCPServer is the IPAddress of the DHCP server (i.e. Carbide) for ManagedResources in this ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "dhcpServer"
    )]
    pub dhcp_server: Option<String>,
    /// DHCPServers are the IPAddresses of the DHCP servers (i.e. Carbide) for ManagedResources in this ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "dhcpServers"
    )]
    pub dhcp_servers: Option<Vec<String>>,
    /// FabricIPPool is used to assign fabric routable IPs to tenant hosts on the overlay network.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "fabricIPPool"
    )]
    pub fabric_ip_pool: Option<String>,
    /// Network defines the overlay L2 network for this ResourceGroup. It is immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ResourceGroupNetwork>,
    /// NetworkImplementationType is the backend implementing the l2 overlay network. Default to "Fabric".
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "networkImplementationType"
    )]
    pub network_implementation_type: Option<String>,
    /// OverlayIPPool is used to allocate overlay IP ranges on tenant's behave.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "overlayIPPool"
    )]
    pub overlay_ip_pool: Option<String>,
    /// TenantIdentifier identifies the tenant associated with this ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "tenantIdentifier"
    )]
    pub tenant_identifier: Option<String>,
}

/// Network defines the overlay L2 network for this ResourceGroup. It is immutable.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupNetwork {
    /// Gateway is the default gateway for IPv4 subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IPAddress is IPv4 or IPv6 Addresse types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "prefixLength"
    )]
    pub prefix_length: Option<i32>,
}

/// ResourceGroupStatus defines the observed state of ResourceGroup
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupStatus {
    /// Conditions specifies responses of ResourceGroup create/delete/update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<ResourceGroupStatusConditions>>,
    /// DHCPCircID is DHCP option 82 - circuit ID. This is the interface name on which DHCP requests for this ResourceGroup are received on.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "dhcpCircID"
    )]
    pub dhcp_circ_id: Option<String>,
    /// FabricNetworkConfiguration is the fabric configuration supporting this overlay network.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "fabricNetworkConfiguration"
    )]
    pub fabric_network_configuration: Option<ResourceGroupStatusFabricNetworkConfiguration>,
    /// ManagedResourceCount is the number of ManagedResources in the ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "managedResourceCount"
    )]
    pub managed_resource_count: Option<i64>,
    /// Network is the overlay L2 network for this ResourceGroup. If Spec.Network is defined, this is same network, otherwise it is auto-allocated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<ResourceGroupStatusNetwork>,
    /// SNATIPs is the snat IPs for overlay traffic entering network fabric.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "snatIPs")]
    pub snat_i_ps: Option<Vec<String>>,
    /// SoftwareNetworkConfiguration is the software defined overlay network configuration.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "softwareNetworkConfiguration"
    )]
    pub software_network_configuration: Option<ResourceGroupStatusSoftwareNetworkConfiguration>,
}

/// ResourceGroupCondition defines responses of ResourceGroup create/delete/update.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupStatusConditions {
    /// LastTransitionTime is the last transaction time for this ResourceGroup.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastTransitionTime"
    )]
    pub last_transition_time: Option<String>,
    /// Message is message from the transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason is reason for the transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status is ResourceGroupCondition status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Type is ResourceGroupCondition type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// FabricNetworkConfiguration is the fabric configuration supporting this overlay network.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupStatusFabricNetworkConfiguration {
    /// VlanID is the ID of VLAN interfaces for this overlay network
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "vlanID")]
    pub vlan_id: Option<i32>,
    /// VNI is the vni for this overlay network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<i32>,
    /// VRF is the VRF name for this overlay network. TODO, Do we need VRF ??
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<String>,
}

/// Network is the overlay L2 network for this ResourceGroup. If Spec.Network is defined, this is same network, otherwise it is auto-allocated.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupStatusNetwork {
    /// Gateway is the default gateway for IPv4 subnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IPAddress is IPv4 or IPv6 Addresse types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "prefixLength"
    )]
    pub prefix_length: Option<i32>,
}

/// SoftwareNetworkConfiguration is the software defined overlay network configuration.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ResourceGroupStatusSoftwareNetworkConfiguration {
    /// LogicalNetwork is logical network name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "LogicalNetwork"
    )]
    pub logical_network: Option<String>,
    /// OvnService is the OVN central service name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "ovnServiceName"
    )]
    pub ovn_service_name: Option<String>,
}
