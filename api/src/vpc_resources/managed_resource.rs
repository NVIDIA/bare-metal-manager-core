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
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// ManagedResourceSpec defines the desired state of ManagedResource
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "resource.vpc.forge.gitlab-master.nvidia.com",
    version = "v1alpha1",
    kind = "ManagedResource",
    plural = "managedresources"
)]
#[kube(namespaced)]
#[kube(status = "ManagedResourceStatus")]
pub struct ManagedResourceSpec {
    /// State is ManagedResource's state.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "State")]
    pub state: Option<String>,
    /// DPUIPs are IPs on DPU. if HostInterfaceAccess >= FabricAccess it must contain second IP which will be used to access the host from DC. This attribute is only required if ResourceGroup.Spec.NetworkImplementationType=Software
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "dpuIPs")]
    pub dpu_i_ps: Option<Vec<String>>,
    /// HostInterface uniquely identifies a host interface.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostInterface"
    )]
    pub host_interface: Option<String>,
    /// HostInterfaceAccess specifies a host interface's accessibility.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostInterfaceAccess"
    )]
    pub host_interface_access: Option<String>,
    /// HostInterfaceIP is the host interface IP of this ManagedResource.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostInterfaceIP"
    )]
    pub host_interface_ip: Option<String>,
    /// HostInterfaceMAC is the host MAC of this ManagedResource.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostInterfaceMAC"
    )]
    pub host_interface_mac: Option<String>,
    /// ResourceGroup this ManagedResource belongs.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "resourceGroup"
    )]
    pub resource_group: Option<String>,
    /// Type is this ManagedResource type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// ManagedResourceStatus defines the observed state of ManagedResource
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatus {
    /// Conditions specify responses of ManagedResource create/delete/update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<ManagedResourceStatusConditions>>,
    /// DHCPServers are the IPAddresses of the DHCP servers (i.e. Carbide) for ManagedResources.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "dhcpServers"
    )]
    pub dhcp_servers: Option<Vec<String>>,
    /// HostAccessIPs are IPs to access the host from within DC or from the public domain.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hostAccessIPs"
    )]
    pub host_access_i_ps: Option<ManagedResourceStatusHostAccessIPs>,
    /// NetworkFabricReference refers to a network fabric device that this ManagedResource connects to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "networkFabricReference"
    )]
    pub network_fabric_reference: Option<ManagedResourceStatusNetworkFabricReference>,
    /// NetworkPolicies applied to this ManagedResource.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "networkPolicies"
    )]
    pub network_policies: Option<Vec<String>>,
}

/// ManagedResourceCondition defines responses of ManagedResource create/delete/update.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatusConditions {
    /// LastTransitionTime is the last transaction time for this ManagedResource.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "lastTransitionTime"
    )]
    pub last_transition_time: Option<String>,
    /// Message is message for the transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Reason is reason for the transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Status is ManagedResourceCondition status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Type is ManagedResourceCondition type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// HostAccessIPs are IPs to access the host from within DC or from the public domain.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatusHostAccessIPs {
    /// FabricIP is a network fabric IP routable within a data center.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fabricIP")]
    pub fabric_ip: Option<String>,
    /// HostIP is an overlay IP assigned to the host.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "hostIP")]
    pub host_ip: Option<String>,
}

/// NetworkFabricReference refers to a network fabric device that this ManagedResource connects to.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatusNetworkFabricReference {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "ConfigurationState"
    )]
    pub configuration_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
}
