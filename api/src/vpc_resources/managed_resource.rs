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
    #[serde(rename = "State")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// DPUIPs are IPs on DPU. if HostInterfaceAccess >= FabricAccess it must contain second IP which will be used to access the host from DC. This attribute is only required if ResourceGroup.Spec.NetworkImplementationType=Software
    #[serde(rename = "dpuIPs")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpu_i_ps: Option<Vec<String>>,
    /// HostInterface uniquely identifies a host interface.
    #[serde(rename = "hostInterface")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_interface: Option<String>,
    /// HostInterfaceAccess specifies a host interface's accessibility.
    #[serde(rename = "hostInterfaceAccess")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_interface_access: Option<String>,
    /// HostInterfaceIP is the host interface IP of this ManagedResource.
    #[serde(rename = "hostInterfaceIP")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_interface_ip: Option<String>,
    /// HostInterfaceMAC is the host MAC of this ManagedResource.
    #[serde(rename = "hostInterfaceMAC")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_interface_mac: Option<String>,
    /// ResourceGroup this ManagedResource belongs.
    #[serde(rename = "resourceGroup")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// HostAccessIPs are IPs to access the host from within DC or from the public domain.
    #[serde(rename = "hostAccessIPs")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_access_i_ps: Option<ManagedResourceStatusHostAccessIPs>,
    /// NetworkFabricReference refers to a network fabric device that this ManagedResource connects to.
    #[serde(rename = "networkFabricReference")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_fabric_reference: Option<ManagedResourceStatusNetworkFabricReference>,
    /// NetworkPolicies applied to this ManagedResource.
    #[serde(rename = "networkPolicies")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policies: Option<Vec<String>>,
}

/// ManagedResourceCondition defines responses of ManagedResource create/delete/update.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatusConditions {
    /// LastTransitionTime is the last transaction time for this ManagedResource.
    #[serde(rename = "lastTransitionTime")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(rename = "fabricIP")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_ip: Option<String>,
    /// HostIP is an overlay IP assigned to the host.
    #[serde(rename = "hostIP")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
}

/// NetworkFabricReference refers to a network fabric device that this ManagedResource connects to.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct ManagedResourceStatusNetworkFabricReference {
    #[serde(rename = "ConfigurationState")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
}
