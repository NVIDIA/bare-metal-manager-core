/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const (
	ResourceGroupFinalizer = "resourcegroup.resource.vpc.forge/finalizer"
)

const (
	// WellKnownAdminResourceGroup provides network properties shared by all un-assigned hosts.
	WellKnownAdminResourceGroup = "administration-resource-group"
)

type ResourceType string

// IPAddress is IPv4 or IPv6 Addresse types.
type IPAddress string
type MACAddress string
type ResourceGroupConditionType string
type OverlayNetworkImplementationType string

const (
	ResourceTypeBareMetal ResourceType = "BareMetal"
	ResourceTypeStorage   ResourceType = "Storage"
)

const (
	OverlayNetworkImplementationTypeFabric   OverlayNetworkImplementationType = "Fabric"
	OverlayNetworkImplementationTypeSoftware OverlayNetworkImplementationType = "Software"
)

const (
	ResourceGroupConditionTypeDestroy = "Destroy"
	ResourceGroupConditionTypeCreate  = "Create"
)

// IPNet describes an IPv4 or IPv6 network.
type IPNet struct {
	IP           IPAddress `json:"ip,omitempty"`
	PrefixLength uint32    `json:"prefixLength,omitempty"`
	// Gateway is the default gateway for IPv4 subnet.
	Gateway IPAddress `json:"gateway,omitempty"`
}

// ResourceGroupSpec defines the desired state of ResourceGroup.
type ResourceGroupSpec struct {
	// TenantIdentifier identifies the tenant associated with this ResourceGroup.
	TenantIdentifier string `json:"tenantIdentifier,omitempty"`
	// Network defines the overlay L2 network for this ResourceGroup. It is immutable.
	Network *IPNet `json:"network,omitempty"`
	// DHCPServer is the IPAddress of the DHCP server (i.e. Carbide) for ManagedResources in this ResourceGroup.
	DHCPServer IPAddress `json:"dhcpServer,omitempty"`
	// NetworkImplementationType is the backend implementing the l2 overlay network. Default to "Fabric".
	NetworkImplementationType OverlayNetworkImplementationType `json:"networkImplementationType,omitempty"`
	// OverlayIPPool is used to allocate overlay IP ranges on tenant's behave.
	OverlayIPPool string `json:"overlayIPPool,omitempty"`
	// FabricIPPool is used to assign fabric routable IPs to tenant hosts on the overlay network.
	FabricIPPool string `json:"fabricIPPool,omitempty"`
}

// ResourceGroupCondition defines responses of ResourceGroup create/delete/update.
type ResourceGroupCondition struct {
	// Type is ResourceGroupCondition type.
	Type ResourceGroupConditionType `json:"type,omitempty"`
	// Status is ResourceGroupCondition status.
	Status corev1.ConditionStatus `json:"status,omitempty"`
	// LastTransitionTime is the last transaction time for this ResourceGroup.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is reason for the transaction.
	Reason string `json:"reason,omitempty"`
	// Message is message from the transaction.
	Message string `json:"message,omitempty"`
}

// FabricNetworkConfiguration is the network fabric details of the overlay network.
type FabricNetworkConfiguration struct {
	// VRF is the VRF name for this overlay network.
	// TODO, Do we need VRF ??
	VRF string `json:"vrf,omitempty"`
	// VNI is the vni for this overlay network.
	VNI uint32 `json:"vni,omitempty"`
	// VlanID is the ID of VLAN interfaces for this overlay network
	VlanID uint32 `json:"vlanID,omitempty"`
}

type SoftwareNetworkConfiguration struct {
	// OvnService is the OVN central service name.
	OvnService string `json:"ovnServiceName,omitempty"`
	// LogicalNetwork is logical network name.
	LogicalNetwork string `json:"LogicalNetwork,omitempty"`
}

// ResourceGroupStatus defines the observed state of ResourceGroup
type ResourceGroupStatus struct {
	// SNATIPs is the snat IPs for overlay traffic entering network fabric.
	SNATIPs []IPAddress `json:"snatIPs,omitempty"`
	// Network is the overlay L2 network for this ResourceGroup.
	// If Spec.Network is defined, this is same network, otherwise it is auto-allocated.
	Network *IPNet `json:"network,omitempty"`
	// DHCPCircID is DHCP option 82 - circuit ID. This is the interface name on which DHCP requests
	// for this ResourceGroup are received on.
	DHCPCircID string `json:"dhcpCircID,omitempty"`

	// ManagedResourceCount is the number of ManagedResources in the ResourceGroup.
	ManagedResourceCount uint64 `json:"managedResourceCount,omitempty"`
	// FabricNetworkConfiguration is the fabric configuration supporting this overlay network.
	FabricNetworkConfiguration *FabricNetworkConfiguration `json:"fabricNetworkConfiguration,omitempty"`
	// SoftwareNetworkConfiguration is the software defined overlay network configuration.
	SoftwareNetworkConfiguration *SoftwareNetworkConfiguration `json:"softwareNetworkConfiguration,omitempty"`
	// Conditions specifies responses of ResourceGroup create/delete/update.
	Conditions []ResourceGroupCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Network",type=string,JSONPath=`.status.network`
//+kubebuilder:printcolumn:name="DHCPCircID",type=string,JSONPath=`.status.dhcpCircID`
//+kubebuilder:printcolumn:name="VNI",type=string,JSONPath=`.status.fabricNetworkConfiguration.vni`
//+kubebuilder:printcolumn:name="VLAN",type=string,JSONPath=`.status.fabricNetworkConfiguration.vlanID`
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[0].status`

// ResourceGroup is the Schema for the resourcegroups API
type ResourceGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ResourceGroupSpec   `json:"spec,omitempty"`
	Status ResourceGroupStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ResourceGroupList contains a list of ResourceGroup
type ResourceGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ResourceGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ResourceGroup{}, &ResourceGroupList{})
}

var (
	ResourceGroupName = reflect.TypeOf(ResourceGroup{}).Name()
)
