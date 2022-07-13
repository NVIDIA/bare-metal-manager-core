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

type ManagedResourceConditionType string
type ManagedResourceState string
type HostAccess string

const (
	ManagedResourceFinalizer = "managedresource.resource.vpc.forge/finalizer"
)

const (
	ManagedResourceConditionTypeRemove ManagedResourceConditionType = "Destroy"
	ManagedResourceConditionTypeAdd    ManagedResourceConditionType = "Create"
)

const (
	ManagedResourceStateUp    ManagedResourceState = "Up"
	ManagedResourceStateDown  ManagedResourceState = "Down"
	ManagedResourceStateError ManagedResourceState = "Error"
)

const (
	// HostAccessIsolated requests no IP to access the host from outside the ResourceGroup overlay.
	HostAccessIsolated HostAccess = "IsolatedAccess"
	// HostAccessFabricDirect allow host unfiltered access to/from within the DC without NATting.
	// Care needs to taken so that there are no overlapping IP ranges between overlays and network fabric.
	HostAccessFabricDirect HostAccess = "FabricAccessDirect"
	// HostAccessEgress requests IP allowing host access to the network fabric.
	HostAccessEgress HostAccess = "HostAccessIngressIsolated"
	// HostAccessFabric requests an IP allowing host access from and to the network fabric.
	HostAccessFabric HostAccess = "FabricAccess"
)

// IPAssociation describes BM host IP to Fabric IP and Public IP association.
type IPAssociation struct {
	// HostIP is an overlay IP assigned to the host.
	HostIP IPAddress `json:"hostIP,omitempty"`
	// FabricIP is a network fabric IP routable within a data center.
	FabricIP IPAddress `json:"fabricIP,omitempty"`
}

// ManagedResourceSpec defines the desired state of ManagedResource
type ManagedResourceSpec struct {
	// ResourceGroup this ManagedResource belongs.
	ResourceGroup string `json:"resourceGroup,omitempty"`
	// Type is this ManagedResource type.
	Type ResourceType `json:"type,omitempty"`
	// State is ManagedResource's state.
	State ManagedResourceState `json:"State,omitempty"`
	// HostInterfaceIP is the host interface IP of this ManagedResource.
	HostInterfaceIP IPAddress `json:"hostInterfaceIP,omitempty"`
	// HostInterfaceMAC is the host MAC of this ManagedResource.
	HostInterfaceMAC MACAddress `json:"hostInterfaceMAC,omitempty"`
	// DPUIPs are IPs on DPU.
	// if HostInterfaceAccess >= FabricAccess it must contain second IP which will be used
	// to access the host from DC.
	// This attribute is only required if ResourceGroup.Spec.NetworkImplementationType=Software
	DPUIPs []IPAddress `json:"dpuIPs,omitempty"`
	// HostInterfaceAccess specifies a host interface's accessibility.
	HostInterfaceAccess HostAccess `json:"hostInterfaceAccess,omitempty"`
	// HostInterface uniquely identifies a host interface.
	HostInterface string `json:"hostInterface,omitempty"`
}

// ManagedResourceCondition defines responses of ManagedResource create/delete/update.
type ManagedResourceCondition struct {
	// Type is ManagedResourceCondition type.
	Type ManagedResourceConditionType `json:"type,omitempty"`
	// Status is ManagedResourceCondition status.
	Status corev1.ConditionStatus `json:"status,omitempty"`
	// LastTransitionTime is the last transaction time for this ManagedResource.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is reason for the transaction.
	Reason string `json:"reason,omitempty"`
	// Message is message for the transaction.
	Message string `json:"message,omitempty"`
}

// NetworkFabricReference references to a network fabric device.
type NetworkFabricReference struct {
	Kind               string `json:"kind,omitempty"`
	Name               string `json:"name,omitempty"`
	Port               string `json:"port,omitempty"`
	ConfigurationState string `json:"ConfigurationState,omitempty"`
}

// LogicalPortReference references to a logical port on overlay network connecting to this ManagedResource.
type LogicalPortReference struct {
	// LogicalPort is the logical port.
	LogicalPort string `json:"logicalPort,omitempty"`
	// Dpu is the DPU this logicalPort is configured on.
	DPU string `json:"dpu,omitempty"`
}

// ManagedResourceStatus defines the observed state of ManagedResource
type ManagedResourceStatus struct {
	// HostAccessIPs are IPs to access the host from within DC or from the public domain.
	HostAccessIPs *IPAssociation `json:"hostAccessIPs,omitempty"`
	// NetworkFabricReference refers to a network fabric device that this ManagedResource connects to.
	NetworkFabricReference *NetworkFabricReference `json:"networkFabricReference,omitempty"`
	// Conditions specify responses of ManagedResource create/delete/update.
	Conditions []ManagedResourceCondition `json:"conditions,omitempty"`
	// NetworkPolicies applied to this ManagedResource.
	NetworkPolicies []string `json:"networkPolicies,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="fabric-device",type=string,JSONPath=`.status.networkFabricReference.name`
//+kubebuilder:printcolumn:name="resourcegroup",type=string,JSONPath=`.spec.resourceGroup`
//+kubebuilder:printcolumn:name="hostIP",type=string,JSONPath=`.status.hostAccessIPs.hostIP`
//+kubebuilder:printcolumn:name="fabricIP",type=string,JSONPath=`.status.hostAccessIPs.fabricIP`
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[0].status`

// ManagedResource is the Schema for the managedresources API
type ManagedResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ManagedResourceSpec   `json:"spec,omitempty"`
	Status ManagedResourceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ManagedResourceList contains a list of ManagedResource
type ManagedResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ManagedResource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ManagedResource{}, &ManagedResourceList{})
}

var (
	ManagedResourceName = reflect.TypeOf(ManagedResource{}).Name()
)
