/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.


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

type NetworkDeviceConditionType string

const (
	NetworkDeviceVendorCumulus = "Cumulus"
)

const (
	NetworkDeviceConditionTypeLiveness = "Liveness"
)

// NetworkDeviceControl specifies information to control a network device.
type NetworkDeviceControl struct {
	// Vendor is this network device's vendor.
	Vendor string `json:"vendor,omitempty"`
	// ManagementIP is the management interface IP to access this network device.
	ManagementIP string `json:"managementIP,omitempty"`
	// MaintenanceMode is set to true when the controller no longer actively configures the device.
	MaintenanceMode bool `json:"maintenanceMode,omitempty"`
}

// NetworkDeviceCondition indicates the transactions with the network device.
type NetworkDeviceCondition struct {
	// Type is the network device condition type.
	Type NetworkDeviceConditionType `json:"type,omitempty"`
	// Status is the network device status.
	Status corev1.ConditionStatus `json:"status,omitempty"`
	// LastTransitionTime is the last transaction time for this ResourceGroup.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Message is the response received from the network device.
	Message string `json:"message,omitempty"`
}

// LeafSpec defines the desired state of Leaf
type LeafSpec struct {
	// Control specifies the ways to interact with this Leaf device.
	Control NetworkDeviceControl `json:"control,omitempty"`
	// HostInterfaces are host interfaces connected to this Leaf.
	// The key value pair is the host interface identifier and the leaf port connected to the host interface.
	HostInterfaces map[string]string `json:"hostInterfaces,omitempty"`
	// HostAdminIPs are host IPs when hosts are not part of any tenant networks, but still
	// need to access the network for host discovery, imaging, etc.
	// The key-value pair is the leaf port and the IP address assigned to the host interface connecting to
	// the leaf port
	HostAdminIPs map[string]string `json:"hostAdminIPs,omitempty"`
}

// LeafStatus defines the observed state of Leaf
type LeafStatus struct {
	// Conditions are the conditions of this Leaf device.
	Conditions []NetworkDeviceCondition `json:"conditions,omitempty"`
	// ASN assigned to this leaf.
	ASN uint32 `json:"asn,omitempty"`
	// LoobackIP assigned to this leaf.
	LoopbackIP string `json:"loopbackIP,omitempty"`
	// HostAdminIPs are host IPs in un-assigned state.
	HostAdminIPs map[string]string `json:"hostAdminIPs,omitempty"`
	// HostAdminDHCPServer is the DHCPServer for hosts in un-assigned state.
	HostAdminDHCPServer string `json:"hostAdminDHCPServer,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="mgmt-ip",type=string,JSONPath=`.spec.control.managementIP`
//+kubebuilder:printcolumn:name="maintenance",type=string,JSONPath=`.spec.control.maintenanceMode`
//+kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[0].status`

// Leaf is the Schema for the leaf device API
type Leaf struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LeafSpec   `json:"spec,omitempty"`
	Status LeafStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// LeafList contains a list of Leaf
type LeafList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Leaf `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Leaf{}, &LeafList{})
}

var (
	LeafName = reflect.TypeOf(Leaf{}).Name()
)
