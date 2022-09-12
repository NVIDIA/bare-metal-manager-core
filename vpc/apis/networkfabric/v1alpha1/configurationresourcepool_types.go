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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type WellKnownConfigurationResourcePool string

const (
	// PublicIPv4ResourcePool contains public IPv4 used to access overlay hosts from the internet.
	PublicIPv4ResourcePool WellKnownConfigurationResourcePool = "public-ipv4"

	// DatacenterIPv4ResourcePool contains data center IPv4 used to access host from within the data center.
	DatacenterIPv4ResourcePool WellKnownConfigurationResourcePool = "dc-ipv4"

	// OverlayIPv4ResourcePool contains overlay IPv4 for hosts.
	OverlayIPv4ResourcePool WellKnownConfigurationResourcePool = "overlay-ipv4"

	// VNIResourcePool contains VNIs assigned to VxLAN. There cannot be overlapping VNIs anywhere else
	// within the same network fabric.
	VNIResourcePool WellKnownConfigurationResourcePool = "vni"

	// VlanIDResourcePool contains VLAN IDs on network fabric leaf devices.
	VlanIDResourcePool WellKnownConfigurationResourcePool = "vlan-id"

	// LoopbackIPResourcePool contains IPs assigned to DPU loop back interface.
	LoopbackIPResourcePool WellKnownConfigurationResourcePool = "lo-ip"

	// ASNResourcePool contains Autonomous System Number assigned to the BGP instance running on HBN.
	ASNResourcePool WellKnownConfigurationResourcePool = "asn"
)

type PoolRangeType string

const (
	RangeTypeInteger PoolRangeType = "integer"
	RangeTypeIPv4    PoolRangeType = "ipv4"
)

// PoolRange specify a continuous range.
type PoolRange struct {
	// Start is start of the PoolRange.
	Start string `json:"start,omitempty"`
	// End is end of the PoolRange.
	End string `json:"end,omitempty"`
}

// ConfigurationResourcePoolSpec defines the desired state of ConfigurationResourcePool
type ConfigurationResourcePoolSpec struct {
	// Type specifies the PoolRange type.
	Type PoolRangeType `json:"type,omitempty"`
	// Range is the ConfigurationResourcePool half-open range [Start, End).
	Ranges []PoolRange `json:"ranges,omitempty"`
	// AllocationBlockBitSize is allocation block size in bits.
	// +kubebuilder:validation:Maximum:=268435455
	// +kubebuilder:validation:Minimum:=0
	AllocationBlockSize int32 `json:"allocationBlockSize,omitempty"`
}

// ConfigurationResourcePoolStatus defines the observed state of ConfigurationResourcePool
type ConfigurationResourcePoolStatus struct {
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ConfigurationResourcePool is the Schema for the configurationresourcepools API
type ConfigurationResourcePool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfigurationResourcePoolSpec   `json:"spec,omitempty"`
	Status ConfigurationResourcePoolStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ConfigurationResourcePoolList contains a list of ConfigurationResourcePool
type ConfigurationResourcePoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConfigurationResourcePool `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfigurationResourcePool{}, &ConfigurationResourcePoolList{})
}
