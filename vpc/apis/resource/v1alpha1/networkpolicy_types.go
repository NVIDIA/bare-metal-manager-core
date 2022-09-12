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

type NetworkPolicyProtocol string
type NetworkPolicyConditionType string

const (
	NetworkPolicyFinalizer = "networkpolicy.resource.vpc.forge/finalizer"
)

const (
	NetworkPolicyProtocolTCP  NetworkPolicyProtocol = "TCP"
	NetworkPolicyProtocolUDP  NetworkPolicyProtocol = "UDP"
	NetworkPolicyProtocolICMP NetworkPolicyProtocol = "ICMP"
)

const (
	NetworkPolicyConditionTypeDestroy NetworkPolicyConditionType = "Destroy"
	NetworkPolicyConditionTypeCreate  NetworkPolicyConditionType = "Create"
)

// LabelSelector selects ManagedResources based on their labels.
type LabelSelector struct {
	// MatchLabels selects a ManagedResource if *all* key/value pairs it contains are found in
	// the ManagedResource's Labels.
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// NetworkPolicyAddress describes some IP addresses that allow traffic to/from.
type NetworkPolicyAddress struct {
	// ManagedResourceSelector selects ManagedResources, and therefore their IP addresses.
	ManagedResourceSelector LabelSelector `json:"managedResourceSelector,omitempty"`
	IPCIDR                  IPAddress     `json:"ipCIDR,omitempty"`
}

type NetworkPolicyPort struct {
	// [Begin, end) specify half-close IP packet port.
	// +kubebuilder:validation:Maximum:=65535
	// +kubebuilder:validation:Minimum:=1
	Begin int32 `json:"begin,required"`
	// +kubebuilder:validation:Maximum:=65535
	// +kubebuilder:validation:Minimum:=1
	End int32 `json:"end,omitempty"`
	// Protocol is the IP packet protocol, default to TCP.
	Protocol NetworkPolicyProtocol `json:"protocol,omitempty"`
}

// NetworkPolicyIngressRule specifies a rule applied to ingress traffic to the ManagedResource.
type NetworkPolicyIngressRule struct {
	// FromAddresses describes all IP addresses from which traffic is allowed. Default is allowing all traffic.
	FromAddresses []NetworkPolicyAddress `json:"fromAddresses,omitempty"`
	// Ports describes all destination ports and protocol to which traffic is allowed. Default is allowing all traffic.
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyEgressRule specifies a rule applied to egress traffic from the ManagedResource.
type NetworkPolicyEgressRule struct {
	// ToAddresses describes all IP addresses to which traffic is allowed. Default is allowing all traffic.
	ToAddresses []NetworkPolicyAddress `json:"toAddresses,omitempty"`
	// Ports describes all destination ports and protocol to which traffic is allowed. Default is allowing all traffic.
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyCondition defines responses of NetworkPolicy create/delete/update.
type NetworkPolicyCondition struct {
	// Type is NetworkPolicyCondition type.
	Type NetworkPolicyConditionType `json:"type,omitempty"`
	// Status is NetworkPolicyCondition status.
	Status corev1.ConditionStatus `json:"status,omitempty"`
	// LastTransitionTime is the last transaction time for this NetworkPolicy.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is reason for the transaction.
	Reason string `json:"reason,omitempty"`
	// Message is message from the transaction.
	Message string `json:"message,omitempty"`
}

// NetworkPolicySpec defines the desired state of NetworkPolicy.
// If a traffic flow matches any rules, it is allowed in the corresponding direction, otherwise it is denied.
type NetworkPolicySpec struct {
	// ManagedResourceSelector selects the ManagedResources on which this NetworkPolicy is applied
	ManagedResourceSelector LabelSelector `json:"managedResourceSelector,omitempty"`
	// LeafSelector selects hosts in admin state on which this NetworkPolicy is applied
	LeafSelector LabelSelector `json:"leafSelector,omitempty"`
	// IngressRules contains ingress rules
	IngressRules []NetworkPolicyIngressRule `json:"ingressRules,omitempty"`
	// EgressRules contains egress rules
	EgressRules []NetworkPolicyEgressRule `json:"egressRules,omitempty"`
}

// NetworkPolicyStatus defines the observed state of NetworkPolicy
type NetworkPolicyStatus struct {
	// ID is runtime allocated ID associated with this NetworkPolicy.
	// +kubebuilder:validation:Maximum:=65535
	// +kubebuilder:validation:Minimum:=1
	ID int32 `json:"id,omitempty"`
	// Conditions defines responses of NetworkPolicy create/delete/update
	Conditions []NetworkPolicyCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="rule-id",type=string,JSONPath=`.status.id`

// NetworkPolicy is the Schema for the networkpolicies API
type NetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetworkPolicySpec   `json:"spec,omitempty"`
	Status NetworkPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// NetworkPolicyList contains a list of NetworkPolicy
type NetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NetworkPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NetworkPolicy{}, &NetworkPolicyList{})
}

var (
	NetworkPolicyName = reflect.TypeOf(NetworkPolicy{}).Name()
)
