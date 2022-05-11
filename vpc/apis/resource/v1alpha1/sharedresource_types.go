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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type SharedResourceConditionType string

// SharedResourceSpec defines the desired state of SharedResource
type SharedResourceSpec struct {
	// ResourceGroup this SharedResource belongs.
	ResourceGroup string `json:"resourceGroup,omitempty"`
	// Type is this ManagedResource type.
	Type ResourceType `json:"type,omitempty"`
	// IPs are fabric IPs of the shared resources.
	IPs []IPAddress `json:"ips,omitempty"`
}

// SharedResourceCondition defines responses of ManagedResource create/delete/update.
type SharedResourceCondition struct {
	// Type is SharedResourceCondition type.
	Type SharedResourceConditionType `json:"type,omitempty"`
	// Status is SharedResourceCondition status.
	Status corev1.ConditionStatus `json:"status,omitempty"`
	// LastTransitionTime is the last transaction time for this ManagedResource.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
	// Reason is reason for the transaction.
	Reason string `json:"reason,omitempty"`
	// Message is message for the transaction.
	Message string `json:"message,omitempty"`
}

// SharedResourceStatus defines the observed state of SharedResource
type SharedResourceStatus struct {
	// Conditions specifies responses of ManagedResource create/delete/update.
	Conditions []SharedResourceCondition `json:"conditions,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// SharedResource is the Schema for the sharedresources API
type SharedResource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SharedResourceSpec   `json:"spec,omitempty"`
	Status SharedResourceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// SharedResourceList contains a list of SharedResource
type SharedResourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SharedResource `json:"items"`
}

func init() {
	SchemeBuilder.Register(&SharedResource{}, &SharedResourceList{})
}
