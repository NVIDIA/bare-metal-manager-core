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
	"fmt"
	"net"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var managedresourcelog = logf.Log.WithName("managedresource-resource")

func (r *ManagedResource) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-managedresource,mutating=true,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=managedresources,verbs=create;update,versions=v1alpha1,name=mmanagedresource.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ManagedResource{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ManagedResource) Default() {
	managedresourcelog.V(1).Info("default", "name", r.Name)

	if len(r.Spec.Type) == 0 {
		r.Spec.Type = ResourceTypeBareMetal
	}
	if len(r.Spec.HostInterfaceAccess) == 0 {
		r.Spec.HostInterfaceAccess = HostAccessIsolated
	}
	if len(r.Spec.HostInterface) == 0 {
		r.Spec.HostInterface = string(r.Spec.HostInterfaceMAC)
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-managedresource,mutating=false,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=managedresources,verbs=create;update,versions=v1alpha1,name=vmanagedresource.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ManagedResource{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ManagedResource) ValidateCreate() error {
	managedresourcelog.V(1).Info("validateResourceGroup create", "name", r.Name)
	return validateManagedResource(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ManagedResource) ValidateUpdate(old runtime.Object) error {
	managedresourcelog.V(1).Info("validateResourceGroup update", "name", r.Name)
	if err := validateManagedResource(r); err != nil {
		return err
	}
	or := old.(*ManagedResource)
	if len(or.Spec.ResourceGroup) > 0 &&
		r.Spec.ResourceGroup != or.Spec.ResourceGroup {
		return fmt.Errorf("managedResource in a ResourceGroup %v cannot be assigned to a different ResourceGroup %v or removed from this resourceGroup",
			or.Spec.ResourceGroup, r.Spec.ResourceGroup)
	}
	if r.Spec.HostInterfaceMAC != or.Spec.HostInterfaceMAC {
		return fmt.Errorf("field HostInterfaceMAC is immutable")
	}
	if r.Spec.Type != or.Spec.Type {
		return fmt.Errorf("field Type is immutable")
	}
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ManagedResource) ValidateDelete() error {
	managedresourcelog.V(1).Info("validateResourceGroup delete", "name", r.Name)
	return nil
}

func validateManagedResource(r *ManagedResource) error {
	if r.Spec.ResourceGroup == WellKnownAdminResourceGroup {
		return fmt.Errorf("managedResource cannot be associated with special ResourceGroup %s", WellKnownAdminResourceGroup)
	}
	types := []ResourceType{ResourceTypeBareMetal, ResourceTypeStorage}
	found := false
	for _, t := range types {
		if r.Spec.Type == t {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown Type %s is specified, valid Type %v", r.Spec.Type, types)
	}
	if len(r.Spec.HostInterfaceIP) != 0 && net.ParseIP(string(r.Spec.HostInterfaceIP)) == nil {
		return fmt.Errorf("field HostInterfaceIP has incorrect IP format")
	}
	if len(r.Spec.HostInterfaceMAC) != 0 {
		if _, err := net.ParseMAC(string(r.Spec.HostInterfaceMAC)); err != nil {
			return fmt.Errorf("field HostInterfaceMAC has incorrect MAC format")
		}
	}
	for _, ip := range r.Spec.DPUIPs {
		if net.ParseIP(string(ip)) == nil {
			return fmt.Errorf("field DPUIP has incorrect IP format: %v", ip)
		}
	}
	found = false
	accesses := []HostAccess{HostAccessIsolated, HostAccessFabric, HostAccessEgress, HostAccessFabricDirect}
	for _, a := range accesses {
		if r.Spec.HostInterfaceAccess == a {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknown HostInterfaceAccess %s is specified, valid HostInterfaceAccess %v", r.Spec.HostInterfaceAccess, accesses)
	}
	if len(r.Spec.HostInterface) == 0 {
		return fmt.Errorf("mandatory field HostInterface is missing")
	}
	return nil
}
