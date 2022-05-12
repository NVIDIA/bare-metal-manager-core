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
	"reflect"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
)

// log is for logging in this package.
var (
	resourcegrouplog   = logf.Log.WithName("resourcegroup-resource")
	CheckPrerequisites func() error
)

func (r *ResourceGroup) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

//+kubebuilder:webhook:path=/mutate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-resourcegroup,mutating=true,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=resourcegroups,verbs=create;update,versions=v1alpha1,name=mresourcegroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &ResourceGroup{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ResourceGroup) Default() {
	resourcegrouplog.V(1).Info("default", "name", r.Name)
	if len(r.Spec.NetworkImplementationType) == 0 {
		r.Spec.NetworkImplementationType = OverlayNetworkImplementationTypeFabric
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-resourcegroup,mutating=false,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=resourcegroups,verbs=create;update,versions=v1alpha1,name=vresourcegroup.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ResourceGroup{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceGroup) ValidateCreate() error {
	resourcegrouplog.V(1).Info("validateResourceGroup create", "name", r.Name)
	return validateResourceGroup(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceGroup) ValidateUpdate(old runtime.Object) error {
	resourcegrouplog.V(1).Info("validateResourceGroup update", "name", r.Name)
	if err := validateResourceGroup(r); err != nil {
		return err
	}
	or := old.(*ResourceGroup)
	if r.Spec.TenantIdentifier != or.Spec.TenantIdentifier {
		return fmt.Errorf("field TenantIdentifier is immutable")
	}
	if !reflect.DeepEqual(r.Spec.Network, or.Spec.Network) {
		return fmt.Errorf("field Network is immutable")
	}
	if r.Spec.OverlayIPPool != or.Spec.OverlayIPPool {
		return fmt.Errorf("field OverlayIPPool is immutable")
	}
	if r.Spec.FabricIPPool != r.Spec.FabricIPPool {
		return fmt.Errorf("field FabricIPPool is immutable")
	}
	if r.Spec.NetworkImplementationType != or.Spec.NetworkImplementationType {
		return fmt.Errorf("field NetworkImplementationType is immutable")
	}
	return nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ResourceGroup) ValidateDelete() error {
	resourcegrouplog.V(1).Info("validateResourceGroup delete", "name", r.Name)
	return nil
}

func validateResourceGroup(r *ResourceGroup) error {
	if r.Name != WellKnownAdminResourceGroup && CheckPrerequisites != nil {
		if err := CheckPrerequisites(); err != nil {
			return err
		}
	}
	if len(r.Spec.TenantIdentifier) == 0 {
		return fmt.Errorf("field TenantIdentifier must be specified")
	}
	if errStrs := validation.IsValidLabelValue(r.Spec.TenantIdentifier); len(errStrs) > 0 {
		return fmt.Errorf("field TenantIdentifier format error: %v", errStrs)
	}
	impls := []OverlayNetworkImplementationType{OverlayNetworkImplementationTypeFabric, OverlayNetworkImplementationTypeSoftware}
	found := false
	for _, impl := range impls {
		if r.Spec.NetworkImplementationType == impl {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unknopwn NetworkImplementationType %s, valid NetworkImplementationTypes %v",
			r.Spec.NetworkImplementationType, impls)
	}
	if len(r.Spec.DHCPServer) != 0 && net.ParseIP(string(r.Spec.DHCPServer)) == nil {
		return fmt.Errorf("field DHCPServer has incorrect IP format")
	}
	if r.Spec.Network != nil {
		ip := net.ParseIP(string(r.Spec.Network.IP))
		if ip == nil {
			return fmt.Errorf("field Network.IP is not specified or has incorrect IP format")
		}

		if ip.To4() == nil && r.Spec.Network.PrefixLength > net.IPv6len*8 || // ipv6
			r.Spec.Network.PrefixLength > net.IPv4len*8 { // ipv4
			return fmt.Errorf("field Network.PrefixLength exceeds IP length")
		}
		gw := net.ParseIP(string(r.Spec.Network.Gateway))
		if gw == nil {
			return fmt.Errorf("field Network.Gateway is not specified or has incorrect IP format")
		}
	}
	if r.Spec.Network != nil && len(r.Spec.DHCPServer) == 0 {
		return fmt.Errorf("field Network is specified without DHCPServer")
	}

	if r.Spec.NetworkImplementationType == OverlayNetworkImplementationTypeSoftware && r.Spec.Network == nil {
		return fmt.Errorf("fields Network and DHCP server must be specified if NetworkImplementationType is %s", OverlayNetworkImplementationTypeSoftware)
	}
	if r.Spec.Network == nil && len(r.Spec.OverlayIPPool) == 0 {
		return fmt.Errorf("one of Network or OverlayIPPool must be specified")
	}
	if len(r.Spec.OverlayIPPool) > 0 && r.Spec.OverlayIPPool != string(v1alpha1.OverlayIPv4ResourcePool) {
		return fmt.Errorf("invalid overlay IP pool, choose from: %s", v1alpha1.OverlayIPv4ResourcePool)
	}
	if len(r.Spec.FabricIPPool) > 0 && !(r.Spec.FabricIPPool == string(v1alpha1.DatacenterIPv4ResourcePool) ||
		r.Spec.FabricIPPool == string(v1alpha1.PublicIPv4ResourcePool)) {
		return fmt.Errorf("invalid fabric IP pool, choose from: %s, %s",
			v1alpha1.DatacenterIPv4ResourcePool, v1alpha1.PublicIPv4ResourcePool)
	}
	return nil
}
