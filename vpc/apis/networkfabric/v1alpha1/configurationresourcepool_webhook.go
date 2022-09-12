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
	"fmt"
	"net"
	"strconv"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

// log is for logging in this package.
var configurationresourcepoollog = logf.Log.WithName("configurationresourcepool-resource")

func (r *ConfigurationResourcePool) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-networkfabric-vpc-forge-gitlab-master-nvidia-com-v1alpha1-configurationresourcepool,mutating=true,failurePolicy=fail,sideEffects=None,groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=configurationresourcepools,verbs=create;update,versions=v1alpha1,name=mconfigurationresourcepool.kb.io,admissionReviewVersions={v1,v1beta1}

type poolConfig struct {
	Type             PoolRangeType
	SupportedBitSize []int32
}

var (
	_                      webhook.Defaulter = &ConfigurationResourcePool{}
	supportedResourcePools                   = map[string]poolConfig{
		string(PublicIPv4ResourcePool): {
			Type: RangeTypeIPv4,
		},
		string(DatacenterIPv4ResourcePool): {
			Type: RangeTypeIPv4,
		},
		string(OverlayIPv4ResourcePool): {
			Type:             RangeTypeIPv4,
			SupportedBitSize: []int32{0, 3, 4, 5, 6, 7, 8},
		},
		string(VNIResourcePool): {
			Type: RangeTypeInteger,
		},
		string(VlanIDResourcePool): {
			Type: RangeTypeInteger,
		},
		string(LoopbackIPResourcePool): {
			Type: RangeTypeIPv4,
		},
	}
)

func validateIPRanges(ipRanges []PoolRange) error {
	for _, r := range ipRanges {
		ipStart := net.ParseIP(r.Start).To4()
		ipEnd := net.ParseIP(r.End).To4()
		if ipStart == nil || ipEnd == nil || utils.Ip2int(ipStart) >= utils.Ip2int(ipEnd) {
			return fmt.Errorf("invalid IP range [%v, %v)", r.Start, r.End)
		}
	}
	return nil
}

func validateIntRanges(intRanges []PoolRange) error {
	for _, r := range intRanges {
		start, errs := strconv.ParseUint(r.Start, 10, 64)
		end, erre := strconv.ParseUint(r.End, 10, 64)
		if errs != nil || erre != nil || start >= end {
			return fmt.Errorf("invalid integer range [%v, %v)", r.Start, r.End)
		}
	}
	return nil
}

func validate(r *ConfigurationResourcePool) error {
	pool, ok := supportedResourcePools[r.Name]
	if !ok {
		var pools []string
		for p := range supportedResourcePools {
			pools = append(pools, p)
		}
		return fmt.Errorf("unknown resource pool %s, choose from %v", r.Name, pools)
	}
	if len(r.Spec.Ranges) == 0 {
		return fmt.Errorf("no ranges specified")
	}
	if r.Spec.Type != pool.Type {
		return fmt.Errorf("pool type mismatch, have: %s, expected: %s", r.Spec.Type, pool.Type)
	}
	if !(r.Spec.AllocationBlockSize == 0 && pool.SupportedBitSize == nil) {
		found := false
		for _, s := range pool.SupportedBitSize {
			if s == r.Spec.AllocationBlockSize {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("pool AllocationBlockSize not supported, choose from: %v", pool.SupportedBitSize)
		}
	}
	if r.Spec.Type == RangeTypeIPv4 {
		return validateIPRanges(r.Spec.Ranges)
	}
	return validateIntRanges(r.Spec.Ranges)
}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *ConfigurationResourcePool) Default() {
	// configurationresourcepoollog.Info("default", "name", r.Name)
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-networkfabric-vpc-forge-gitlab-master-nvidia-com-v1alpha1-configurationresourcepool,mutating=false,failurePolicy=fail,sideEffects=None,groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=configurationresourcepools,verbs=create;update,versions=v1alpha1,name=vconfigurationresourcepool.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &ConfigurationResourcePool{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *ConfigurationResourcePool) ValidateCreate() error {
	configurationresourcepoollog.Info("validate create", "name", r.Name)
	return validate(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *ConfigurationResourcePool) ValidateUpdate(old runtime.Object) error {
	configurationresourcepoollog.Info("validate update", "name", r.Name)
	op := old.(*ConfigurationResourcePool)
	if op.Spec.AllocationBlockSize != r.Spec.AllocationBlockSize {
		return fmt.Errorf("field AllocationBlockSize is immutable")
	}
	return validate(r)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *ConfigurationResourcePool) ValidateDelete() error {
	// configurationresourcepoollog.Info("validate delete", "name", r.Name)
	return nil
}
