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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var networkpolicylog = logf.Log.WithName("networkpolicy-resource")

func (r *NetworkPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-networkpolicy,mutating=true,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=networkpolicies,verbs=create;update,versions=v1alpha1,name=mnetworkpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &NetworkPolicy{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *NetworkPolicy) Default() {
	networkpolicylog.Info("default", "name", r.Name)
	for i := range r.Spec.IngressRules {
		rule := &r.Spec.IngressRules[i]
		if rule.FromAddresses == nil {
			rule.FromAddresses = []NetworkPolicyAddress{{IPCIDR: "0.0.0.0/0"}}
		}
		for j := range rule.Ports {
			port := &rule.Ports[j]
			if len(port.Protocol) == 0 {
				port.Protocol = NetworkPolicyProtocolTCP
			}
		}
	}
	for i := range r.Spec.EgressRules {
		rule := &r.Spec.EgressRules[i]
		if rule.ToAddresses == nil {
			rule.ToAddresses = []NetworkPolicyAddress{{IPCIDR: "0.0.0.0/0"}}
		}
		for j := range rule.Ports {
			port := &rule.Ports[j]
			if len(port.Protocol) == 0 {
				port.Protocol = NetworkPolicyProtocolTCP
			}
		}
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-resource-vpc-forge-gitlab-master-nvidia-com-v1alpha1-networkpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=networkpolicies,verbs=create;update,versions=v1alpha1,name=vnetworkpolicy.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &NetworkPolicy{}

func validateNetworkPolicy(spec *NetworkPolicySpec) error {
	if spec.LeafSelector.MatchLabels == nil && spec.ManagedResourceSelector.MatchLabels == nil {
		return fmt.Errorf("one of LeafSelector and ManagedResourceSelector must be specified")
	}

	for _, rule := range spec.IngressRules {
		for _, addr := range rule.FromAddresses {
			if addr.ManagedResourceSelector.MatchLabels != nil && len(addr.IPCIDR) > 0 {
				return fmt.Errorf("ip address can either be IPCIDR block or ManagedResourceSelector, but not both")
			}
			if _, _, err := net.ParseCIDR(string(addr.IPCIDR)); err != nil {
				if ip := net.ParseIP(string(addr.IPCIDR)); ip != nil {
					addr.IPCIDR += "/32"
				} else {
					return fmt.Errorf("inccrrect IPCIDR address format")
				}
			}
		}
		for _, port := range rule.Ports {
			if port.Begin <= 0 {
				return fmt.Errorf("port range start value must be greater than zero")
			}
			if port.End != 0 && port.End <= port.Begin {
				return fmt.Errorf("invalid port range")
			}
		}
	}
	for _, rule := range spec.EgressRules {
		for _, addr := range rule.ToAddresses {
			if addr.ManagedResourceSelector.MatchLabels != nil && len(addr.IPCIDR) > 0 {
				return fmt.Errorf("ip address can either be IPCIDR block or ManagedResourceSelector, but not both")
			}
			if _, _, err := net.ParseCIDR(string(addr.IPCIDR)); err != nil {
				if ip := net.ParseIP(string(addr.IPCIDR)); ip != nil {
					addr.IPCIDR += "/32"
				} else {
					return fmt.Errorf("inccrrect IPCIDR address format")
				}
			}
		}
		for _, port := range rule.Ports {
			if port.Begin <= 0 {
				return fmt.Errorf("port range start value must be greater than zero")
			}
			if port.End != 0 && port.End <= port.Begin {
				return fmt.Errorf("invalid port range")
			}
		}
	}
	return nil
}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *NetworkPolicy) ValidateCreate() error {
	networkpolicylog.Info("validate create", "name", r.Name, "LeafSelector", r.Spec.LeafSelector,
		"ResourceSelector", r.Spec.ManagedResourceSelector)
	return validateNetworkPolicy(&r.Spec)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *NetworkPolicy) ValidateUpdate(old runtime.Object) error {
	networkpolicylog.Info("validate update", "name", r.Name)
	return validateNetworkPolicy(&r.Spec)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *NetworkPolicy) ValidateDelete() error {
	networkpolicylog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
