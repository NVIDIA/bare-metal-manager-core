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
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var (
	leaflog            = logf.Log.WithName("leaf-resource")
	CheckPrerequisites func() error
)

func (r *Leaf) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-networkfabric-vpc-forge-gitlab-master-nvidia-com-v1alpha1-leaf,mutating=true,failurePolicy=fail,sideEffects=None,groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=leafs,verbs=create;update,versions=v1alpha1,name=mleaf.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Defaulter = &Leaf{}

func validateLeaf(r *Leaf) error {
	if CheckPrerequisites != nil {
		if err := CheckPrerequisites(); err != nil {
			return err
		}
	}
	items := strings.Split(r.Spec.Control.ManagementIP, ":")
	if len(items) == 0 || len(items) > 2 {
		return fmt.Errorf("field Control.ManagementIP has incorrect IP format: IP[:Port]")
	}
	if net.ParseIP(items[0]) == nil {
		return fmt.Errorf("field Control.ManagementIP has incorrect IP format: IP[:Port]")
	}
	if len(items) > 1 {
		if _, err := strconv.ParseUint(items[1], 10, 16); err != nil {
			return fmt.Errorf("field Control.ManagementIP has incorrect IP format: IP[:Port]")
		}
	}
	for port, nic := range r.Spec.HostInterfaces {
		if len(port) == 0 || len(nic) == 0 {
			return fmt.Errorf("field HostInterfaces cannot have empty field")
		}
	}
	for port, ip := range r.Spec.HostAdminIPs {
		if len(port) == 0 {
			return fmt.Errorf("field HostAdminIPs cannot have empty field")
		}
		if len(ip) != 0 && net.ParseIP(ip) == nil {
			return fmt.Errorf("field HostAdminIPs has incorrect IP format")
		}
	}

	return nil
}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Leaf) Default() {
	leaflog.Info("default", "name", r.Name)

	// TODO(user): fill in your defaulting logic.
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
//+kubebuilder:webhook:path=/validate-networkfabric-vpc-forge-gitlab-master-nvidia-com-v1alpha1-leaf,mutating=false,failurePolicy=fail,sideEffects=None,groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=leafs,verbs=create;update,versions=v1alpha1,name=vleaf.kb.io,admissionReviewVersions={v1,v1beta1}

var _ webhook.Validator = &Leaf{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Leaf) ValidateCreate() error {
	leaflog.Info("validate create", "name", r.Name)
	return validateLeaf(r)
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Leaf) ValidateUpdate(old runtime.Object) error {
	leaflog.Info("validate update", "name", r.Name)
	return validateLeaf(r)
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Leaf) ValidateDelete() error {
	leaflog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil
}
