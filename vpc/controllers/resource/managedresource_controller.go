/*
Copyright 2021.

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

package resource

import (
	"context"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	controllers2 "gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
)

// ManagedResourceReconciler reconciles a ManagedResource object
type ManagedResourceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	VPCMgr vpc.VPCManager
}

//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=managedresources,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=managedresources/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=managedresources/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ManagedResource object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ManagedResourceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, fErr error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Received update")

	mr := &resource.ManagedResource{}
	if err := r.Get(ctx, req.NamespacedName, mr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	update := false
	updateStatus := false

	defer func() {
		// Update mr if needed before exiting.
		if update {
			if err := r.Update(ctx, mr); err != nil {
				log.Error(err, "Failed to update ManagedResource", "ManagedResource", req)
				if fErr == nil {
					fErr = err
				}
			}
		}
		if updateStatus {
			if err := r.Status().Update(ctx, mr); err != nil {
				log.V(1).Info("Failed to update ManagedResource.Status", "ManagedResource", req, "Err", err)
				if fErr == nil {
					fErr = err
				}
			}
		}
		fErr = vpc.IgnoreNetworkDeviceNotAvailableError(fErr)
	}()

	if mr.ObjectMeta.DeletionTimestamp.IsZero() {
		// Register finalizer.
		if !controllerutil.ContainsFinalizer(mr, resource.ManagedResourceFinalizer) {
			controllerutil.AddFinalizer(mr, resource.ManagedResourceFinalizer)
			update = true
		}
	} else {
		// ManagedResource is being deleted.
		if controllerutil.ContainsFinalizer(mr, resource.ManagedResourceFinalizer) {
			if len(mr.Spec.ResourceGroup) > 0 {
				if err := r.VPCMgr.RemoveResourceToNetwork(ctx, req.Name); err != nil {
					log.V(1).Info("Failed to remove managed resource", "ManagedResource", req, "Error", err)
					updateStatus = r.updateConditions(mr, resource.ManagedResourceConditionTypeRemove, err)
					return HandleReconcileReturnErr(err)
				}
			}
			// Remove finalizer.
			controllerutil.RemoveFinalizer(mr, resource.ManagedResourceFinalizer)
			update = true
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}

	if len(mr.Spec.ResourceGroup) == 0 {
		// No ResourceGroup provided, nothing to be done.
		return ctrl.Result{}, nil
	}
	rgKey := client.ObjectKey{
		Namespace: req.Namespace,
		Name:      mr.Spec.ResourceGroup,
	}
	rg := &resource.ResourceGroup{}
	if err := r.Get(ctx, rgKey, rg); err != nil {
		// ResourceGroup not yet created, nothing to be done.
		if len(mr.Status.Conditions) == 0 {
			updateStatus = r.updateConditions(mr, resource.ManagedResourceConditionTypeAdd, err)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Add to ResourceGroup
	if ResourceGroupHasBackend(rg) && metav1.GetControllerOf(mr) == nil {
		_ = ctrl.SetControllerReference(rg, mr, r.Scheme)
		update = true
		return ctrl.Result{}, nil
	}
	if err := r.VPCMgr.AddOrUpdateResourceToNetwork(ctx, req.Name); err != nil {
		if !vpc.IsAlreadyExistError(err) {
			log.V(1).Info("Failed to add resource to overlay network", "ManagedResource", req, "Err", err)
			updateStatus = r.updateConditions(mr, resource.ManagedResourceConditionTypeAdd, err)
		}
		return HandleReconcileReturnErr(err)
	}

	// Get ManagedResource from the backend.
	properties, err := r.VPCMgr.GetResourceProperties(ctx, req.Name)
	if err != nil {
		updateStatus = r.updateConditions(mr, resource.ManagedResourceConditionTypeAdd, err)
		return HandleReconcileReturnErr(err)
	}
	if !reflect.DeepEqual(properties.HostAccessIPs, mr.Status.HostAccessIPs) ||
		!reflect.DeepEqual(properties.FabricReference, mr.Status.NetworkFabricReference) ||
		(properties.NetworkPolicyProperties != nil &&
			!reflect.DeepEqual(properties.NetworkPolicyProperties.Applied, mr.Status.NetworkPolicies)) {
		// Update status from backend.
		mr.Status.HostAccessIPs = properties.HostAccessIPs
		mr.Status.NetworkFabricReference = properties.FabricReference
		if properties.NetworkPolicyProperties != nil {
			mr.Status.NetworkPolicies = properties.NetworkPolicyProperties.Applied
		}
		updateStatus = true
	}
	updateStatus = r.updateConditions(mr, resource.ManagedResourceConditionTypeAdd, nil)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ManagedResourceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &resource.ManagedResource{}, controllers2.ManagedResourceByGroup,
		func(rawObj client.Object) []string {
			mr := rawObj.(*resource.ManagedResource)
			if len(mr.Spec.ResourceGroup) == 0 {
				return nil
			}
			return []string{mr.Spec.ResourceGroup}
		}); err != nil {
		return err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &resource.ManagedResource{}, controllers2.ManagedResourceByIdentifier,
		func(rawObj client.Object) []string {
			mr := rawObj.(*resource.ManagedResource)
			return []string{mr.Spec.HostInterface}
		}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&resource.ManagedResource{}).
		Complete(r)
}

func (r *ManagedResourceReconciler) updateConditions(mr *resource.ManagedResource,
	condType resource.ManagedResourceConditionType, err error) bool {
	return UpdateManagedResourceConditions(mr, condType, err)
}

func (r *ManagedResourceReconciler) Start(ctx context.Context) error {
	log := logf.Log.WithName("ManagedResourceReconciler event handler")
	log.Info("Starting")
	req := ctrl.Request{}
	for {
		select {
		case <-ctx.Done():
			log.V(1).Info("Reconciler stopped")
			return nil
		case req.NamespacedName = <-r.VPCMgr.GetEvent(resource.ManagedResourceName):
			log.V(1).Info("Backend event detected", "ManagedResource", req)
			if _, err := r.Reconcile(ctx, req); err != nil {
				// r.VPCMgr.AddEvent(resource.ManagedResourceName, req.NamespacedName)
			}
		}
	}
}

// UpdateManagedResourceConditions updates ManagedResource.Status.Conditions.
// And returns true if update occurs.
func UpdateManagedResourceConditions(mr *resource.ManagedResource,
	condType resource.ManagedResourceConditionType, err error) bool {
	clen := len(mr.Status.Conditions)
	if clen == 0 || mr.Status.Conditions[clen-1].Type != condType {
		mr.Status.Conditions = append(mr.Status.Conditions, resource.ManagedResourceCondition{})
		clen++
	}
	status := corev1.ConditionTrue
	msg := ""
	if err != nil {
		status = corev1.ConditionFalse
		msg = err.Error()
	}
	cond := &mr.Status.Conditions[clen-1]
	if cond.Status == status && cond.Type == condType && cond.Message == msg {
		return false
	}
	mr.Status.Conditions[clen-1] = resource.ManagedResourceCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Message:            msg,
	}
	return true
}
