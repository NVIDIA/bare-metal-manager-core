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

package resource

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	resourcev1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
)

// NetworkPolicyReconciler reconciles a NetworkPolicy object
type NetworkPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	VPCMgr vpc.VPCManager
}

//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=networkpolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=networkpolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the NetworkPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *NetworkPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, err error) {

	log := logf.FromContext(ctx)
	log.V(1).Info("Received update")

	np := &resourcev1alpha1.NetworkPolicy{}
	if err := r.Get(ctx, req.NamespacedName, np); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	update := false
	updateStatus := false

	defer func() {
		if update {
			if err = r.Update(ctx, np); err != nil {
				log.Error(err, "Failed to update NetworkPolicy", "Name", req)
			}
		}
		if updateStatus {
			if err = r.Status().Update(ctx, np); err != nil {
				log.V(1).Info("Failed to update NetworkPolicy status", "Name", req, "Err", err)
			}
		}
	}()

	if np.ObjectMeta.DeletionTimestamp.IsZero() {
		// Register finalizer.
		if !controllerutil.ContainsFinalizer(np, resourcev1alpha1.NetworkPolicyFinalizer) {
			controllerutil.AddFinalizer(np, resourcev1alpha1.NetworkPolicyFinalizer)
			update = true
		}
	} else {
		// NetworkPolicy is being deleted.
		if controllerutil.ContainsFinalizer(np, resourcev1alpha1.NetworkPolicyFinalizer) {
			if err = r.VPCMgr.DeleteNetworkPolicy(ctx, req.Name); err != nil {
				log.V(1).Info("Failed to remove network policy", "NetworkPolicy", req, "Error", err)
				updateStatus = r.updateStatus(np, resourcev1alpha1.NetworkPolicyConditionTypeDestroy, 0, err)
				return HandleReconcileReturnErr(err)
			}
			controllerutil.RemoveFinalizer(np, resourcev1alpha1.NetworkPolicyFinalizer)
			update = true
		}
		return ctrl.Result{}, nil
	}

	if err = r.VPCMgr.CreateOrUpdateNetworkPolicy(ctx, req.Name); err != nil {
		if !vpc.IsAlreadyExistError(err) {
			log.V(1).Info("Failed to create or update NetworkPolicy", "Name", req, "Err", err)
			updateStatus = r.updateStatus(np, resourcev1alpha1.NetworkPolicyConditionTypeCreate, 0, err)
		}
		return HandleReconcileReturnErr(err)
	}
	// Get ManagedResource from the backend.
	properties, err := r.VPCMgr.GetNetworkPolicyProperties(ctx, req.Name)
	if err != nil {
		updateStatus = r.updateStatus(np, resourcev1alpha1.NetworkPolicyConditionTypeCreate, 0, err)
		return HandleReconcileReturnErr(err)
	}
	updateStatus = r.updateStatus(np, resourcev1alpha1.NetworkPolicyConditionTypeCreate, int32(properties.ID), nil)
	return ctrl.Result{}, nil
}

func (r *NetworkPolicyReconciler) updateStatus(np *resourcev1alpha1.NetworkPolicy,
	condType resourcev1alpha1.NetworkPolicyConditionType, policyID int32, err error) bool {
	clen := len(np.Status.Conditions)
	if clen == 0 || np.Status.Conditions[clen-1].Type != condType {
		np.Status.Conditions = append(np.Status.Conditions, resourcev1alpha1.NetworkPolicyCondition{})
		clen++
	}
	status := corev1.ConditionTrue
	msg := ""
	if err != nil {
		status = corev1.ConditionFalse
		msg = err.Error()
	}
	cond := &np.Status.Conditions[clen-1]
	if cond.Status == status && cond.Type == condType && cond.Message == msg && np.Status.ID == policyID {
		return false
	}
	if policyID > 0 {
		np.Status.ID = policyID
	}
	*cond = resourcev1alpha1.NetworkPolicyCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Message:            msg,
	}
	return true
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&resourcev1alpha1.NetworkPolicy{}).
		Complete(r)
}

func (r *NetworkPolicyReconciler) Start(ctx context.Context) error {
	log := logf.Log.WithName("NetworkPolicyReconciler")
	req := ctrl.Request{}
	for {
		select {
		case <-ctx.Done():
			log.V(1).Info("Reconciler stopped")
			return nil
		case req.NamespacedName = <-r.VPCMgr.GetEvent(resourcev1alpha1.NetworkPolicyName):
			if _, err := r.Reconcile(ctx, req); err != nil {
				log.V(1).Info("Backend event error detected", "NetworkPolicy", req, "Error", err)
			}
		}
	}
}
