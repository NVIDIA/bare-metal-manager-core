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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
)

// ResourceGroupReconciler reconciles a ResourceGroup object
type ResourceGroupReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	VPCMgr vpc.VPCManager
}

//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=resourcegroups,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=resourcegroups/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=resource.vpc.forge.gitlab-master.nvidia.com,resources=resourcegroups/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ResourceGroup object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ResourceGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, fErr error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Received update")

	rg := &resource.ResourceGroup{}
	if err := r.Get(ctx, req.NamespacedName, rg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	updateStatus := false
	update := false

	mrList := &resource.ManagedResourceList{}
	if err := r.List(ctx, mrList,
		client.InNamespace(req.Namespace),
		client.MatchingFields{controllers.ManagedResourceByGroup: req.Name}); err != nil {
		log.Error(err, "Failed to list ManagedResources in ResourceGroup", "ResourceGroup", req)
		return ctrl.Result{}, err
	}

	defer func() {
		// Update rg if needed before exiting.
		if update {
			if err := r.Update(ctx, rg); err != nil {
				log.Error(err, "Failed to update ResourceGroup", "ResourceGroup", req)
				if fErr == nil {
					fErr = err
				}
			}
		}
		if updateStatus {
			if err := r.Status().Update(ctx, rg); err != nil {
				log.V(1).Info("Failed to update ResourceGroup.Status", "ResourceGroup", req, "Err", err)
				if fErr == nil {
					fErr = err
				}
			}
		}

		// update ManagedResources ownership before exiting.
		if ResourceGroupHasBackend(rg) {
			for _, mr := range mrList.Items {
				// Assuming single owner
				if metav1.GetControllerOf(&mr) != nil {
					continue
				}
				_ = ctrl.SetControllerReference(rg, &mr, r.Scheme)
				if err := r.Update(ctx, &mr); err != nil {
					log.V(1).Info("Failed to update ManagedResource owner", "ManagedResource", mr, "Error", err)
					if fErr == nil {
						fErr = err
						return
					}
				}
			}
		}
		fErr = vpc.IgnoreNetworkDeviceNotAvailableError(fErr)
	}()

	if uint64(len(mrList.Items)) != rg.Status.ManagedResourceCount {
		rg.Status.ManagedResourceCount = uint64(len(mrList.Items))
		updateStatus = true
	}

	if rg.ObjectMeta.DeletionTimestamp.IsZero() {
		// Register finalizer.
		if !controllerutil.ContainsFinalizer(rg, resource.ResourceGroupFinalizer) {
			controllerutil.AddFinalizer(rg, resource.ResourceGroupFinalizer)
			update = true
		}
	} else {
		// ResourceGroup is being deleted.
		if controllerutil.ContainsFinalizer(rg, resource.ResourceGroupFinalizer) {
			ownerCnt := 0
			// Delete any ManagedResources in this ResourceGroup.
			for _, mr := range mrList.Items {
				mrOwner := metav1.GetControllerOf(&mr)
				if mrOwner != nil && mrOwner.Name == rg.Name {
					ownerCnt++
				}
				if !mr.ObjectMeta.DeletionTimestamp.IsZero() {
					continue
				}
				if err := r.Delete(ctx, &mr); err != nil {
					updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeDestroy, err)
					return ctrl.Result{}, err
				}
			}
			if ownerCnt > 0 {
				updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeDestroy, nil)
			} else { // Delete backend overlay network after all ManagedResources are removed.
				if err := r.VPCMgr.DeleteOverlayNetwork(ctx, req.Name); err != nil {
					log.V(1).Info("Failed to remove overlay network", "ResourceGroup", req, "Error", err)
					updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeDestroy, err)
					return HandleReconcileReturnErr(err)
				}
				// Remove finalizer.
				controllerutil.RemoveFinalizer(rg, resource.ResourceGroupFinalizer)
				update = true
				updateStatus = false
				return ctrl.Result{}, nil
			}
		}
		return ctrl.Result{}, nil
	}

	// Create or update.
	if err := r.VPCMgr.CreateOrUpdateOverlayNetwork(ctx, req.Name); err != nil {
		if !vpc.IsAlreadyExistError(err) {
			log.V(1).Info("Failed to create overlay network", "ResourceGroup", req, "Error", err)
			updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeCreate, err)
		}
		return HandleReconcileReturnErr(err)
	}
	properties, err := r.VPCMgr.GetOverlayNetworkProperties(ctx, req.Name)
	if err != nil {
		log.V(1).Info("Failed to retrieve overlay network", "ResourceGroup", req, "Error", err)
		updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeCreate, err)
		return HandleReconcileReturnErr(err)
	}
	rg.Status.FabricNetworkConfiguration = properties.FabricConfig
	rg.Status.SoftwareNetworkConfiguration = properties.SwConfig
	rg.Status.Network = properties.Network
	rg.Status.DHCPCircID = properties.DHCPCircID
	updateStatus = r.updateConditions(rg, resource.ResourceGroupConditionTypeCreate, nil)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ResourceGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&resource.ResourceGroup{}).
		Owns(&resource.ManagedResource{}).
		Complete(r)
}

func (r *ResourceGroupReconciler) updateConditions(rg *resource.ResourceGroup,
	condType resource.ResourceGroupConditionType, err error) bool {
	return UpdateResourceGroupConditions(rg, condType, err)
}

func (r *ResourceGroupReconciler) Start(ctx context.Context) error {
	log := logf.Log.WithName("ResourceGroupReconciler")
	req := ctrl.Request{}
	for {
		select {
		case <-ctx.Done():
			log.V(1).Info("Reconciler stopped")
			return nil
		case req.NamespacedName = <-r.VPCMgr.GetEvent(resource.ResourceGroupName):
			log.V(1).Info("Backend event detected", "ResourceGroup", req)
			if _, err := r.Reconcile(ctx, req); err != nil {
				r.VPCMgr.AddEvent(resource.ResourceGroupName, req.NamespacedName)
			}
		}
	}
}

// UpdateResourceGroupConditions updates ResourceGroup.Status.Conditions.
// It returns true if condition needs to be updated.
func UpdateResourceGroupConditions(rg *resource.ResourceGroup,
	condType resource.ResourceGroupConditionType, err error) bool {
	clen := len(rg.Status.Conditions)
	if clen == 0 || rg.Status.Conditions[clen-1].Type != condType {
		rg.Status.Conditions = append(rg.Status.Conditions, resource.ResourceGroupCondition{})
		clen++
	}
	status := corev1.ConditionTrue
	msg := ""
	if err != nil {
		status = corev1.ConditionFalse
		msg = err.Error()
	}
	cond := &rg.Status.Conditions[clen-1]
	if cond.Status == status && cond.Type == condType && cond.Message == msg {
		return false
	}
	*cond = resource.ResourceGroupCondition{
		Type:               condType,
		Status:             status,
		LastTransitionTime: metav1.Time{Time: time.Now()},
		Message:            msg,
	}
	return true
}

// ResourceGroupHasBackend returns true if the ResourceGroup has backend configuration.
func ResourceGroupHasBackend(rg *resource.ResourceGroup) bool {
	return rg.Status.SoftwareNetworkConfiguration != nil || rg.Status.FabricNetworkConfiguration != nil
}

func HandleReconcileReturnErr(err error) (ctrl.Result, error) {
	if err == nil {
		return ctrl.Result{}, nil
	}
	nextPoll, err := vpc.GetErrorNextPollAfter(err)
	if nextPoll == nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: *nextPoll}, err
}
