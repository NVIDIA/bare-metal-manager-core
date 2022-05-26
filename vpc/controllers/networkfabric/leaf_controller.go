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

package networkfabric

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

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers/resource"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
)

// LeafReconciler reconciles a Leaf object
type LeafReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	VPCMgr vpc.VPCManager
}

//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=leafs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=leafs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=leafs/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Leaf object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *LeafReconciler) Reconcile(ctx context.Context, req ctrl.Request) (_ ctrl.Result, fErr error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Received update")
	leaf := &networkfabric.Leaf{}
	if err := r.Get(ctx, req.NamespacedName, leaf); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	update := false
	updateStatus := false
	defer func() {
		if update {
			if err := r.Update(ctx, leaf); err != nil {
				log.Error(err, "Failed to update Leaf", "Leaf", req)
				if fErr == nil {
					fErr = err
				}
			}
		}
		if updateStatus {
			if err := r.Status().Update(ctx, leaf); err != nil {
				log.V(1).Info("Failed to update Leaf.Status", "Leaf", req, "Err", err)
				if fErr == nil {
					fErr = err
				}
			}
		}
	}()
	if leaf.ObjectMeta.DeletionTimestamp.IsZero() {
		// Register finalizer.
		if !controllerutil.ContainsFinalizer(leaf, networkfabric.LeafFinalizer) {
			controllerutil.AddFinalizer(leaf, networkfabric.LeafFinalizer)
			update = true
		}
	} else {
		// Leaf is being deleted.
		if controllerutil.ContainsFinalizer(leaf, networkfabric.LeafFinalizer) {
			if err := r.VPCMgr.RemoveNetworkDevice(ctx, reflect.TypeOf(leaf).Elem().Name(), req.Name); err != nil {
				log.V(1).Info("Failed to remove network device ", "Leaf", req, "Error", err)
				updateStatus = updateNetworkDeviceStatus(leaf, nil, err)
				return resource.HandleReconcileReturnErr(err)
			}
			controllerutil.RemoveFinalizer(leaf, networkfabric.LeafFinalizer)
			update = true
		}
		return ctrl.Result{}, nil
	}

	if err := r.VPCMgr.CreateOrUpdateNetworkDevice(ctx, networkfabric.LeafName, req.Name); err != nil {
		if !vpc.IsAlreadyExistError(err) {
			log.V(1).Info("Failed to add network device", "Device", req, "Error", err)
			updateStatus = updateNetworkDeviceStatus(leaf, nil, err)
		}
		return resource.HandleReconcileReturnErr(err)
	}
	properties, err := r.VPCMgr.GetNetworkDeviceProperties(ctx, networkfabric.LeafName, req.Name)
	updateStatus = updateNetworkDeviceStatus(leaf, properties, err)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *LeafReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkfabric.Leaf{}).
		Complete(r)
}

func (r *LeafReconciler) Start(ctx context.Context) error {
	log := logf.Log.WithName("LeafReconciler")
	req := ctrl.Request{}
	for {
		select {
		case <-ctx.Done():
			log.V(1).Info("Reconciler stopped")
			return nil
		case req.NamespacedName = <-r.VPCMgr.GetEvent(networkfabric.LeafName):
			log.V(1).Info("Backend event detected", "Leaf", req)
			if _, err := r.Reconcile(ctx, req); err != nil {
				r.VPCMgr.AddEvent(networkfabric.LeafName, req.NamespacedName)
			}
		}
	}
}

func needUpdateStatus(properties *properties.NetworkDeviceProperties, status *networkfabric.LeafStatus) bool {
	if properties == nil {
		return status.ASN > 0 || len(status.LoopbackIP) > 0 && len(status.HostAdminIPs) > 0 ||
			len(status.HostAdminDHCPServer) > 0
	}
	return properties.ASN != status.ASN || properties.LoopbackIP != status.LoopbackIP ||
		properties.AdminDHCPServer != status.HostAdminDHCPServer ||
		!reflect.DeepEqual(properties.AdminHostIPs, status.HostAdminIPs)
}

func updateStatus(properties *properties.NetworkDeviceProperties, status *networkfabric.LeafStatus) {
	if properties == nil {
		status.ASN = 0
		status.LoopbackIP = ""
		status.HostAdminIPs = nil
		status.HostAdminDHCPServer = ""
		return
	}
	status.ASN = properties.ASN
	status.HostAdminIPs = properties.AdminHostIPs
	status.HostAdminDHCPServer = properties.AdminDHCPServer
	status.LoopbackIP = properties.LoopbackIP
}

func updateNetworkDeviceStatus(leaf *networkfabric.Leaf, properties *properties.NetworkDeviceProperties, err error) bool {
	status := corev1.ConditionFalse
	if properties != nil && properties.Alive {
		status = corev1.ConditionTrue
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	conds := leaf.Status.Conditions
	if len(conds) >= 1 && conds[0].Status == status &&
		conds[0].Type == networkfabric.NetworkDeviceConditionTypeLiveness &&
		conds[0].Message == msg && !needUpdateStatus(properties, &leaf.Status) {
		return false
	}
	leaf.Status.Conditions = []networkfabric.NetworkDeviceCondition{
		{
			Type:               networkfabric.NetworkDeviceConditionTypeLiveness,
			Status:             status,
			LastTransitionTime: metav1.Time{Time: time.Now()},
			Message:            msg,
		},
	}
	updateStatus(properties, &leaf.Status)
	return true
}
