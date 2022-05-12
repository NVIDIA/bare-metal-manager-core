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

package networkfabric

import (
	"context"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	networkfabricv1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
)

// ConfigurationResourcePoolReconciler reconciles a ConfigurationResourcePool object
type ConfigurationResourcePoolReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	ResourceMgr *resourcepool.Manager
}

//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=configurationresourcepools,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=configurationresourcepools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=networkfabric.vpc.forge.gitlab-master.nvidia.com,resources=configurationresourcepools/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ConfigurationResourcePool object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *ConfigurationResourcePoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("Received update")
	poolName := networkfabricv1alpha1.WellKnownConfigurationResourcePool(req.Name)
	pool := &networkfabricv1alpha1.ConfigurationResourcePool{}
	if err := r.Get(ctx, req.NamespacedName, pool); err != nil {
		if errors.IsNotFound(err) {
			if err := r.ResourceMgr.Delete(poolName); err != nil {
				log.Error(err, "Delete resource pool", "Pool", poolName)
			}
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	var err error
	if pool.Spec.Type == networkfabricv1alpha1.RangeTypeIPv4 {
		var ranges [][]string
		for _, r := range pool.Spec.Ranges {
			ranges = append(ranges, []string{r.Start, r.End})
		}
		if resourcePool := r.ResourceMgr.GetIPv4Pool(poolName); resourcePool == nil {
			resourcePool = r.ResourceMgr.CreateIPv4Pool(poolName, ranges, uint(pool.Spec.AllocationBlockSize))
			if err = resourcePool.Reconcile(); err != nil {
				log.Error(err, "Failed to reconcile resource pool", "Pool", poolName)
				_ = r.ResourceMgr.Delete(poolName)
			}
		} else {
			resourcePool.Update(ranges)
		}
	} else if pool.Spec.Type == networkfabricv1alpha1.RangeTypeInteger {
		var ranges [][]uint64
		for _, r := range pool.Spec.Ranges {
			start, _ := strconv.ParseUint(r.Start, 10, 64)
			end, _ := strconv.ParseUint(r.End, 10, 64)
			ranges = append(ranges, []uint64{start, end})
		}
		if resourcePool := r.ResourceMgr.GetIntegerPool(poolName); resourcePool == nil {
			resourcePool = r.ResourceMgr.CreateIntegerPool(poolName, ranges)
			if err = resourcePool.Reconcile(); err != nil {
				log.Error(err, "Failed to reconcile resource pool", "Pool", poolName)
				_ = r.ResourceMgr.Delete(poolName)
			}
		} else {
			resourcePool.Update(ranges)
		}
	}

	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigurationResourcePoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&networkfabricv1alpha1.ConfigurationResourcePool{}).
		Complete(r)
}
