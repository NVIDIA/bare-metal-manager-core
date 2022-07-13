/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"context"
	"net"
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
)

type ConfigurationBackendResult struct {
	State ConfigurationBackendState
	Error error
}

type managedResourceRuntime struct {
	Key          string
	Identifier   string
	FabricIP     net.IP
	FabricIPPool *resourcepool.IPv4BlockPool
	NetworkImpl  OverlayNetworkImplementation
	DoReconcile  bool
	ConfigurationBackendResult
}

func (m *managedResourceRuntime) Copy() *managedResourceRuntime {
	return &managedResourceRuntime{
		Key:                        m.Key,
		Identifier:                 m.Identifier,
		FabricIP:                   m.FabricIP,
		FabricIPPool:               m.FabricIPPool,
		NetworkImpl:                m.NetworkImpl,
		ConfigurationBackendResult: m.ConfigurationBackendResult,
		DoReconcile:                m.DoReconcile,
	}
}

type vpcManagerManagedResource struct {
	mutex        sync.Mutex
	indexer      cache.Indexer
	log          logr.Logger
	k8sNamespace string
	eventQueue   *vpcManagerEventQueue
	resourceMgr  *resourcepool.Manager
}

// NotifyNetworkDeviceChange notifies the front end ManagedResource changes due to
// associated NetworkDevice change.
func (r *vpcManagerManagedResource) NotifyNetworkDeviceChange(hostNICs []string) {
	for _, host := range hostNICs {
		l, _ := r.indexer.ByIndex(managedResourceRuntimeByIdentifier, host)
		for _, ii := range l {
			r.NotifyChange(ii.(*managedResourceRuntime).Key)
		}
	}
}

// NotifyResourceGroupChange notifies the front end ManagedResource changes due to
// associated ResourceGroup change. It notifies only if the corresponding runtime of the
// ManagedResource has yet created.
func (r *vpcManagerManagedResource) NotifyResourceGroupChange(rg client.ObjectKey, cl client.Client, ctx context.Context) {
	mrList := &resource.ManagedResourceList{}
	if err := cl.List(ctx, mrList,
		client.InNamespace(rg.Namespace),
		client.MatchingFields{controllers.ManagedResourceByGroup: rg.Name}); err != nil {
		r.log.Error(err, "Failed to list ManagedResources in ResourceGroup", "ResourceGroup", rg)
		return
	}
	for _, mr := range mrList.Items {
		key := &client.ObjectKey{
			Namespace: mr.Namespace,
			Name:      mr.Name,
		}
		if _, ok, _ := r.indexer.GetByKey(key.String()); ok {
			continue
		}

		r.eventQueue.AddEvent(resource.ManagedResourceName, *key)
	}
}

// NotifyChange notifies the front end ManagedResource changes.
func (r *vpcManagerManagedResource) NotifyChange(key string) {
	rt := r.Get(key)
	if rt == nil {
		r.log.Info("Notify unknown managedResource", "ManagedResource", key)
		return
	}

	r.eventQueue.AddEvent(resource.ManagedResourceName, client.ObjectKey{
		Namespace: r.k8sNamespace,
		Name:      rt.Key,
	})
}

// CreateOrUpdate creates or updates a ManagedResource runtime.
func (r *vpcManagerManagedResource) CreateOrUpdate(req *PortRequest, impl OverlayNetworkImplementation,
	mr *resource.ManagedResource) (
	*managedResourceRuntime, error) {
	rt := &managedResourceRuntime{
		Identifier:  req.Identifier,
		Key:         req.name,
		NetworkImpl: impl,
	}
	if len(req.FabricIPPool) > 0 {
		rt.FabricIPPool = r.resourceMgr.GetIPv4Pool(req.FabricIPPool)
		if rt.FabricIPPool == nil {
			return nil, NewMissingResourcePoolError(req.FabricIPPool)
		}
	}
	if req.FabricIP != nil {
		rt.FabricIP = req.FabricIP
	} else if req.NeedFabricIP {
		if rt.FabricIPPool == nil {
			return nil, NewMissingResourcePoolError(req.FabricIPPool)
		}
		ip, err := rt.FabricIPPool.Get()
		if err != nil {
			return nil, NewMissingResourcePoolError(req.FabricIPPool)
		}
		rt.FabricIP = net.ParseIP(ip)
	}
	if i, ok, _ := r.indexer.GetByKey(rt.Key); ok {
		// Preserve state from backend.
		rt.State = i.(*managedResourceRuntime).State
		rt.Error = i.(*managedResourceRuntime).Error
	} else {
		// new rt.
		if IsManagedResourceReady(mr) {
			// controller restarted, reconcile with existing ManagedResources.
			rt.State = StringToManagedResourceBackendState(mr.Status.NetworkFabricReference.ConfigurationState)
			rt.DoReconcile = true
		}
	}
	return rt, r.indexer.Update(rt)
}

// Update updates an existing ManagedResource runtime.
func (r *vpcManagerManagedResource) Update(key string, updater func(_ *managedResourceRuntime) *managedResourceRuntime) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	rt := r.getLocked(key)
	if rt == nil {
		r.log.Info("Update unknown managedResource", "ManagedResource", key)
		return nil
	}
	rt = updater(rt)
	return r.indexer.Update(rt)
}

// Delete deletes ManagedResource runtime.
func (r *vpcManagerManagedResource) Delete(key string) error {
	i, ok, _ := r.indexer.GetByKey(key)
	if !ok {
		return nil
	}
	mrRt := i.(*managedResourceRuntime)
	if len(mrRt.FabricIP) > 0 && mrRt.FabricIPPool != nil {
		if err := mrRt.FabricIPPool.Release(mrRt.FabricIP.String()); err != nil {
			return err
		}
	}
	return r.indexer.Delete(i)
}

// Get returns a copy of ManagedResource runtime.
func (r *vpcManagerManagedResource) getLocked(key string) *managedResourceRuntime {
	i, ok, _ := r.indexer.GetByKey(key)
	if !ok {
		return nil
	}
	return i.(*managedResourceRuntime).Copy()
}

func (r *vpcManagerManagedResource) Get(key string) *managedResourceRuntime {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.getLocked(key)
}
