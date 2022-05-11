/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"net"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
)

type managedResourceRuntime struct {
	Key          client.ObjectKey
	Identifier   string
	FabricIP     net.IP
	FabricIPPool *resourcepool.IPv4BlockPool
	NetworkImpl  OverlayNetworkImplementation
	State        ManagedResourceBackendState
	Error        error
}

func (m *managedResourceRuntime) Copy() *managedResourceRuntime {
	return &managedResourceRuntime{
		Key:          m.Key,
		Identifier:   m.Identifier,
		FabricIP:     m.FabricIP,
		FabricIPPool: m.FabricIPPool,
		NetworkImpl:  m.NetworkImpl,
		State:        m.State,
		Error:        m.Error,
	}
}

type vpcManagerManagedResource struct {
	indexer     cache.Indexer
	log         logr.Logger
	eventQueue  *vpcManagerEventQueue
	resourceMgr *resourcepool.Manager
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

// NotifyChange notifies the front end ManagedResource changes.
func (r *vpcManagerManagedResource) NotifyChange(key client.ObjectKey) {
	rt := r.Get(key)
	if rt == nil {
		r.log.Info("Unknown managedResource", "ManagedResource", key)
		return
	}
	r.eventQueue.AddEvent(resource.ManagedResourceName, rt.Key)
}

// CreateOrUpdate creates or updates a ManagedResource runtime.
func (r *vpcManagerManagedResource) CreateOrUpdate(req *PortRequest, impl OverlayNetworkImplementation) error {
	rt := &managedResourceRuntime{
		Identifier:  req.Identifier,
		Key:         req.Key,
		NetworkImpl: impl,
	}
	if len(req.FabricIPPool) > 0 {
		rt.FabricIPPool = r.resourceMgr.GetIPv4Pool(
			networkfabric.WellKnownConfigurationResourcePool(req.FabricIPPool))
		if rt.FabricIPPool == nil {
			return NewMissingResourcePoolError(req.FabricIPPool)
		}
	}
	if req.FabricIP != nil {
		rt.FabricIP = req.FabricIP
	} else if req.NeedFabricIP {
		if rt.FabricIPPool == nil {
			return NewMissingResourcePoolError(req.FabricIPPool)
		}
		ip, err := rt.FabricIPPool.Get()
		if err != nil {
			return NewMissingResourcePoolError(req.FabricIPPool)
		}
		rt.FabricIP = net.ParseIP(ip)
	}
	if i, ok, _ := r.indexer.GetByKey(rt.Key.String()); ok {
		// Preserve state from backend.
		rt.State = i.(*managedResourceRuntime).State
		rt.Error = i.(*managedResourceRuntime).Error
	}
	return r.indexer.Update(rt)
}

// Update updates an existing ManagedResource runtime.
func (r *vpcManagerManagedResource) Update(rt *managedResourceRuntime) error {
	return r.indexer.Update(rt.Copy())
}

// Delete deletes ManagedResource runtime.
func (r *vpcManagerManagedResource) Delete(objKey client.ObjectKey) error {
	i, ok, _ := r.indexer.GetByKey(objKey.String())
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
func (r *vpcManagerManagedResource) Get(objKey client.ObjectKey) *managedResourceRuntime {
	var i interface{}
	var ok bool
	if len(objKey.Name) > 0 {
		i, ok, _ = r.indexer.GetByKey(objKey.String())
	}
	if !ok {
		return nil
	}
	return i.(*managedResourceRuntime).Copy()
}
