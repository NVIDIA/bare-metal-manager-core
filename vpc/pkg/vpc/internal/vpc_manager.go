/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

type vpcManager struct {
	mutex sync.Mutex
	client.Client
	overlayNetworks        map[string]*TenantNetwork
	k8sNamespace           string
	log                    logr.Logger
	resourceMgr            *resourcepool.Manager
	podController          *controllers.PodReconciler
	managedResources       *vpcManagerManagedResource
	adminResourceGroup     *FabricOverlayNetworkImplementation
	eventQueue             *vpcManagerEventQueue
	networkDevices         *vpcManagerDevice
	networkDeviceTransport map[string]func(string, string, string, string, string) (NetworkDeviceTransport, error)
	networkPolicyMgr       *NetworkPolicyManager
}

func NewManager(cl client.Client, podController *controllers.PodReconciler, crdNS string,
	resourceMgr *resourcepool.Manager) *vpcManager {
	networkDeviceRateLimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(NetworkDeviceRetryBaseDelay, NetworkDeviceRetryMaxDelay),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(NetworkDeviceQueueLeakyRate),
			NetworkDeviceQueueBucketSize)},
	)
	eventQueue := &vpcManagerEventQueue{
		eventChans: make(map[string]chan client.ObjectKey),
		eventQueue: workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		log:        logf.Log.WithName("VPCManager:EventQueue"),
	}
	networkDevices := cache.NewIndexer(
		func(obj interface{}) (string, error) {
			device := obj.(NetworkDevice)
			return device.Key(), nil
		},
		cache.Indexers{
			networkDeviceByConnectedNICs: func(obj interface{}) ([]string, error) {
				device := obj.(NetworkDevice)
				return device.GetNICIdentifiers(), nil
			},
		})
	managedResources := &vpcManagerManagedResource{
		indexer: cache.NewIndexer(
			func(obj interface{}) (string, error) {
				r := obj.(*managedResourceRuntime)
				return r.Key, nil
			},
			cache.Indexers{
				managedResourceRuntimeByIdentifier: func(obj interface{}) ([]string, error) {
					r := obj.(*managedResourceRuntime)
					return []string{r.Identifier}, nil
				},
			}),
		log:          logf.Log.WithName("VPCManage:ManagedResourceRuntime"),
		eventQueue:   eventQueue,
		resourceMgr:  resourceMgr,
		k8sNamespace: crdNS,
	}
	mgr := &vpcManager{
		Client:          cl,
		overlayNetworks: make(map[string]*TenantNetwork),
		k8sNamespace:    crdNS,
		podController:   podController,
		eventQueue:      eventQueue,
		networkDevices: &vpcManagerDevice{
			queue:            workqueue.NewRateLimitingQueue(networkDeviceRateLimiter),
			log:              logf.Log.WithName("VPCManager:NetworkDevice"),
			eventQueue:       eventQueue,
			managedResources: managedResources,
			k8sNamespace:     crdNS,
			Indexer:          networkDevices,
		},
		log:         logf.Log.WithName("VPCManager"),
		resourceMgr: resourceMgr,
		networkDeviceTransport: map[string]func(string, string, string, string, string) (NetworkDeviceTransport, error){
			networkfabric.LeafName: NewCumulusTransport,
		},
		managedResources: managedResources,
	}

	if EnableNetworkPolicy {
		var err error
		if mgr.networkPolicyMgr, err = newNetworkPolicyManager(mgr.networkDevices, mgr.resourceMgr, mgr.eventQueue, crdNS); err != nil {
			logf.Log.WithName("VPCManage").Error(err, "Failed to create NetworkPolicyMgr")
			return nil
		}
	}
	return mgr
}

func getInternalNetworkDeviceName(kind, name string) string {
	return kind + ":" + name
}

func getNetworkDeviceK8sKindName(s string) (string, string) {
	ss := strings.Split(s, ":")
	return ss[0], ss[1]
}

func (m *vpcManager) Start(ctx context.Context) error {
	m.log.Info("Starting")
	var wg sync.WaitGroup
	for i := 0; i < EventWorkerNum; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.eventQueue.RunWorker()
		}()
	}
	for i := 0; i < NetworkDeviceWorkerNum; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.networkDevices.RunWorker()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.networkPolicyMgr.Start(ctx)
	}()
	<-ctx.Done()
	for _, n := range m.overlayNetworks {
		n.Stop <- struct{}{}
	}
	m.eventQueue.eventQueue.ShutDown()
	m.networkDevices.queue.ShutDown()
	wg.Wait()
	m.log.Info("Exits")
	return nil
}

// SetNetworkDeviceTransport sets transport creator for network devices.
func (m *vpcManager) SetNetworkDeviceTransport(transport map[string]func(string, string, string, string, string) (NetworkDeviceTransport, error)) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.networkDeviceTransport = transport
}

// CreateOrUpdateOverlayNetwork creates or update overlay network for a ResourceGroup.
func (m *vpcManager) CreateOrUpdateOverlayNetwork(ctx context.Context, resourceGroup string) error {
	m.log.V(1).Info("CreateOrUpdateOverlayNetwork", "ResourceGroup", resourceGroup)
	rg := &resource.ResourceGroup{}
	rgKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      resourceGroup,
	}
	var err error
	if err = m.Get(ctx, rgKey, rg); err != nil {
		return err
	}
	var t *TenantNetwork
	var req *NetworkRequest
	notifyMRs := false
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		req = (&NetworkRequest{}).Populate(rg)
		t = m.getNetwork(resourceGroup)
		if t == nil {
			if err = m.checkResourceGroupPrerequisites(rg); err != nil {
				return
			}
			stop := make(chan struct{})
			if rg.Spec.NetworkImplementationType == resource.OverlayNetworkImplementationTypeSoftware {
				impl := NewOvnNetwork(m, resourceGroup)
				t = NewTenantNetwork(impl, stop)
			} else {
				impl := NewFabricNetwork(m, resourceGroup)
				if rg.Name == resource.WellKnownAdminResourceGroup {
					m.adminResourceGroup = impl.(*FabricOverlayNetworkImplementation)
				}
				t = NewTenantNetwork(impl, stop)
			}
			m.setNetwork(t, resourceGroup)
			go t.Run(resourceGroup)
			notifyMRs = IsResourceGroupReady(rg)
		}
	}()
	if err != nil {
		return err
	}
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return nil, t.CreateOrUpdateNetwork(req)
		},
	}
	if _, err = m.waitTenantWorkComplete(ctx, t, item); err != nil {
		return err
	}
	if notifyMRs {
		m.managedResources.NotifyResourceGroupChange(rgKey, m.Client, ctx)
	}
	return err
}

// GetOverlayNetworkProperties retrieves properties of an overlay network from the backend.
func (m *vpcManager) GetOverlayNetworkProperties(ctx context.Context, resourceGroup string) (*properties.OverlayNetworkProperties, error) {
	m.log.V(1).Info("GetOverlayNetworkProperties", "ResourceGroup", resourceGroup)
	var out *properties.OverlayNetworkProperties
	var err error
	var t *TenantNetwork
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		t = m.getNetwork(resourceGroup)
		if t == nil {
			out = nil
			err = NewUnknownResourceGroupError(resourceGroup)
		}

	}()
	if out != nil || err != nil {
		return out, err
	}
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return t.GetNetworkProperties()
		},
	}
	raw, err := m.waitTenantWorkComplete(ctx, t, item)
	out, _ = raw.(*properties.OverlayNetworkProperties)
	return out, err
}

// DeleteOverlayNetwork deletes an overlay network when responding ResourceGroup is deleted.
func (m *vpcManager) DeleteOverlayNetwork(ctx context.Context, resourceGroup string) error {
	m.log.V(1).Info("DeleteOverlayNetwork", "resourceGroup", resourceGroup)
	var t *TenantNetwork
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		t = m.getNetwork(resourceGroup)
	}()
	if t == nil {
		m.log.Info("ResourceGroup to delete does not exist", "ResourceGroup", resourceGroup)
		return nil
	}
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return nil, t.DeleteNetwork()
		},
	}
	_, err := m.waitTenantWorkComplete(ctx, t, item)
	if err != nil {
		return err
	}
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.setNetwork(nil, resourceGroup)
		if resourceGroup == resource.WellKnownAdminResourceGroup {
			m.adminResourceGroup = nil
		}

	}()
	return nil
}

// AddOrUpdateResourceToNetwork adds or updates a ManagedResource on an overlay network.
func (m *vpcManager) AddOrUpdateResourceToNetwork(ctx context.Context, managedResource string) error {
	m.log.V(1).Info("AddOrUpdateResourceToNetwork", "managedResource", managedResource)
	var err error
	mrKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      managedResource,
	}
	mr := &resource.ManagedResource{}
	if err = m.Get(ctx, mrKey, mr); err != nil {
		return nil
	}
	rgKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      mr.Spec.ResourceGroup,
	}
	rg := &resource.ResourceGroup{}
	if err = m.Get(ctx, rgKey, rg); err != nil {
		return err
	}
	var t *TenantNetwork
	var req *PortRequest
	doreconcile := false
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		var rt *managedResourceRuntime
		t = m.getNetwork(mr.Spec.ResourceGroup)
		if t == nil {
			return
		}
		req = (&PortRequest{}).Populate(mr, rg)
		rt, err = m.managedResources.CreateOrUpdate(req, t.OverlayNetworkImplementation, mr)
		if rt != nil {
			doreconcile = rt.DoReconcile
		}
	}()
	if err != nil {
		return err
	}
	// Network may not have been created.
	if t == nil {
		if IsManagedResourceReady(mr) {
			return NewAlreadyExistError(resource.ManagedResourceName, managedResource)
		}
		return NewUnknownResourceGroupError(rg.Name)
	}
	// Notify changes to networkPolicy
	npResource := (&NetworkPolicyResource{}).Populate(mr)
	npErr := m.networkPolicyMgr.AddOrUpdateNetworkPolicyResource(npResource)
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return nil, t.AddOrUpdateResourceToNetwork(req, doreconcile)
		},
	}
	_, err = m.waitTenantWorkComplete(ctx, t, item)
	if doreconcile {
		if _, ok := err.(*NetworkDeviceNotAvailableError); ok {
			return NewAlreadyExistError(resource.ManagedResourceName, managedResource)
		}
		_ = m.managedResources.Update(req.name, func(stored *managedResourceRuntime) *managedResourceRuntime {
			stored.DoReconcile = false
			return stored
		})
	}
	return utils.CombineErrors(npErr, err)
}

// GetResourceProperties retrieves properties of a ManagedResource from the backend.
func (m *vpcManager) GetResourceProperties(ctx context.Context, managedResource string) (*properties.ResourceProperties, error) {
	m.log.V(1).Info("GetResourceProperties", "ManagedResource", managedResource)
	var err error
	mrKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      managedResource,
	}
	mr := &resource.ManagedResource{}
	if err = m.Get(ctx, mrKey, mr); err != nil {
		return nil, err
	}
	var t *TenantNetwork
	var req *PortRequest
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		t = m.getNetwork(mr.Spec.ResourceGroup)
		if t == nil {
			err = NewUnknownResourceGroupError(mr.Spec.ResourceGroup)
			return
		}
		req = (&PortRequest{}).Populate(mr, nil)

	}()
	if err != nil {
		return nil, err
	}
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return t.GetResourceProperties(req)
		},
	}
	raw, err := m.waitTenantWorkComplete(ctx, t, item)
	out, _ := raw.(*properties.ResourceProperties)
	// Get NetworkPolicy properties
	npProperty, npErr := m.networkPolicyMgr.GetNetworkPolicyResourceProperty(mr.Name, resource.ManagedResourceName)
	if npProperty != nil {
		out.NetworkPolicyProperties = npProperty
	}
	return out, utils.CombineErrors(err, npErr)
}

// RemoveResourceToNetwork removes a ManagedResource from an overlay network.
func (m *vpcManager) RemoveResourceToNetwork(ctx context.Context, managedResource string) error {
	m.log.V(1).Info("RemoveResourceToNetwork", "ManagedResource", managedResource)
	var err error
	mrKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      managedResource,
	}
	mr := &resource.ManagedResource{}
	if err = m.Get(ctx, mrKey, mr); err != nil {
		return client.IgnoreNotFound(err)
	}
	var t *TenantNetwork
	var req *PortRequest
	func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		t = m.getNetwork(mr.Spec.ResourceGroup)
		if t == nil {
			return
		}
		req = (&PortRequest{}).Populate(mr, nil)

	}()
	if t == nil {
		return nil
	}
	// Notify changes to networkPolicy
	npResource := (&NetworkPolicyResource{}).Populate(mr)
	npErr := m.networkPolicyMgr.DeleteNetworkPolicyResource(npResource)
	item := &WorkItem{
		Call: func() (interface{}, error) {
			return nil, t.DeleteResourceFromNetwork(req)
		},
	}
	if _, err = m.waitTenantWorkComplete(ctx, t, item); err != nil {
		return utils.CombineErrors(err, npErr)
	}
	_ = m.managedResources.Delete(mrKey.String())
	return utils.CombineErrors(err, npErr)
}

// CreateOrUpdateNetworkDevice updates a network device and optionally probe the device,
func (m *vpcManager) CreateOrUpdateNetworkDevice(ctx context.Context, kind, name string) error {
	m.log.V(1).Info("CreateOrUpdateNetworkDevice", "Kind", kind, "Name", name)
	var device NetworkDevice
	if kind != networkfabric.LeafName {
		return NewNetworkDeviceNotAvailableError(kind, "")
	}
	leaf := &networkfabric.Leaf{}
	oKey := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      name,
	}
	if err := m.Get(ctx, oKey, leaf); err != nil {
		return err
	}
	key := getInternalNetworkDeviceName(kind, name)
	d, ok, _ := m.networkDevices.GetByKey(key)
	var doReconcile bool
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if ok {
		device = d.(NetworkDevice)
		device.SetMaintenanceMode(leaf.Spec.Control.MaintenanceMode)
		device.SetMgmtIP(leaf.Spec.Control.ManagementIP)
		device.SetNICIdentifiers(leaf.Spec.HostInterfaces)
		device.SetHostAdminIPs(leaf.Spec.HostAdminIPs, false)
	} else {
		if err := m.checkLeafPrerequisites(leaf); err != nil {
			return err
		}
		user, pwd, sshUser, sshPwd, err := m.getCredential(kind, name)
		if err != nil {
			return err
		}
		trans, err := m.networkDeviceTransport[kind](
			leaf.Spec.Control.ManagementIP, user, pwd, sshUser, sshPwd)
		if err != nil {
			return err
		}
		device, err = NewCumulus(m, key,
			leaf.Spec.Control.MaintenanceMode, leaf.Spec.HostInterfaces,
			leaf.Status.ASN, leaf.Status.LoopbackIP, trans)
		if err != nil {
			return err
		}
		doReconcile = IsNetworkDeviceAlive(leaf)
		device.SetHostAdminIPs(leaf.Spec.HostAdminIPs, doReconcile)
		go device.Liveness(doReconcile)
	}
	if err := m.networkDevices.Update(device); err != nil {
		return err
	}
	// Notify changes to networkPolicy
	npResource := (&NetworkPolicyResource{}).Populate(leaf)
	npErr := m.networkPolicyMgr.AddOrUpdateNetworkPolicyResource(npResource)
	if doReconcile {
		return NewAlreadyExistError(kind, name)
	}
	return npErr
}

func (m *vpcManager) GetNetworkDeviceProperties(_ context.Context, kind, name string) (*properties.NetworkDeviceProperties, error) {
	m.log.V(1).Info("GetNetworkDeviceProperties", "Kind", kind, "Name", name)
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := getInternalNetworkDeviceName(kind, name)
	d, ok, _ := m.networkDevices.GetByKey(key)
	if !ok {
		return nil, NewNetworkDeviceNotAvailableError(kind, name)
	}
	out, err := d.(NetworkDevice).GetProperties()
	// Get NetworkPolicy properties
	npProperty, npErr := m.networkPolicyMgr.GetNetworkPolicyResourceProperty(name, kind)
	if npProperty != nil {
		out.NetworkPolicyProperties = npProperty
	}
	return out, utils.CombineErrors(err, npErr)
}

// RemoveNetworkDevice removes a network device.
func (m *vpcManager) RemoveNetworkDevice(ctx context.Context, kind, name string) error {
	m.log.V(1).Info("RemoveNetworkDevice", "Kind", kind, "Name", name)
	maintenanceMode := false
	switch kind {
	case networkfabric.LeafName:
		leaf := &networkfabric.Leaf{}
		key := client.ObjectKey{
			Namespace: m.k8sNamespace,
			Name:      name,
		}
		if err := m.Get(ctx, key, leaf); err != nil {
			return err
		}
		maintenanceMode = leaf.Spec.Control.MaintenanceMode
	default:
		return fmt.Errorf("unknown device type: %v", kind)
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := getInternalNetworkDeviceName(kind, name)
	dev, exists, err := m.networkDevices.GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		m.log.V(1).Info("Device not known to the backend", "Device", key)
		return nil
	}
	dev.(NetworkDevice).SetMaintenanceMode(maintenanceMode)
	if err := dev.(NetworkDevice).Unmanage(); err != nil {
		return err
	}
	if err = m.networkDevices.Delete(dev); err != nil {
		return err
	}
	m.networkDevices.Remove(dev.(NetworkDevice))
	m.managedResources.NotifyNetworkDeviceChange(dev.(NetworkDevice).GetNICIdentifiers())
	// Notify changes to networkPolicy
	npResource := &NetworkPolicyResource{
		Kind: kind,
		Name: name,
	}
	return m.networkPolicyMgr.DeleteNetworkPolicyResource(npResource)
}

func (m *vpcManager) CreateOrUpdateNetworkPolicy(ctx context.Context, name string) error {
	np := &resource.NetworkPolicy{}
	key := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      name,
	}
	if err := m.Get(ctx, key, np); err != nil {
		return err
	}
	return m.networkPolicyMgr.AddOrUpdateNetworkPolicy((&NetworkPolicy{}).Populate(np))
}

func (m *vpcManager) DeleteNetworkPolicy(ctx context.Context, name string) error {
	np := &resource.NetworkPolicy{}
	key := client.ObjectKey{
		Namespace: m.k8sNamespace,
		Name:      name,
	}
	if err := m.Get(ctx, key, np); err != nil {
		return err
	}
	return m.networkPolicyMgr.DeleteNetworkPolicy((&NetworkPolicy{}).Populate(np))
}

func (m *vpcManager) GetNetworkPolicyProperties(ctx context.Context, name string) (*properties.NetworkPolicyProperties, error) {
	return m.networkPolicyMgr.GetNetworkPolicyProperty(name)
}

func (m *vpcManager) AddEvent(kind string, obj client.ObjectKey) {
	m.eventQueue.AddEvent(kind, obj)

}

func (m *vpcManager) GetEvent(kind string) <-chan client.ObjectKey {
	return m.eventQueue.GetEvent(kind)
}

func (m *vpcManager) waitTenantWorkComplete(ctx context.Context, tenant *TenantNetwork, item *WorkItem) (interface{}, error) {
	item.Response = make(chan ItemResponse)
	tenant.WorkQueue.Add(item)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	case resp, ok := <-item.Response:
		if !ok {
			return nil, fmt.Errorf("backend internal error")
		}
		return resp.Output, resp.err
	}
}

func (m *vpcManager) getNetwork(resourceGroup string) *TenantNetwork {
	t, ok := m.overlayNetworks[resourceGroup]
	if !ok {
		return nil
	}
	return t
}

func (m *vpcManager) setNetwork(t *TenantNetwork, resourceGroup string) {
	if t == nil {
		delete(m.overlayNetworks, resourceGroup)
		return
	}
	m.overlayNetworks[resourceGroup] = t
}

func (m *vpcManager) getCredential(kind, name string) (string, string, string, string, error) {
	var usr, pwd string
	usr = os.Getenv(EnvCumulusUser)
	pwd = os.Getenv(EnvCumulusPwd)
	if len(usr) == 0 {
		return "", "", "", "", fmt.Errorf("cannot get user from env for device: %v:%v", kind, name)
	}
	if len(pwd) == 0 {
		return "", "", "", "", fmt.Errorf("cannot get pwd from env for device: %v:%v", kind, name)
	}
	return usr, pwd, os.Getenv(EnvSSHUser), os.Getenv(EnvSSHPwd), nil
}

func (m *vpcManager) checkResourceGroupPrerequisites(rg *resource.ResourceGroup) error {
	if rg.Spec.NetworkImplementationType == resource.OverlayNetworkImplementationTypeSoftware {
		return nil
	}

	if IsResourceGroupReady(rg) {
		return nil
	}

	resourcepools := []string{
		// networkfabric.OverlayIPv4ResourcePool,
		string(networkfabric.VNIResourcePool),
		string(networkfabric.VlanIDResourcePool),
	}
	if HBNConfig.HBNDevice {
		resourcepools = append(resourcepools, string(networkfabric.LoopbackIPResourcePool))
	}
	for _, name := range resourcepools {
		if ipPool := m.resourceMgr.GetIPv4Pool(name); ipPool != nil {
			continue
		}
		if intPool := m.resourceMgr.GetIntegerPool(name); intPool == nil {
			return NewMissingResourcePoolError(string(name))
		}
	}
	return nil
}

func (m *vpcManager) checkLeafPrerequisites(leaf *networkfabric.Leaf) error {
	if !HBNConfig.HBNDevice {
		return nil
	}

	if IsNetworkDeviceAlive(leaf) {
		return nil
	}

	if m.adminResourceGroup == nil {
		return NewMissingResourcePoolError(resource.WellKnownAdminResourceGroup)
	}
	return nil
}

func IsResourceGroupReady(rg *resource.ResourceGroup) bool {
	if !rg.ObjectMeta.DeletionTimestamp.IsZero() {
		return false
	}
	for _, cond := range rg.Status.Conditions {
		if cond.Type == resource.ResourceGroupConditionTypeCreate && cond.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}

func IsManagedResourceReady(mr *resource.ManagedResource) bool {
	if !mr.ObjectMeta.DeletionTimestamp.IsZero() {
		return false
	}
	for _, cond := range mr.Status.Conditions {
		if cond.Type == resource.ManagedResourceConditionTypeAdd && cond.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}

func IsNetworkDeviceAlive(leaf *networkfabric.Leaf) bool {
	if !leaf.ObjectMeta.DeletionTimestamp.IsZero() {
		return false
	}
	for _, cond := range leaf.Status.Conditions {
		if cond.Type == networkfabric.NetworkDeviceConditionTypeLiveness && cond.Status == v1.ConditionTrue {
			return true
		}
	}
	return false
}
