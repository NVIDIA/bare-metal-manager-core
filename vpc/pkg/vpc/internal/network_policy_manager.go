/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
)

const (
	// returns all NetworkPolicies matching Leaf selector key/value pair.
	networkPolicyByLeafSelectors = "networkPolicyByLeafSelectors"
	// returns all NetworkPolicies matching ManagedResource selector key/value pair.
	networkPolicyByManagedResourceSelectors = "networkPolicyByManagedResourceSelectors"
	// returns all NetworkPolicies matching To/From address selector key/value pair.
	networkPolicyByAddressSelectors = "networkPolicyByAddressSelectors"
	// returns all Leafs matching a key/value pair in its label.
	leafByLabels = "leafByLabels"
	// returns all Leafs that has a NetworkPolicy.
	leafByNetworkPolicies = "leafByNetworkPolicies"
	// returns all ManagedResources matching a key/value pair in its labels.
	managedResourceByLabels = "managedResourceByLabels"
	// returns all managedResources that has a NetworkPolicy.
	managedResourceByNetworkPolicies = "managedResourceByNetworkPolicies"
	//returns all NetworkPolicyBackendStates on a Leaf or ManagedResource.
	networkPolicyStateByResources = "networkPolicyStateByResources"
	//returns all NetworkPolicyBackendStates for a NetworkPolicy.
	networkPolicyStateByNetworkPolicy = "networkPolicyStateByNetworkPolicy"
)

const (
	NetworkPolicyPriorityMandatoryPermit int = iota // highest priority
	NetworkPolicyPriorityMandatoryDeny
	NetworkPolicyPriorityWhileList
	NetworkPolicyPriorityDefaultPermit
	NetworkPolicyPriorityDefaultDeny
)

var (
	// NetworkPolicyPriorityRuleIDMapDefault reflects HBN hard code 8 priority levels mapping to rule ID,
	// mostly will be allocated to NetworkPolicyPriorityWhileList.
	NetworkPolicyPriorityRuleIDMapDefault = []uint16{8000, 16000, 40000, 48000, 56000}
)

const (
	networkPolicyMaxID             = 16
	HostAdminLeafPort              = "pf0hpf"
	DefaultDenyNetworkPolicyName   = "default-deny"
	DefaultPermitNetworkPolicyName = "default-permit"
)

var (
	DefaultDenyNetworkPolicy = &NetworkPolicy{
		Name: DefaultDenyNetworkPolicyName,
		// default deny all traffic in ingress direction.
		Ingress: []NetworkPolicyAddress{{
			Ports: []NetworkPolicyPorts{
				{Protocol: ACLProtocolUDP},
				{Protocol: ACLProtocolTCP},
				{Protocol: ACLProtocolICMP},
			},
		}},
		// default deny all traffic in egress direction.
		Egress: []NetworkPolicyAddress{{
			Ports: []NetworkPolicyPorts{
				{Protocol: ACLProtocolUDP},
				{Protocol: ACLProtocolTCP},
				{Protocol: ACLProtocolICMP},
			},
		}},
		ID:        NetworkPolicyPriorityRuleIDMap[NetworkPolicyPriorityDefaultDeny-1] + 1,
		Drop:      true,
		stateless: true,
	}
	DefaultPermitNetworkPolicy = &NetworkPolicy{
		Name: DefaultPermitNetworkPolicyName,
		Egress: []NetworkPolicyAddress{
			// allow egress traffic on sessions already established.
			{
				Ports: []NetworkPolicyPorts{
					{Protocol: ACLProtocolUDP},
					{Protocol: ACLProtocolTCP},
					{Protocol: ACLProtocolICMP},
				},
				Related: true,
			},
			// allow egress bcast DHCP discovery
			{
				Addresses: []string{"255.255.255.255/32"},
				Ports: []NetworkPolicyPorts{{
					Ports:    []uint16{67},
					Protocol: ACLProtocolUDP,
				}},
			},
		},
		Ingress: []NetworkPolicyAddress{
			// allow ingress traffic on sessions already established.
			{
				Ports: []NetworkPolicyPorts{
					{Protocol: ACLProtocolUDP},
					{Protocol: ACLProtocolTCP},
					{Protocol: ACLProtocolICMP},
				},
				Related: true,
			}},
		ID:   1,
		Drop: false,
	}
)

var (
	// NetworkPolicyPriorityRuleIDMap maps RuleID into priority where index is the priority,
	// and value is the last RuleID in that priority.
	NetworkPolicyPriorityRuleIDMap = NetworkPolicyPriorityRuleIDMapDefault
	// NetworkPolicyRuleIDRange is the RuleID range allocated to each NetworkPolicy.
	NetworkPolicyRuleIDRange = uint16(1024)
	// EnableNetworkPolicy enables NetworkPolicy enforcement at backend.
	EnableNetworkPolicy = false
)

func label2String(k, v string) string {
	return k + ":" + v
}

// NetworkPolicyBackendState is the backend configuration states of NetworkPolicies.
type NetworkPolicyBackendState struct {
	// Name is Managed Resource.ObjectKey; or Leaf.ObjectKey.
	Name              string
	Kind              string
	NetworkPolicyName string
	ConfigurationBackendResult
}

func (n *NetworkPolicyBackendState) Key() string {
	return n.NetworkPolicyName + ":" + n.ResourceKey()
}

func (n *NetworkPolicyBackendState) ResourceKey() string {
	return n.Kind + ":" + n.Name
}

type NetworkPolicyManager struct {
	mutex                      sync.Mutex
	managedResources           cache.Indexer
	leafs                      cache.Indexer
	networkPolicies            cache.Indexer
	networkPolicyBackendStates cache.Indexer
	k8sNamespace               string
	networkDevices             *vpcManagerDevice
	idPool                     *resourcepool.IntegerPool
	eventQueue                 *vpcManagerEventQueue
	log                        logr.Logger
}

func newNetworkPolicyManager(deviceMgr *vpcManagerDevice, poolMgr *resourcepool.Manager,
	eventQueue *vpcManagerEventQueue, k8sNamespace string) (*NetworkPolicyManager, error) {
	idPool := poolMgr.CreateIntegerPool(resourcepool.RuntimePoolNetworkPolicyIDPool, [][]uint64{{0, networkPolicyMaxID}})
	if err := idPool.Reconcile(); err != nil {
		return nil, err
	}
	return &NetworkPolicyManager{
		managedResources: cache.NewIndexer(
			func(obj interface{}) (string, error) {
				mr := obj.(*NetworkPolicyResource)
				if mr.Kind != v1alpha1.ManagedResourceName {
					return "", nil
				}
				return mr.Key(), nil
			},
			cache.Indexers{
				managedResourceByLabels: func(obj interface{}) ([]string, error) {
					mr := obj.(*NetworkPolicyResource)
					if mr.Kind != v1alpha1.ManagedResourceName {
						return nil, nil
					}
					var ret []string
					for k, v := range mr.Labels {
						ret = append(ret, label2String(k, v))
					}
					return ret, nil
				},
				managedResourceByNetworkPolicies: func(obj interface{}) ([]string, error) {
					mr := obj.(*NetworkPolicyResource)
					if mr.Kind != v1alpha1.ManagedResourceName {
						return nil, nil
					}
					return mr.AppliedNetworkPolicies, nil
				},
			}),
		leafs: cache.NewIndexer(
			func(obj interface{}) (string, error) {
				leaf := obj.(*NetworkPolicyResource)
				if leaf.Kind != v1alpha12.LeafName {
					return "", nil
				}
				return leaf.Key(), nil
			},
			cache.Indexers{
				leafByLabels: func(obj interface{}) ([]string, error) {
					leaf := obj.(*NetworkPolicyResource)
					if leaf.Kind != v1alpha12.LeafName {
						return nil, nil
					}
					var ret []string
					for k, v := range leaf.Labels {
						ret = append(ret, label2String(k, v))
					}
					return ret, nil
				},
				leafByNetworkPolicies: func(obj interface{}) ([]string, error) {
					leaf := obj.(*NetworkPolicyResource)
					if leaf.Kind != v1alpha12.LeafName {
						return nil, nil
					}
					return leaf.AppliedNetworkPolicies, nil
				},
			}),
		networkPolicies: cache.NewIndexer(
			func(obj interface{}) (string, error) {
				np := obj.(*NetworkPolicy)
				return np.Name, nil
			},
			cache.Indexers{
				networkPolicyByLeafSelectors: func(obj interface{}) ([]string, error) {
					np := obj.(*NetworkPolicy)
					var ret []string
					for k, v := range np.LeafSelector {
						ret = append(ret, label2String(k, v))
					}
					return ret, nil
				},
				networkPolicyByManagedResourceSelectors: func(obj interface{}) ([]string, error) {
					np := obj.(*NetworkPolicy)
					var ret []string
					for k, v := range np.ManagedResourceSelector {
						ret = append(ret, label2String(k, v))
					}
					return ret, nil
				},
				networkPolicyByAddressSelectors: func(obj interface{}) ([]string, error) {
					np := obj.(*NetworkPolicy)
					var ret []string
					for _, rule := range np.Egress {
						for _, s := range rule.Selectors {
							for k, v := range s {
								ret = append(ret, label2String(k, v))
							}
						}
					}
					for _, rule := range np.Ingress {
						for _, s := range rule.Selectors {
							for k, v := range s {
								ret = append(ret, label2String(k, v))
							}
						}
					}
					return ret, nil
				},
			}),
		networkPolicyBackendStates: cache.NewIndexer(
			func(obj interface{}) (string, error) {
				st := obj.(*NetworkPolicyBackendState)
				return st.Key(), nil
			},
			cache.Indexers{
				networkPolicyStateByResources: func(obj interface{}) ([]string, error) {
					state := obj.(*NetworkPolicyBackendState)
					return []string{state.ResourceKey()}, nil
				},
				networkPolicyStateByNetworkPolicy: func(obj interface{}) ([]string, error) {
					state := obj.(*NetworkPolicyBackendState)
					return []string{state.NetworkPolicyName}, nil
				},
			}),
		networkDevices: deviceMgr,
		idPool:         idPool,
		eventQueue:     eventQueue,
		log:            logf.Log.WithName("NetworkPolicyManager"),
		k8sNamespace:   k8sNamespace,
	}, nil
}

// generates default rules on any ManagedResources and Leafs.
func (m *NetworkPolicyManager) generateDefaultRules(leafPort, resourceName, resourceKind string) []ConfigurationRequest {
	return []ConfigurationRequest{
		DefaultDenyNetworkPolicy.GetRules(leafPort, resourceName, resourceKind, nil),
		DefaultPermitNetworkPolicy.GetRules(leafPort, resourceName, resourceKind, nil),
	}
}

// computes the NetworkPolices configured on a resource
func (m *NetworkPolicyManager) computeResourceNetworkPolicies(resource *NetworkPolicyResource) map[string]*NetworkPolicy {
	npIndexer := networkPolicyByLeafSelectors
	if resource.Kind == v1alpha1.ManagedResourceName {
		npIndexer = networkPolicyByManagedResourceSelectors
	}
	npCandidates := make(map[string]*NetworkPolicy)
	for k, v := range resource.Labels {
		ll, _ := m.networkPolicies.ByIndex(npIndexer, label2String(k, v))
		for _, l := range ll {
			np := l.(*NetworkPolicy)
			if np.IsDelete {
				continue
			}
			npCandidates[np.Name] = np
		}
	}

	if resource.Kind == v1alpha12.LeafName {
		for name, np := range npCandidates {
			for k, v := range np.LeafSelector {
				if vv, ok := resource.Labels[k]; !ok || v != vv {
					delete(npCandidates, name)
					break
				}
			}
		}
	} else if resource.Kind == v1alpha1.ManagedResourceName {
		for name, np := range npCandidates {
			for k, v := range np.ManagedResourceSelector {
				if vv, ok := resource.Labels[k]; !ok || v != vv {
					delete(npCandidates, name)
					break
				}
			}
		}
	} else {
		// should not happen.
		return nil
	}
	return npCandidates
}

// computes the NetworkPolicies uses the resource as from or to field selector.
func (m *NetworkPolicyManager) computeResourceUsedByNetworkPolicies(resource *NetworkPolicyResource, nps map[string]struct{}) map[string]struct{} {
	if len(resource.HostIP) == 0 || resource.Kind != v1alpha1.ManagedResourceName || len(resource.Labels) == 0 {
		return nps
	}
	if nps == nil {
		nps = make(map[string]struct{})
	}
	npCandidates := make(map[string]*NetworkPolicy)
	for k, v := range resource.Labels {
		ll, _ := m.networkPolicies.ByIndex(networkPolicyByAddressSelectors, label2String(k, v))
		for _, l := range ll {
			np := l.(*NetworkPolicy)
			if np.IsDelete {
				continue
			}
			if _, ok := nps[np.Name]; ok {
				continue
			}
			npCandidates[np.Name] = np
		}
	}
	for name, np := range npCandidates {
		match := false
		var selectors []map[string]string
		for _, rule := range np.Egress {
			selectors = append(selectors, rule.Selectors...)
		}
		for _, rule := range np.Ingress {
			selectors = append(selectors, rule.Selectors...)
		}
		for _, s := range selectors {
			if match = func() bool {
				for k, v := range s {
					if vv, ok := resource.Labels[k]; !ok || vv != v {
						return false
					}
				}
				return true
			}(); match {
				break
			}
		}
		if !match {
			delete(npCandidates, name)
		}
	}
	for name := range npCandidates {
		nps[name] = struct{}{}
	}
	return nps
}

// compute the resources configured with a NetworkPolicy.
func (m *NetworkPolicyManager) computeNetworkPolicyResources(np *NetworkPolicy) map[string]*NetworkPolicyResource {
	if np == nil {
		return nil
	}
	ret := make(map[string]*NetworkPolicyResource)
	resourcesCnt := make(map[string]int)
	for k, v := range np.LeafSelector {
		ll, _ := m.leafs.ByIndex(leafByLabels, label2String(k, v))
		for _, i := range ll {
			resource := i.(*NetworkPolicyResource)
			resourcesCnt[resource.Key()] += 1
		}
	}
	for name, count := range resourcesCnt {
		if count == len(np.LeafSelector) {
			i, _, _ := m.leafs.GetByKey(name)
			ret[name] = i.(*NetworkPolicyResource)
		}
	}
	resourcesCnt = make(map[string]int)
	for k, v := range np.ManagedResourceSelector {
		ll, _ := m.managedResources.ByIndex(managedResourceByLabels, label2String(k, v))
		for _, i := range ll {
			resource := i.(*NetworkPolicyResource)
			if resource.IsDelete {
				continue
			}
			resourcesCnt[resource.Key()] += 1
		}
	}
	for name, count := range resourcesCnt {
		if count == len(np.ManagedResourceSelector) {
			i, _, _ := m.managedResources.GetByKey(name)
			ret[name] = i.(*NetworkPolicyResource)
		}
	}
	return ret
}

// returns network device operation from a resource.
func (m *NetworkPolicyManager) getNetworkDeviceFromResource(resource *NetworkPolicyResource) *networkDeviceOp {
	var i interface{}
	leafPort := HostAdminLeafPort
	if resource.Kind == v1alpha12.LeafName {
		i, _, _ = m.networkDevices.GetByKey(getInternalNetworkDeviceName(resource.Kind, resource.Name))
	} else {
		ll, _ := m.networkDevices.ByIndex(networkDeviceByConnectedNICs, resource.Identifier)
		if len(ll) == 0 {
			m.log.V(1).Info("Cannot find NetworkDevice from resource",
				"HostNIC", resource.Identifier, "Resource", resource.Name, "Kind", resource.Kind)
			return nil
		}
		i = ll[0]
		leafPort = i.(NetworkDevice).GetPortByNICIdentifier(resource.Identifier)
	}
	return &networkDeviceOp{
		NetworkDevice: i.(NetworkDevice),
		devicePort:    leafPort,
		hostAdmin:     resource.Kind == v1alpha12.LeafName,
		resourceKind:  resource.Kind,
		resourceName:  resource.Name,
	}
}

// returns IPs of resources with matching labels.
func (m *NetworkPolicyManager) getResourceIPsByLabels(labels map[string]string) []net.IP {
	resourcesCnt := make(map[string]int)
	for k, v := range labels {
		ll, _ := m.managedResources.ByIndex(managedResourceByLabels, label2String(k, v))
		for _, i := range ll {
			resource := i.(*NetworkPolicyResource)
			resourcesCnt[resource.Key()] += 1
		}
	}
	var ret []net.IP
	for name, count := range resourcesCnt {
		if count == len(labels) {
			i, _, _ := m.managedResources.GetByKey(name)
			resource := i.(*NetworkPolicyResource)
			if len(resource.HostIP) > 0 {
				ret = append(ret, resource.HostIP)
			}
		}
	}
	return ret
}

// deletes NetworkPolicyBackendStates associated with an index.
func (m *NetworkPolicyManager) deleteBackendStates(indexedValue, indexName string) {
	l, _ := m.networkPolicyBackendStates.ByIndex(indexName, indexedValue)
	for _, i := range l {
		_ = m.networkPolicyBackendStates.Delete(i)
	}
}

// Start background processing
func (m *NetworkPolicyManager) Start(ctx context.Context) error {
	if m == nil {
		return nil
	}
	ticker := time.NewTicker(time.Second)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil
		case <-ticker.C:
			m.RunBackGround()
		}
	}
}

func (m *NetworkPolicyManager) RunBackGround() {
	if m == nil {
		return
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for _, i := range m.networkPolicies.List() {
		// Find if a NetworkPolicy has been removed from all resources
		np := i.(*NetworkPolicy)
		if !np.IsDelete {
			continue
		}
		l, _ := m.leafs.ByIndex(leafByNetworkPolicies, np.Name)
		if len(l) > 0 {
			continue
		}
		l, _ = m.managedResources.ByIndex(managedResourceByNetworkPolicies, np.Name)
		if len(l) > 0 {
			continue
		}
		m.eventQueue.AddEvent(v1alpha1.NetworkPolicyName, client.ObjectKey{
			Namespace: m.k8sNamespace,
			Name:      np.Name,
		})
	}
}

// AddOrUpdateNetworkPolicyResource updates associated NetworkPolicy configurations when ManagedResource or Leaf is modified.
func (m *NetworkPolicyManager) AddOrUpdateNetworkPolicyResource(resource *NetworkPolicyResource) (err error) {
	if m == nil {
		return nil
	}
	defer func() {
		m.log.V(1).Info("AddOrUpdateNetworkPolicyResource completed", "Resource", resource, "Error", err)
	}()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// Find network device associated with the resource.
	indexer := m.leafs
	if resource.Kind == v1alpha1.ManagedResourceName {
		indexer = m.managedResources
	}
	devOp := m.getNetworkDeviceFromResource(resource)
	if devOp == nil {
		return NewNetworkDeviceNotAvailableError(resource.Kind, resource.Name)
	}
	// Compute NetworkPolicy changes to this resource.
	// do reconcile if resources already present and configured
	doReconcile := false

	var existingNps map[string]*NetworkPolicy
	var notifyNps map[string]struct{}
	var addReqs, delReqs []ConfigurationRequest
	configChanged := true
	if i, exists, _ := indexer.GetByKey(resource.Key()); !exists {
		// Update default rules.
		addReqs = append(addReqs, m.generateDefaultRules(devOp.devicePort, resource.Name, resource.Kind)...)
		// Reconcile existing resources during vpc restart.
		doReconcile = resource.Status
	} else {
		existingNps = m.computeResourceNetworkPolicies(i.(*NetworkPolicyResource))
		if configChanged = !resource.ConfigEqual(i.(*NetworkPolicyResource)); configChanged {
			notifyNps = m.computeResourceUsedByNetworkPolicies(i.(*NetworkPolicyResource), notifyNps)
		}
	}

	newNps := m.computeResourceNetworkPolicies(resource)
	if configChanged {
		notifyNps = m.computeResourceUsedByNetworkPolicies(resource, notifyNps)
	}
	for name, np := range newNps {
		// skip np we are notifying, because np content will change therefore do not update
		// network device yet,
		if _, ok := notifyNps[name]; ok {
			continue
		}
		addReqs = append(addReqs, np.GetRules(devOp.devicePort, resource.Name, resource.Kind, m))
	}
	for name, np := range existingNps {
		if _, ok := newNps[name]; ok {
			continue
		}
		delReqs = append(delReqs, np.GetRules(devOp.devicePort, resource.Name, resource.Kind, m))
	}
	// Create backendState if applicable.
	for _, req := range addReqs {
		_ = m.updateNetworkPolicyResourceConfigurationState(req.(*NetworkPolicyRules).NetworkPolicyName, resource.Name, resource.Kind,
			ConfigurationBackendResult{
				State: BackendStateInit,
			}, true)
	}
	inSync := true
	if len(addReqs) > 0 {
		syn, err := devOp.NetworkDevice.UpdateConfigurations(addReqs, devOp.hostAdmin, doReconcile, false)
		if err != nil {
			return err
		}
		inSync = inSync && syn
	}
	if len(delReqs) > 0 {
		syn, err := devOp.NetworkDevice.UpdateConfigurations(delReqs, devOp.hostAdmin, doReconcile, true)
		if err != nil {
			return err
		}
		inSync = inSync && syn
	}
	_ = indexer.Update(resource)
	for np := range notifyNps {
		m.eventQueue.AddEvent(v1alpha1.NetworkPolicyName, client.ObjectKey{
			Namespace: m.k8sNamespace,
			Name:      np,
		})
	}
	if !inSync {
		return NewBackendConfigurationInProgress("Fabric", v1alpha1.NetworkPolicyName, "")
	}
	return nil
}

// DeleteNetworkPolicyResource delete associated NetworkPolicy configurations when a ManagedResource or Leaf is deleted.
func (m *NetworkPolicyManager) DeleteNetworkPolicyResource(resource *NetworkPolicyResource) (err error) {
	if m == nil {
		return nil
	}
	defer func() {
		m.log.V(1).Info("DeleteNetworkPolicyResource completed", "Resource", resource, "Error", err)
	}()

	m.mutex.Lock()
	defer m.mutex.Unlock()
	resourceKey := (&NetworkPolicyBackendState{
		Name: resource.Name,
		Kind: resource.Kind,
	}).ResourceKey()
	// NetworkPolicy configuration is removed when network device is no longer managed by forge.
	if resource.Kind == v1alpha12.LeafName {
		m.deleteBackendStates(resourceKey, networkPolicyStateByResources)
		return m.leafs.Delete(resource)
	}
	// Sanity check.
	_, exists, _ := m.managedResources.GetByKey(resource.Key())
	if !exists {
		return nil
	}
	inSync := true
	devOp := m.getNetworkDeviceFromResource(resource)
	delReqs := m.generateDefaultRules(devOp.devicePort, resource.Name, resource.Kind)
	nps := m.computeResourceNetworkPolicies(resource)
	notifyNps := m.computeResourceUsedByNetworkPolicies(resource, nil)
	if devOp != nil {
		for _, np := range nps {
			delReqs = append(delReqs, np.GetRules(devOp.devicePort, resource.Name, resource.Kind, m))
		}
		if len(delReqs) > 0 {
			syn, err := devOp.NetworkDevice.UpdateConfigurations(delReqs, false, false, true)
			if err != nil {
				return err
			}
			inSync = inSync && syn
		}
	}

	// Update resource before notify.
	resource.IsDelete = true
	_ = m.managedResources.Update(resource)
	for np := range notifyNps {
		m.eventQueue.AddEvent(v1alpha1.NetworkPolicyName, client.ObjectKey{
			Namespace: m.k8sNamespace,
			Name:      np,
		})
	}
	if !inSync {
		return NewBackendConfigurationInProgress("Fabric", v1alpha1.NetworkPolicyName, "")
	}
	m.deleteBackendStates(resourceKey, networkPolicyStateByResources)
	m.managedResources.Delete(resource)
	return nil
}

// AddOrUpdateNetworkPolicy updates backend NetworkPolicy configurations.
func (m *NetworkPolicyManager) AddOrUpdateNetworkPolicy(np *NetworkPolicy) (err error) {
	if m == nil {
		return nil
	}
	defer func() {
		m.log.V(1).Info("AddOrUpdateNetworkPolicy completed", "NetworkPolicy", np, "Error", err)
	}()
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check for NetworkPolicy sanity.
	i, _, _ := m.networkPolicies.GetByKey(np.Name)
	existingNp, _ := i.(*NetworkPolicy)
	doReconcile := existingNp == nil && np.ID != 0

	// Allocated NetworkPolicy ID is not present.
	if np.ID == 0 {
		id, _ := m.idPool.Get()
		np.ID = NetworkPolicyPriorityRuleIDMap[NetworkPolicyPriorityWhileList-1] + 1 + uint16(id)*NetworkPolicyRuleIDRange
	}

	// Find resources and corresponding network devices to remove and to update the NetworkPolicy.
	existingResources := m.computeNetworkPolicyResources(existingNp)
	resources := m.computeNetworkPolicyResources(np)
	var addToDevices, rmFromDevices []*networkDeviceOp
	for _, resource := range resources {
		devOp := m.getNetworkDeviceFromResource(resource)
		if devOp == nil {
			continue
		}
		addToDevices = append(addToDevices, devOp)
	}
	for name, resource := range existingResources {
		if _, ok := resources[name]; ok {
			continue
		}
		devOp := m.getNetworkDeviceFromResource(resource)
		if devOp == nil {
			continue
		}
		rmFromDevices = append(rmFromDevices, devOp)
	}
	// Apply changes to corresponding network devices.
	for _, device := range addToDevices {
		_ = m.updateNetworkPolicyResourceConfigurationState(np.Name, device.resourceName, device.resourceKind,
			ConfigurationBackendResult{
				State: BackendStateInit,
			}, true)
		if _, err = device.UpdateConfigurations(
			[]ConfigurationRequest{np.GetRules(device.devicePort, device.resourceName, device.resourceKind, m)},
			device.hostAdmin, doReconcile, false); err != nil {
			return err
		}
	}
	for _, device := range rmFromDevices {
		if _, err = device.UpdateConfigurations(
			[]ConfigurationRequest{np.GetRules(device.devicePort, device.resourceName, device.resourceKind, m)},
			device.hostAdmin, false, true); err != nil {
			return err
		}
	}
	return m.networkPolicies.Update(np)
}

// DeleteNetworkPolicy delete backend NetworkPolicy configurations.
func (m *NetworkPolicyManager) DeleteNetworkPolicy(np *NetworkPolicy) (err error) {
	if m == nil {
		return nil
	}
	defer func() {
		m.log.V(1).Info("DeleteNetworkPolicy completed", "NetworkPolicy", np, "Error", err)
	}()

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check for NetworkPolicy sanity.
	_, ok, _ := m.networkPolicies.GetByKey(np.Name)
	if !ok {
		m.log.V(1).Info("Delete unknown NetworkPolicy", "Name", np.Name)
		return nil
	}
	if np.ID == 0 {
		m.log.V(1).Info("Delete NetworkPolicy without ID", "Name", np.Name)
		m.networkPolicies.Delete(np)
		return nil
	}
	// Find resources and corresponding network devices to remove or to update the NetworkPolicy.
	resources := m.computeNetworkPolicyResources(np)
	var rmFromDevices []*networkDeviceOp
	for _, resource := range resources {
		devOp := m.getNetworkDeviceFromResource(resource)
		if devOp != nil {
			rmFromDevices = append(rmFromDevices, devOp)
		}
	}
	inSync := true
	for _, device := range rmFromDevices {
		syn, err := device.UpdateConfigurations(
			[]ConfigurationRequest{np.GetRules(device.devicePort, device.resourceName, device.resourceKind, m)},
			device.hostAdmin, false, true)
		if err != nil {
			return err
		}
		inSync = inSync && syn
	}
	if !inSync {
		np.IsDelete = true
		_ = m.networkPolicies.Update(np)
		return NewBackendConfigurationInProgress("Fabric", v1alpha1.NetworkPolicyName, "")
	}
	m.deleteBackendStates(np.Name, networkPolicyStateByNetworkPolicy)
	if err := m.idPool.Release(np.ID); err != nil {
		return err
	}
	return m.networkPolicies.Delete(np)
}

// GetNetworkPolicyProperty returns backend property of a NetworkPolicy.
func (m *NetworkPolicyManager) GetNetworkPolicyProperty(name string) (prop *properties.NetworkPolicyProperties, err error) {
	if m == nil {
		return &properties.NetworkPolicyProperties{}, nil
	}
	defer func() {
		m.log.V(1).Info("GetNetworkPolicyProperty completed", "Name", name, "Property", prop, "Error", err)
	}()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	i, exists, _ := m.networkPolicies.GetByKey(name)
	if !exists {
		return nil, NewBackendConfigurationError("Fabric", v1alpha1.NetworkPolicyName, name, "No NetworkPolicy found")
	}
	return &properties.NetworkPolicyProperties{ID: i.(*NetworkPolicy).ID}, nil
}

// GetNetworkPolicyResourceConfigurationState gets the backend NetworkPolicy configuration state for a Leaf or ManagedResource.
func (m *NetworkPolicyManager) GetNetworkPolicyResourceConfigurationState(npName, name, kind string) *ConfigurationBackendResult {
	if m == nil {
		return nil
	}
	key := (&NetworkPolicyBackendState{
		Name:              name,
		Kind:              kind,
		NetworkPolicyName: npName,
	}).Key()
	i, _, _ := m.networkPolicyBackendStates.GetByKey(key)
	state, _ := i.(*NetworkPolicyBackendState)
	if state == nil {
		return nil
	}
	return &ConfigurationBackendResult{
		State: state.ConfigurationBackendResult.State,
		Error: state.ConfigurationBackendResult.Error,
	}
}

// UpdateNetworkPolicyResourceConfigurationState creates or updates the backend NetworkPolicy configuration state for a Leaf or ManagedResource.
func (m *NetworkPolicyManager) updateNetworkPolicyResourceConfigurationState(npName, name, kind string, rlt ConfigurationBackendResult,
	createOnly bool) error {
	state := &NetworkPolicyBackendState{
		Name:                       name,
		Kind:                       kind,
		NetworkPolicyName:          npName,
		ConfigurationBackendResult: rlt,
	}
	_, exists, _ := m.networkPolicyBackendStates.Get(state)
	if exists == createOnly {
		// create only if not exists
		// update only if exists
		return nil
	}
	return m.networkPolicyBackendStates.Update(state)
}

// GetNetworkPolicyResourceProperty returns NetworkPolicy
func (m *NetworkPolicyManager) GetNetworkPolicyResourceProperty(name, kind string) (prop *properties.NetworkPolicyResourceProperties, err error) {
	if m == nil {
		return nil, nil
	}
	defer func() {
		m.log.V(1).Info("GetNetworkPolicyResourceProperty completed", "Kind", kind, "Name", name, "Property", prop, "Error", err)
	}()
	m.mutex.Lock()
	defer m.mutex.Unlock()
	resourceKey := (&NetworkPolicyBackendState{
		Name: name,
		Kind: kind,
	}).ResourceKey()
	prop = &properties.NetworkPolicyResourceProperties{}
	l, _ := m.networkPolicyBackendStates.ByIndex(networkPolicyStateByResources, resourceKey)
	for _, i := range l {
		st := i.(*NetworkPolicyBackendState)
		if st.Error != nil {
			return nil, st.Error
		}
		if st.State != BackendStateComplete {
			continue
		}
		prop.Applied = append(prop.Applied, st.NetworkPolicyName)
	}
	return prop, nil
}
