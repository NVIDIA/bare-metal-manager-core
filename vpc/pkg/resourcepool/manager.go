/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package resourcepool

import (
	"fmt"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
)

var (
	log = logf.Log.WithName("Resource Pool")
)

type Manager struct {
	mutex        sync.Mutex
	ipv4Pools    map[v1alpha1.WellKnownConfigurationResourcePool]*IPv4BlockPool
	integerPools map[v1alpha1.WellKnownConfigurationResourcePool]*IntegerPool
	k8sClient    client.Client
	namespace    string
}

func NewManager(k8sClient client.Client, k8sNS string) *Manager {
	return &Manager{
		ipv4Pools:    make(map[v1alpha1.WellKnownConfigurationResourcePool]*IPv4BlockPool),
		integerPools: make(map[v1alpha1.WellKnownConfigurationResourcePool]*IntegerPool),
		k8sClient:    k8sClient,
		namespace:    k8sNS,
	}
}

// CreateIPv4Pool creates an IPv4 resource pool.
func (m *Manager) CreateIPv4Pool(
	poolName v1alpha1.WellKnownConfigurationResourcePool,
	ranges [][]string, blkSizeBit uint) *IPv4BlockPool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	pool := newIPv4BlockPool(poolName, ranges, m.k8sClient, blkSizeBit, m.namespace)
	m.ipv4Pools[poolName] = pool
	log.V(1).Info("Create ipv4 pool", "Name", poolName, "Ranges", ranges, "BlkSizeBit", blkSizeBit)
	return pool
}

// CreateIntegerPool creates an integer resource pool.
func (m *Manager) CreateIntegerPool(
	poolName v1alpha1.WellKnownConfigurationResourcePool,
	ranges [][]uint64) *IntegerPool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	pool := newIntegerPool(poolName, ranges, m.k8sClient, m.namespace)
	m.integerPools[poolName] = pool
	log.V(1).Info("Create integer pool", "Name", poolName, "Ranges", ranges)
	return pool
}

// Delete deletes a resource pool.
func (m *Manager) Delete(poolName v1alpha1.WellKnownConfigurationResourcePool) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.ipv4Pools[poolName]; ok {
		log.V(1).Info("Delete IPv4 pool", "Name", poolName)
		delete(m.ipv4Pools, poolName)
		return nil
	}
	if _, ok := m.integerPools[poolName]; ok {
		log.V(1).Info("Delete integer pool", "Name", poolName)
		delete(m.integerPools, poolName)
		return nil
	}
	return fmt.Errorf("unknown resource pool: %s", poolName)
}

// GetIPv4Pool returns an existing IPv4 resource pool.
func (m *Manager) GetIPv4Pool(poolName v1alpha1.WellKnownConfigurationResourcePool) *IPv4BlockPool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	pool, ok := m.ipv4Pools[poolName]
	if !ok {
		return nil
	}
	return pool
}

// GetIntegerPool returns an existing integer resource pool.
func (m *Manager) GetIntegerPool(poolName v1alpha1.WellKnownConfigurationResourcePool) *IntegerPool {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	pool, ok := m.integerPools[poolName]
	if !ok {
		return nil
	}
	return pool
}
