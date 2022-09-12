/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"github.com/go-logr/logr"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpcManagerDevice struct {
	queue workqueue.RateLimitingInterface
	log   logr.Logger
	cache.Indexer
	eventQueue       *vpcManagerEventQueue
	managedResources *vpcManagerManagedResource
	k8sNamespace     string
}

type networkDeviceOp struct {
	NetworkDevice
	devicePort   string
	hostAdmin    bool
	resourceName string
	resourceKind string
}

// NotifyChange notifies the front end that NetworkDevice has changed.
func (q *vpcManagerDevice) NotifyChange(key string, hostNics []string) {
	kind, name := getNetworkDeviceK8sKindName(key)
	i, _, _ := q.GetByKey(key)
	_, ok := i.(NetworkDevice)
	if !ok {
		q.log.V(1).Info("Notify network device change, not found", "Name", key)
		return
	}
	q.managedResources.NotifyNetworkDeviceChange(hostNics)
	q.eventQueue.AddEvent(kind, client.ObjectKey{
		Namespace: q.k8sNamespace,
		Name:      name,
	})
}

func (q *vpcManagerDevice) Add(device NetworkDevice, retry bool) {
	q.log.V(1).Info("Configuration queued for device", "Device", device.Key(), "Retry", retry)
	if !retry {
		q.queue.Add(device)
		return
	}
	q.queue.AddRateLimited(device)
}

func (q *vpcManagerDevice) Remove(device NetworkDevice) {
	q.queue.Forget(device)
	q.queue.Done(device)
}

func (q *vpcManagerDevice) RunWorker() {
	for {
		i, shutdown := q.queue.Get()
		if shutdown {
			return
		}
		retry, _ := i.(NetworkDevice).ExecuteConfiguration()
		// Done after execution to ensure one execution per device.
		q.queue.Done(i)
		if retry && q.queue.NumRequeues(i) <= NetworkDeviceRetryMaxCount {
			q.Add(i.(NetworkDevice), true)
			continue
		}
		q.queue.Forget(i)
	}
}
