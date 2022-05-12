/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"sync"

	"github.com/go-logr/logr"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type resourceID struct {
	Kind string
	key  client.ObjectKey
}

type vpcManagerEventQueue struct {
	mutex      sync.Mutex
	eventChans map[string]chan client.ObjectKey
	eventQueue workqueue.RateLimitingInterface
	log        logr.Logger
}

// GetEvent returns a channel that receives backend events on K8s resources.
// Note: it supports only single listener per k8s resource Kind.
func (q *vpcManagerEventQueue) GetEvent(kind string) <-chan client.ObjectKey {
	return q.getEventChanWithLock(kind, true)
}

func (q *vpcManagerEventQueue) getEventChanWithLock(kind string, create bool) chan client.ObjectKey {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	ch, ok := q.eventChans[kind]
	if !ok {
		if !create {
			return nil
		}
		ch = make(chan client.ObjectKey, 10)
		q.eventChans[kind] = ch
	}
	return ch
}

func (q *vpcManagerEventQueue) AddEvent(kind string, obj client.ObjectKey) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.eventQueue.Add(
		resourceID{Kind: kind, key: obj},
	)
}

func (q *vpcManagerEventQueue) RunWorker() {
	for {
		i, shutdown := q.eventQueue.Get()
		if shutdown {
			q.log.V(1).Info("EventWorker shuts down")
			return
		}
		q.eventQueue.Done(i)
		rid := i.(resourceID)
		ch := q.getEventChanWithLock(rid.Kind, false)
		if ch == nil {
			q.log.Error(nil, "Event channel not found", "Kind", rid.Kind)
			continue
		}
		ch <- rid.key
	}
}
