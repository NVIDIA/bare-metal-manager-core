package internal

import (
	"k8s.io/client-go/util/workqueue"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
)

type ItemResponse struct {
	err    error
	Output interface{}
}

type WorkItem struct {
	Call     func() (interface{}, error)
	Response chan ItemResponse
}

type OverlayNetworkImplementation interface {
	CreateOrUpdateNetwork(*NetworkRequest) error
	AddOrUpdateResourceToNetwork(*PortRequest, bool) error
	DeleteResourceFromNetwork(*PortRequest) error
	GetNetworkProperties() (*properties.OverlayNetworkProperties, error)
	GetResourceProperties(*PortRequest) (*properties.ResourceProperties, error)
	DeleteNetwork() error
}

type TenantNetwork struct {
	OverlayNetworkImplementation
	WorkQueue workqueue.RateLimitingInterface
	Stop      chan struct{}
}

func NewTenantNetwork(impl OverlayNetworkImplementation, stop chan struct{}) *TenantNetwork {
	return &TenantNetwork{
		OverlayNetworkImplementation: impl,
		WorkQueue:                    workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		Stop:                         stop,
	}
}

func (t *TenantNetwork) Run(name string) {
	go func() {
		for {
			i, shutdown := t.WorkQueue.Get()
			t.WorkQueue.Done(i)
			if shutdown {
				logf.Log.WithName(name).Info("Runner queue exits")
				return
			}
			item := i.(*WorkItem)
			output, err := item.Call()
			if item.Response != nil {
				item.Response <- ItemResponse{
					err:    err,
					Output: output,
				}
				close(item.Response)
			}
		}
	}()
	<-t.Stop
	logf.Log.WithName(name).Info("Runner stopped")
	t.WorkQueue.ShutDown()
}
