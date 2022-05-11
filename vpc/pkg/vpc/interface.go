package vpc

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
)

var (
	HBNConfig = &internal.HBNConfig
)

type VPCManager interface {
	// CreateOrUpdateOverlayNetwork creates or update overlay network for a ResourceGroup.
	CreateOrUpdateOverlayNetwork(ctx context.Context, name string) error
	// GetOverlayNetworkProperties retrieves properties of an overlay network from the backend.
	GetOverlayNetworkProperties(ctx context.Context, name string) (*properties.OverlayNetworkProperties, error)
	// DeleteOverlayNetwork deletes an overlay network when responding ResourceGroup is deleted.
	DeleteOverlayNetwork(ctx context.Context, name string) error
	// AddOrUpdateResourceToNetwork adds or updates a ManagedResource on an overlay network.
	AddOrUpdateResourceToNetwork(ctx context.Context, name string) error
	// GetResourceProperties retrieves properties of a ManagedResource from the backend.
	GetResourceProperties(ctx context.Context, name string) (*properties.ResourceProperties, error)
	// RemoveResourceToNetwork removes a ManagedResource from an overlay network.
	RemoveResourceToNetwork(ctx context.Context, name string) error
	// CreateOrUpdateNetworkDevice creates or updates a network device.
	CreateOrUpdateNetworkDevice(ctx context.Context, kind, name string) error
	// GetNetworkDeviceProperties returns a network device properties.
	GetNetworkDeviceProperties(ctx context.Context, kind, name string) (*properties.NetworkDeviceProperties, error)
	// RemoveNetworkDevice removes a network device.
	RemoveNetworkDevice(_ context.Context, kind, name string) error
	// Start the VPC manager.
	Start(ctx context.Context) error
	// GetEvent indicates some backend event(s) has happened to a K8s Resource.
	GetEvent(kind string) <-chan client.ObjectKey
	// AddEvent add K8s resource event to it may be re-processed via GetEvent.
	AddEvent(kind string, obj client.ObjectKey)
}

func NewVPCManager(cl client.Client, podController *controllers.PodReconciler, crdNS string,
	resourceMgr *resourcepool.Manager) VPCManager {
	return internal.NewManager(cl, podController, crdNS, resourceMgr)
}
