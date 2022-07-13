package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

const (
	EnvCumulusUser = "CUMULUS_USER"
	EnvCumulusPwd  = "CUMULUS_PWD"
	EnvSSHUser     = "SSH_USER"
	EnvSSHPwd      = "SSH_PWD"
)

const (
	networkDeviceByConnectedNICs       = "networkDeviceByConnectedNICs"
	managedResourceRuntimeByIdentifier = "managedResourceRuntimeByIdentifier"
)

var (
	// NetworkDeviceRetryBaseDelay is device retry base interval.
	NetworkDeviceRetryBaseDelay = 5 * time.Second
	// NetworkDeviceRetryMaxDelay is device retry max. interval.
	NetworkDeviceRetryMaxDelay = 60 * time.Second
	// NetworkDeviceRetryMaxCount is the max. retry count.
	NetworkDeviceRetryMaxCount = 5
	// NetworkDeviceQueueBucketSize is device queue bucket size.
	// Maximum number of devices in a site.
	NetworkDeviceQueueBucketSize = 1000
	// NetworkDeviceQueueLeakyRate is device queue leak rate.
	NetworkDeviceQueueLeakyRate = 100
	// NetworkDeviceWorkerNum is number of workers handling network device interactions.
	NetworkDeviceWorkerNum = 20
	// EventWorkerNum is number of workers handling K8s events.
	EventWorkerNum = 1
)

type NetworkDeviceTransport interface {
	// Send request to device.
	Send(*http.Request) ([]byte, error)
	// GetMgmtIP returns management IP of the device.
	GetMgmtIP() string
	// SetMgmtIP returns management IP of the device.
	SetMgmtIP(ip string)
	// Ssh sends command to network device via ssh.
	Ssh(cmd string) (string, error)
	// SshHBN sends command to HBN on DPU via ssh.
	SshHBN(cmd string) (string, error)
	// GetHBNContainerID returns HBN containerID.
	GetHBNContainerID() (string, error)
}

type NetworkDevice interface {
	NetworkDeviceTransport
	// Key uniquely identifies a network device.
	Key() string
	// SetMaintenanceMode puts the device in maintenance mode, or vice versa.
	SetMaintenanceMode(bool)
	// IsInMaintenanceMode returns whether the device is in maintenance mode.
	IsInMaintenanceMode() bool
	// SetHostAdminIPs sets admin IPs for hosts.
	SetHostAdminIPs(map[string]string, bool)
	// Liveness continuously probes the liveness of the device.
	Liveness(doReconcile bool)
	// IsReachable is true if the device is alive and operating.
	IsReachable() bool
	// GetNICIdentifiers returns all hosts connected to this device.
	GetNICIdentifiers() []string
	// SetNICIdentifiers sets the connected hosts and their attached ports.
	SetNICIdentifiers(map[string]string)
	// GetPortByNICIdentifier returns the port connected to the host (identifier).
	GetPortByNICIdentifier(identifier string) string
	// UpdateConfigurations updates configures on the device.
	UpdateConfigurations(reqs []ConfigurationRequest, hostAdmin, doReconcile, isDelete bool) (bool, error)
	// ExecuteConfiguration sends configuration updates to the device.
	ExecuteConfiguration() (bool, error)
	// Unmanage attempts to remove all configurations on the device.
	Unmanage() error
	// IsUnmanaged indicates the device is not managed by the controller, do any cleanup.
	IsUnmanaged() bool
	// GetProperties returns networkDevice Properties
	GetProperties() (*properties.NetworkDeviceProperties, error)
}

type ConfigurationBackendState int

const (
	BackendStateInit ConfigurationBackendState = iota
	BackendStateModifying
	BackendStateComplete
	BackendStateDeleted
	BackendStateError
	BackendStateUnknown
)

func (s ConfigurationBackendState) String() string {
	switch s {
	case BackendStateInit:
		return "Initializing"
	case BackendStateModifying:
		return "Modifying"
	case BackendStateComplete:
		return "Completed"
	case BackendStateDeleted:
		return "Deleted"
	case BackendStateError:
		return "Errored"
	}
	return "N/A"
}

func StringToManagedResourceBackendState(in string) ConfigurationBackendState {
	switch in {
	case "Initializing":
		return BackendStateInit
	case "Modifying":
		return BackendStateModifying
	case "Completed":
		return BackendStateComplete
	case "Errored":
		return BackendStateError
	}
	return -1
}

type FabricOverlayNetworkImplementation struct {
	manager       *vpcManager
	resourceGroup string
	log           logr.Logger
	network       *net.IPNet
	gateway       net.IP
	dhcpServer    net.IP
	vni           uint32
	vlan          uint32
	overlayIPPool *resourcepool.IPv4BlockPool
}

func GetVlanInterfaceFromID(vlan uint32) string {
	return fmt.Sprintf("vlan%d", vlan)
}

func NewFabricNetwork(mgr *vpcManager, resourceGroup string) OverlayNetworkImplementation {
	return &FabricOverlayNetworkImplementation{
		manager:       mgr,
		resourceGroup: resourceGroup,
		log:           logf.Log.WithName("fabric").WithName(resourceGroup),
	}
}

func (i *FabricOverlayNetworkImplementation) CreateOrUpdateNetwork(req *NetworkRequest) error {
	network := req.IPNet
	// Check overlay network is already created.
	if req.Exist && i.network != nil {
		if req.DHCPServer.String() != i.dhcpServer.String() {
			i.dhcpServer = req.DHCPServer
			// Notify all ManagedResources in this ResourceGroup that some configuration has changed.
			mrList := &v1alpha12.ManagedResourceList{}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			if err := i.manager.List(ctx, mrList,
				client.InNamespace(req.Key.Namespace),
				client.MatchingFields{controllers.ManagedResourceByGroup: req.Key.Name}); err != nil {
				i.log.Error(err, "Failed to list ManagedResources in ResourceGroup", "ResourceGroup", req.Key)
				return err
			}
			for _, mr := range mrList.Items {
				i.manager.managedResources.NotifyChange(mr.Name)
			}
		}
		// Nothing to do, network is already configured.
		return NewAlreadyExistError("ResourceGroup", req.Key.String())
	}

	// Allocation VNI and vlan

	if i.vni == 0 {
		if req.VNI != 0 {
			i.vni = req.VNI
		} else {
			vniPool := i.manager.resourceMgr.GetIntegerPool(string(v1alpha1.VNIResourcePool))
			if vniPool == nil {
				i.log.Info("VNI resource pool not found")
				return NewMissingResourcePoolError(string(v1alpha1.VNIResourcePool))
			}
			vni, err := vniPool.Get()
			if err != nil {
				i.log.Info("Get resource from vni resource pool return error", "Error", err)
				return NewMissingResourcePoolError(string(v1alpha1.VNIResourcePool))
			}
			i.vni = uint32(vni)
		}
	}
	if i.vlan == 0 {
		if req.VLAN != 0 {
			i.vlan = req.VLAN
		} else {
			vlanPool := i.manager.resourceMgr.GetIntegerPool(string(v1alpha1.VlanIDResourcePool))
			if vlanPool == nil {
				i.log.Info("VNI resource pool not found")
				return NewMissingResourcePoolError(string(v1alpha1.VlanIDResourcePool))
			}
			vlanid, err := vlanPool.Get()
			if err != nil {
				i.log.Info("Get resource from vlan resource pool return error", "Error", err)
				return NewMissingResourcePoolError(string(v1alpha1.VlanIDResourcePool))
			}
			i.vlan = uint32(vlanid)
		}
	}
	// Allocate overlay network
	if network == nil {
		// Multiple updates sent to backend, while frontend has not flush out resourceGroup.status.
		if i.overlayIPPool != nil {
			return nil
		}
		ipPool := i.manager.resourceMgr.GetIPv4Pool(req.OverlayIPPool)
		if ipPool == nil {
			i.log.Info("Overlay resource pool not found", "Pool", req.OverlayIPPool)
			return NewMissingResourcePoolError(req.OverlayIPPool)
		}
		ipstr, err := ipPool.Get()
		if err != nil {
			i.log.Info("Get resource from overlay resource pool return error", "Error", err)
			return NewMissingResourcePoolError(req.OverlayIPPool)
		}
		_, network, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", ipstr, ipPool.PrefixLen))
		i.overlayIPPool = ipPool
	}
	i.dhcpServer = req.DHCPServer
	i.network = network
	if req.Gateway != nil {
		i.gateway = req.Gateway
	} else {
		i.gateway = utils.Int2ip(utils.Ip2int(i.network.IP) + 1)
	}
	return nil
}

func (i *FabricOverlayNetworkImplementation) DeleteNetwork() error {
	if i.overlayIPPool != nil && i.network != nil {
		_ = i.overlayIPPool.Release(i.network.IP.String())
	}
	if vniPool := i.manager.resourceMgr.GetIntegerPool(string(v1alpha1.VNIResourcePool)); vniPool != nil && i.vni > 0 {
		_ = vniPool.Release(i.vni)
	}
	if vlanPool := i.manager.resourceMgr.GetIntegerPool(string(v1alpha1.VlanIDResourcePool)); vlanPool != nil && i.vlan > 0 {
		_ = vlanPool.Release(i.vlan)
	}
	return nil
}

func (i *FabricOverlayNetworkImplementation) GetNetworkProperties() (*properties.OverlayNetworkProperties, error) {
	if !i.IsReady() {
		return &properties.OverlayNetworkProperties{}, NewBackendConfigurationInProgress("fabric", "ResourceGroup", i.resourceGroup)
	}
	prefixLen, _ := i.network.Mask.Size()
	return &properties.OverlayNetworkProperties{
		FabricConfig: &v1alpha12.FabricNetworkConfiguration{
			VNI:    i.vni,
			VlanID: i.vlan,
		},
		Network: &v1alpha12.IPNet{
			IP:           v1alpha12.IPAddress(i.network.IP.String()),
			PrefixLength: uint32(prefixLen),
			Gateway:      v1alpha12.IPAddress(i.gateway.String()),
		},
		DHCPCircID: GetVlanInterfaceFromID(i.vlan),
	}, nil
}

func (i *FabricOverlayNetworkImplementation) AddOrUpdateResourceToNetwork(req *PortRequest, doReconcile bool) error {
	i.log.V(1).Info("AddOrUpdateResourceToNetwork", "ManagedResource", req.name)
	l, err := i.manager.networkDevices.ByIndex(networkDeviceByConnectedNICs, req.Identifier)
	if err != nil {
		i.log.Error(err, "Failed to list network devices", "HostInterface", req.Identifier)
		return err
	}
	if len(l) == 0 {
		return NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, "")
	}
	if req.NeedFabricIP && req.FabricIP == nil {
		// Allow frontend to persist allocated resources.
		i.log.V(1).Info("AddOrUpdateResourceToNetwork returns to allow persisting allowed IPs")
		return nil
	}
	done := true
	for _, ii := range l {
		device := ii.(NetworkDevice)
		if device.IsInMaintenanceMode() {
			return NewNetworkDeviceInMaintenanceError(v1alpha1.LeafName, device.Key())
		}
		if !device.IsReachable() {
			return NewNetworkDeviceNotReachableError(v1alpha1.LeafName, device.Key())
		}
		if device.IsUnmanaged() {
			return NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, device.Key())
		}

		ok, err := device.UpdateConfigurations([]ConfigurationRequest{req}, false, doReconcile, false)
		if err != nil {
			return err
		}
		done = ok
	}
	if done {
		return nil
	}
	return NewBackendConfigurationInProgress("Fabric", v1alpha12.ManagedResourceName, req.Key())
}

func (i *FabricOverlayNetworkImplementation) DeleteResourceFromNetwork(req *PortRequest) error {
	l, err := i.manager.networkDevices.ByIndex(networkDeviceByConnectedNICs, req.Identifier)
	if err != nil {
		i.log.Error(err, "Failed to list network devices", "HostInterface", req.Identifier)
		return err
	}
	if len(l) == 0 {
		i.log.Info("Connected network device not found, remove resource is no-op", "ManagedResource", req.Key())
		return nil
	}
	done := true
	for _, ii := range l {
		device := ii.(NetworkDevice)
		if device.IsInMaintenanceMode() {
			return NewNetworkDeviceInMaintenanceError(v1alpha1.LeafName, device.Key())
		}
		if !device.IsReachable() {
			return NewNetworkDeviceNotReachableError(v1alpha1.LeafName, device.Key())
		}
		ok, err := device.UpdateConfigurations([]ConfigurationRequest{req}, false, false, true)
		if err != nil {
			return err
		}
		done = ok
	}
	if done {
		return nil
	}
	return NewBackendConfigurationInProgress("Fabric", v1alpha12.ManagedResourceName, req.Key())
}

func (i *FabricOverlayNetworkImplementation) GetResourceProperties(req *PortRequest) (*properties.ResourceProperties, error) {
	l, err := i.manager.networkDevices.ByIndex(networkDeviceByConnectedNICs, req.Identifier)
	if err != nil {
		i.log.Error(err, "Failed to list network devices", "HostInterface", req.Identifier)
		return nil, err
	}
	if len(l) == 0 {
		i.log.Info("Connected network device not found.", "ManagedResource", req.name)
		return nil, NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, "")
	}

	mrRt := i.manager.managedResources.Get(req.name)
	if mrRt == nil {
		return nil, fmt.Errorf("internal error ManagedResource runtime not found: %s", req.Key())
	}
	device := l[0].(NetworkDevice)
	_, k8sName := getNetworkDeviceK8sKindName(device.Key())
	var retErr error
	if mrRt.Error != nil {
		retErr = NewBackendConfigurationError("Fabric", v1alpha12.ManagedResourceName, k8sName, mrRt.Error.Error())
	}
	var fabricIP net.IP
	if !req.Isolated {
		if req.NeedFabricIP {
			fabricIP = mrRt.FabricIP
		} else {
			fabricIP = req.HostIP
		}
	}
	return &properties.ResourceProperties{
		FabricReference: &v1alpha12.NetworkFabricReference{
			Kind:               v1alpha1.LeafName,
			Name:               k8sName,
			Port:               device.GetPortByNICIdentifier(req.Identifier),
			ConfigurationState: mrRt.State.String(),
		},
		HostAccessIPs: &v1alpha12.IPAssociation{
			HostIP:   v1alpha12.IPAddress(req.HostIP.String()),
			FabricIP: v1alpha12.IPAddress(fabricIP.String()),
		},
	}, retErr
}

func (i *FabricOverlayNetworkImplementation) IsReady() bool {
	return i.network != nil
}
