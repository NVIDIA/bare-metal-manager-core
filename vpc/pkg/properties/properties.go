package properties

import "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"

type OverlayNetworkProperties struct {
	// FabricConfig is the corresponding fabric configuration for this overlay if
	// backend is fabric
	FabricConfig *v1alpha1.FabricNetworkConfiguration
	// SwConfig is the corresponding SDN configuration for this overlay if backend is sw.
	SwConfig *v1alpha1.SoftwareNetworkConfiguration
	// Network specifies overlay network configuration.
	Network *v1alpha1.IPNet
	// DHCPCircID is the interface on which the DHCP relay agent is listening on.
	DHCPCircID string
}

type ResourceProperties struct {
	// FabricReference references to the networkfabric device of this ManagedResource.
	FabricReference *v1alpha1.NetworkFabricReference
	// LogicalPortReference references to a logical port on overlay network connecting to this ManagedResource.
	LogicalPortReference *v1alpha1.LogicalPortReference
	// HostAccessIPs are IPs assigned to the ManagedResource by the backend.
	HostAccessIPs *v1alpha1.IPAssociation
	// NetworkPolicyProperties are NetworkPolicies applied to this ManagedResource.
	NetworkPolicyProperties *NetworkPolicyResourceProperties
}

type NetworkDeviceProperties struct {
	LoopbackIP              string
	ASN                     uint32
	Alive                   bool
	AdminHostIPs            map[string]string
	AdminDHCPServer         string
	NetworkPolicyProperties *NetworkPolicyResourceProperties
}

type NetworkPolicyResourceProperties struct {
	// Applied is NetworkPolices applied to a ManagedResource.
	Applied []string
}

type NetworkPolicyProperties struct {
	// ID associated with a NetworkPolicy.
	ID uint16
}
