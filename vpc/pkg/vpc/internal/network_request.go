/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"fmt"
	"net"

	"sigs.k8s.io/controller-runtime/pkg/client"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

type NetworkRequest struct {
	Key           client.ObjectKey
	DHCPServer    net.IP
	OverlayIPPool string
	FabricIPPool  string
	Gateway       net.IP
	IPNet         *net.IPNet
	Exist         bool
	VNI           uint32
	VLAN          uint32
}

func (n *NetworkRequest) Populate(rg *resource.ResourceGroup) *NetworkRequest {
	n.Key = client.ObjectKey{
		Namespace: rg.Namespace,
		Name:      rg.Name,
	}
	n.DHCPServer = net.ParseIP(string(rg.Spec.DHCPServer))
	n.OverlayIPPool = rg.Spec.OverlayIPPool
	n.FabricIPPool = rg.Spec.FabricIPPool
	network := rg.Status.Network
	if network == nil {
		network = rg.Spec.Network
	}
	if network != nil {
		_, n.IPNet, _ = net.ParseCIDR(fmt.Sprintf("%s/%d", network.IP, network.PrefixLength))
		n.Gateway = net.ParseIP(string(network.Gateway))
	}
	if rg.Status.FabricNetworkConfiguration != nil {
		n.VNI = rg.Status.FabricNetworkConfiguration.VNI
		n.VLAN = rg.Status.FabricNetworkConfiguration.VlanID
	}
	n.Exist = rg.Status.Network != nil
	return n
}
