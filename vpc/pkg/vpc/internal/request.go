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

type PortRequest struct {
	Key          client.ObjectKey
	Identifier   string
	DCHPServer   net.IP
	FabricIPPool string
	FabricIP     net.IP
	NeedFabricIP bool
	Isolated     bool
	HostIP       net.IP
	HostMAC      net.HardwareAddr
	DPUIPs       []net.IP
}

func (p *PortRequest) Populate(mr *resource.ManagedResource, rg *resource.ResourceGroup) *PortRequest {
	p.Key = client.ObjectKey{
		Namespace: mr.Namespace,
		Name:      mr.Name,
	}
	p.Identifier = mr.Spec.HostInterface
	p.HostIP = net.ParseIP(string(mr.Spec.HostInterfaceIP))
	p.HostMAC, _ = net.ParseMAC(string(mr.Spec.HostInterfaceMAC))
	if mr.Status.HostAccessIPs != nil {
		p.FabricIP = net.ParseIP(string(mr.Status.HostAccessIPs.FabricIP))
	}

	for _, dpuIP := range mr.Spec.DPUIPs {
		p.DPUIPs = append(p.DPUIPs, net.ParseIP(string(dpuIP)))
	}
	p.NeedFabricIP = mr.Spec.HostInterfaceAccess == resource.HostAccessEgress || mr.Spec.HostInterfaceAccess == resource.HostAccessFabric
	p.Isolated = mr.Spec.HostInterfaceAccess == resource.HostAccessIsolated
	if rg != nil {
		p.FabricIPPool = rg.Spec.FabricIPPool
		p.DCHPServer = net.ParseIP(string(rg.Spec.DHCPServer))
	}
	return p
}

func (p *PortRequest) Update(rt *managedResourceRuntime) {
	if rt.FabricIP != nil && !p.FabricIP.Equal(rt.FabricIP) {
		p.FabricIP = rt.FabricIP
	}
}

func (p *PortRequest) Equal(o *PortRequest) bool {
	eq := p.Key == o.Key && p.DCHPServer.Equal(o.DCHPServer) && p.Isolated == o.Isolated && p.HostIP.Equal(o.HostIP) &&
		p.NeedFabricIP == o.NeedFabricIP
	if !eq {
		return false
	}
	if !p.NeedFabricIP {
		return true
	}
	return p.FabricIP.Equal(o.FabricIP)
}
