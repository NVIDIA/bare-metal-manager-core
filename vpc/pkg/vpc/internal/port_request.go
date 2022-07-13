/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"net"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

type PortRequest struct {
	name         string
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

func (p *PortRequest) Key() string {
	return "mr/" + p.name
}

func (p *PortRequest) Populate(mr *resource.ManagedResource, rg *resource.ResourceGroup) *PortRequest {
	p.name = mr.Name
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

func (p *PortRequest) Equal(i ConfigurationRequest) bool {
	o, ok := i.(*PortRequest)
	if !ok {
		return false
	}
	eq := p.DCHPServer.Equal(o.DCHPServer) && p.Isolated == o.Isolated && p.HostIP.Equal(o.HostIP) &&
		p.NeedFabricIP == o.NeedFabricIP
	if !eq {
		return false
	}
	if !p.NeedFabricIP {
		return true
	}
	return p.FabricIP.Equal(o.FabricIP)
}

func (p *PortRequest) GetBackendState(m *vpcManager) (ConfigurationBackendState, error) {
	rt := m.managedResources.Get(p.name)
	if rt == nil {
		return BackendStateUnknown, nil
	}
	return rt.State, rt.Error
}

func (p *PortRequest) SetBackendState(m *vpcManager, state ConfigurationBackendState, err error, notifyChange bool) error {
	m.managedResources.Update(p.name, func(stored *managedResourceRuntime) *managedResourceRuntime {
		stored.State = state
		stored.Error = err
		return stored
	})
	if notifyChange {
		m.managedResources.NotifyChange(p.name)
	}
	return nil
}
