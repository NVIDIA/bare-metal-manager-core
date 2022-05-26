/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"net"

	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

func (m *vpcManager) GetAdminDHCPServer() (string, error) {
	if m.adminResourceGroup == nil {
		return "", NewUnknownResourceGroupError(v1alpha1.WellKnownAdminResourceGroup)
	}
	return m.adminResourceGroup.dhcpServer.String(), nil
}

func (m *vpcManager) GetAdminNetworkGW() (string, error) {
	if m.adminResourceGroup == nil {
		return "", NewUnknownResourceGroupError(v1alpha1.WellKnownAdminResourceGroup)
	}
	return (&net.IPNet{
		IP:   m.adminResourceGroup.gateway.To4(),
		Mask: m.adminResourceGroup.network.Mask,
	}).String(), nil
}

func (m *vpcManager) GetAdminNetworkVLan() (uint32, error) {
	if m.adminResourceGroup == nil {
		return 0, NewUnknownResourceGroupError(v1alpha1.WellKnownAdminResourceGroup)
	}
	return m.adminResourceGroup.vlan, nil
}
