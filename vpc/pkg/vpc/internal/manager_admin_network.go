/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"fmt"

	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

func (m *vpcManager) GetAdminDHCPServer() (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.adminResourceGroup == nil {
		return "", NewUnknownResourceGroupError(v1alpha1.WellKnownAdminResourceGroup)
	}
	return string(m.adminResourceGroup.Spec.DHCPServer), nil
}

func (m *vpcManager) GetAdminNetworkGW() (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.adminResourceGroup == nil {
		return "", NewUnknownResourceGroupError(v1alpha1.WellKnownAdminResourceGroup)
	}
	return fmt.Sprintf("%s/%d", m.adminResourceGroup.Spec.Network.Gateway,
		m.adminResourceGroup.Spec.Network.PrefixLength), nil
}
