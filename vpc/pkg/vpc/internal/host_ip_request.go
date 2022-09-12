/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"reflect"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
)

type HostAdminRequest struct {
	hostAdminIPs map[string]string
	deviceName   string
}

func (r *HostAdminRequest) Key() string {
	return "host-admin-ips/" + r.deviceName
}

func (r *HostAdminRequest) Equal(o ConfigurationRequest) bool {
	return reflect.DeepEqual(r, o)
}

func (r *HostAdminRequest) GetBackendState(mgr *vpcManager) (ConfigurationBackendState, error) {
	i, exists, _ := mgr.networkDevices.GetByKey(r.deviceName)
	if !exists {
		// device is in the process of being added but not in cache yet.
		return BackendStateInit, NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, r.deviceName)
	}
	return i.(*Cumulus).getHostAdminIPsBackendState()
}

func (r *HostAdminRequest) SetBackendState(mgr *vpcManager, state ConfigurationBackendState, err error, notifyChange bool) error {
	i, exists, _ := mgr.networkDevices.GetByKey(r.deviceName)
	if !exists {
		return NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, r.deviceName)
	}
	_ = i.(*Cumulus).sethostAdminIPsBackendState(state, err)
	if notifyChange {
		mgr.networkDevices.NotifyChange(r.deviceName, nil)
	}
	return nil
}
