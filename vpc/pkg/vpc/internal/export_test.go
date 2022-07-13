/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import "fmt"

func GetVPCManagerImpl(i interface{}) *vpcManager {
	return i.(*vpcManager)
}

func CheckNetworkPolicyManagerResourceFreed(vpcMgr interface{}) error {
	npMgr := vpcMgr.(*vpcManager).networkPolicyMgr
	if len(npMgr.managedResources.ListKeys()) > 0 {
		return fmt.Errorf("mangedResources not empty: %v", npMgr.managedResources.ListKeys())
	}
	if len(npMgr.leafs.ListKeys()) > 0 {
		return fmt.Errorf("leafs not empty: %v", npMgr.leafs.ListKeys())
	}
	if len(npMgr.networkPolicies.ListKeys()) > 0 {
		return fmt.Errorf("networkpolicies empty: %v", npMgr.networkPolicies.ListKeys())
	}
	if len(npMgr.networkPolicyBackendStates.ListKeys()) > 0 {
		return fmt.Errorf("networkpolicyBackendStates empty: %v", npMgr.networkPolicyBackendStates.ListKeys())
	}
	return nil
}
