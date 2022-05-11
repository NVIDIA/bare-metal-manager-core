/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

func GetVPCManagerImpl(i interface{}) *vpcManager {
	return i.(*vpcManager)
}
