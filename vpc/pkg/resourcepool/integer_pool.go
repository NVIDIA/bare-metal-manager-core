/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package resourcepool

import (
	"context"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

type IntegerPool struct {
	*pool
}

func newIntegerPool(poolName string, ranges [][]uint64, cl client.Client, k8sNS string) *IntegerPool {
	return &IntegerPool{
		pool: newPool(string(poolName), ranges,
			func(val interface{}) uint64 {
				var val1 uint64
				switch i := val.(type) {
				case int:
					val1 = uint64(i)
				case uint:
					val1 = uint64(i)
				case uint32:
					val1 = uint64(i)
				case int32:
					val1 = uint64(i)
				case uint64:
					val1 = i
				case int64:
					val1 = uint64(i)
				}
				return val1
			},
			func(val uint64) interface{} {
				return val
			},
			func() ([]uint64, error) {
				var resourceGetter func(_ client.Client, _, _ string) ([]uint64, error)
				switch poolName {
				case string(v1alpha12.VNIResourcePool):
					fallthrough
				case string(v1alpha12.VlanIDResourcePool):
					resourceGetter = getVlanVNIFromResourceGroup
				case string(v1alpha12.ASNResourcePool):
					resourceGetter = getASNFromLeaf
				case RuntimePoolNetworkPolicyIDPool:
					resourceGetter = getIDFromNetworkPolicy
				}
				return resourceGetter(cl, string(poolName), k8sNS)
			}),
	}
}

func (p *IntegerPool) Get() (uint64, error) {
	i, err := p.pool.Get()
	if err != nil {
		return 0, err
	}
	return i.(uint64), nil
}

func getVlanVNIFromResourceGroup(cl client.Client, poolName, ns string) ([]uint64, error) {
	rgList := &v1alpha1.ResourceGroupList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, rgList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	ret := make([]uint64, 0, len(rgList.Items))
	for _, i := range rgList.Items {
		if i.Spec.NetworkImplementationType == v1alpha1.OverlayNetworkImplementationTypeFabric &&
			i.Status.FabricNetworkConfiguration != nil {
			var val uint64
			if poolName == string(v1alpha12.VNIResourcePool) {
				val = uint64(i.Status.FabricNetworkConfiguration.VNI)
			} else if poolName == string(v1alpha12.VlanIDResourcePool) {
				val = uint64(i.Status.FabricNetworkConfiguration.VlanID)
			} else {
				continue
			}
			if val == 0 {
				continue
			}
			ret = append(ret, val)
		}
	}
	return ret, nil
}

func getASNFromLeaf(cl client.Client, poolName, ns string) ([]uint64, error) {
	leafList := &v1alpha12.LeafList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, leafList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	ret := make([]uint64, 0, len(leafList.Items))
	for _, i := range leafList.Items {
		if i.Status.ASN > 0 {
			ret = append(ret, uint64(i.Status.ASN))
		}
	}
	return ret, nil
}

func getIDFromNetworkPolicy(cl client.Client, _, ns string) ([]uint64, error) {
	npList := &v1alpha1.NetworkPolicyList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, npList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	ret := make([]uint64, 0, len(npList.Items))
	for _, i := range npList.Items {
		if i.Status.ID > 0 {
			ret = append(ret, uint64(i.Status.ID))
		}
	}
	return ret, nil
}
