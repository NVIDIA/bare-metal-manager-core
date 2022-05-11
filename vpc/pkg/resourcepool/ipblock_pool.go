/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package resourcepool

import (
	"context"
	"net"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

type IPv4BlockPool struct {
	*pool
	PrefixLen uint32
}

func newIPv4BlockPool(poolName v1alpha12.WellKnownConfigurationResourcePool, ranges [][]string, cl client.Client, blockSizeBit uint, k8sNS string) *IPv4BlockPool {
	intRange := make([][]uint64, 0, len(ranges))
	// convert ip range to start and end.
	for _, r := range ranges {
		start := utils.Ip2int(net.ParseIP(r[0])) >> blockSizeBit
		end := utils.Ip2int(net.ParseIP(r[1])) >> blockSizeBit
		intRange = append(intRange, []uint64{uint64(start), uint64(end)})
	}
	return &IPv4BlockPool{
		PrefixLen: 32 - uint32(blockSizeBit),
		pool: newPool(string(poolName), intRange,
			func(val interface{}) uint64 {
				// convert IP string to integer index.
				var s string
				switch i := val.(type) {
				case string:
					s = i
				case v1alpha1.IPAddress:
					s = string(i)
				}
				intv := utils.Ip2int(net.ParseIP(s))
				return uint64(intv >> blockSizeBit)
			},
			func(val uint64) interface{} {
				// convert integer index to IP string.
				intv := uint32(val) << blockSizeBit
				return utils.Int2ip(intv).String()
			},
			func() ([]uint64, error) {
				// List IPBlocks used by K8s resources.
				var resourceGetter func(_ client.Client, _, _ string) ([]string, error)
				switch poolName {
				case v1alpha12.PublicIPv4ResourcePool:
					fallthrough
				case v1alpha12.DatacenterIPv4ResourcePool:
					resourceGetter = getFabricIPFromManagedResource
				case v1alpha12.OverlayIPv4ResourcePool:
					resourceGetter = getOverlayIPBlocksFromResourceGroup
				case v1alpha12.LoopbackIPResourcePool:
					resourceGetter = getLoopbackIPFromLeaf
				}
				ips, err := resourceGetter(cl, string(poolName), k8sNS)
				if err != nil {
					return nil, err
				}
				ret := make([]uint64, 0, len(ips))
				for _, ipstr := range ips {
					ip := net.ParseIP(ipstr)
					ret = append(ret, uint64(utils.Ip2int(ip)>>blockSizeBit))
				}
				return ret, nil
			}),
	}
}

// Get implements IPv4BlockPool.
func (p *IPv4BlockPool) Get() (string, error) {
	i, err := p.pool.Get()
	if err != nil {
		return "", err
	}
	return i.(string), nil
}

// Update implements IPv4BlockPool.
func (p *IPv4BlockPool) Update(strRanges [][]string) {
	var ranges [][]uint64
	for _, r := range strRanges {
		start := p.converterToInt(r[0])
		end := p.converterToInt(r[1])
		ranges = append(ranges, []uint64{start, end})
	}
	p.pool.Update(ranges)
}

func getOverlayIPBlocksFromResourceGroup(cl client.Client, name, ns string) ([]string, error) {
	rgList := &v1alpha1.ResourceGroupList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, rgList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	ret := make([]string, 0, len(rgList.Items))
	for _, i := range rgList.Items {
		if i.Spec.OverlayIPPool == name && i.Status.Network != nil {
			ret = append(ret, string(i.Status.Network.IP))
		}
	}
	return ret, nil
}

func getFabricIPFromManagedResource(cl client.Client, poolname, ns string) ([]string, error) {
	rgList := &v1alpha1.ResourceGroupList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, rgList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	poolMap := make(map[string]struct{})
	for _, i := range rgList.Items {
		if i.Spec.FabricIPPool == poolname {
			poolMap[i.Name] = struct{}{}
		}
	}
	ret := make([]string, 0)
	mrList := &v1alpha1.ManagedResourceList{}
	if err := cl.List(ctx, mrList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	for _, i := range mrList.Items {
		if _, ok := poolMap[i.Spec.ResourceGroup]; !ok {
			continue
		}
		if (i.Spec.HostInterfaceAccess == v1alpha1.HostAccessEgress || i.Spec.HostInterfaceAccess == v1alpha1.HostAccessFabric) &&
			len(i.Status.HostAccessIPs.FabricIP) > 0 {
			ret = append(ret, string(i.Status.HostAccessIPs.FabricIP))
		}
	}
	return ret, nil
}

func getLoopbackIPFromLeaf(cl client.Client, _, ns string) ([]string, error) {
	leafList := &v1alpha12.LeafList{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := cl.List(ctx, leafList, client.InNamespace(ns)); err != nil {
		return nil, err
	}
	ret := make([]string, 0, len(leafList.Items))
	for _, i := range leafList.Items {
		if len(i.Status.LoopbackIP) > 0 {
			ret = append(ret, i.Status.LoopbackIP)
		}
	}
	return ret, nil

}
