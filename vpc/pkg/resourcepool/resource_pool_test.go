package resourcepool_test

import (
	"context"
	"fmt"
	"net"

	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

func verifyIP(ipStr string, prefixLen int32, ipRanges [][]string) {
	for _, r := range ipRanges {
		start := utils.Ip2int(net.ParseIP(r[0]))
		end := utils.Ip2int(net.ParseIP(r[1]))
		ip := utils.Ip2int(net.ParseIP(ipStr))
		mask := ^uint32(0xffffffff) << (32 - prefixLen)
		Expect(ip&mask).To(BeZero(), fmt.Sprintf("ip obeys subnet prefix rule, IP=%s, mask=%s(%x)", ipStr, utils.Int2ip(mask).String(), mask))
		if ip >= start && ip < end {
			return
		}
	}
	Fail(fmt.Sprintf("IP outside ranges, Ranges=%v, IP=%s", ipRanges, ipStr))
}

func verifyInteger(val uint64, intRanges [][]uint64) {
	for _, r := range intRanges {
		if val >= r[0] && val < r[1] {
			return
		}
	}
	Fail(fmt.Sprintf("Integer outside ranges, Ranges=%v, Val=%d", intRanges, val))
}

var _ = Describe("ResourcePool", func() {
	AfterEach(func() {
		By("Removing K8s resources")
		rgList := &v1alpha12.ResourceGroupList{}
		err := k8sClient.List(context.Background(), rgList, client.InNamespace(namespace))
		Expect(err).ToNot(HaveOccurred())
		for _, item := range rgList.Items {
			err = k8sClient.Delete(context.Background(), &item)
			Expect(err).ToNot(HaveOccurred())
		}
		mgList := &v1alpha12.ManagedResourceList{}
		err = k8sClient.List(context.Background(), mgList, client.InNamespace(namespace))
		Expect(err).ToNot(HaveOccurred())
		for _, item := range mgList.Items {
			err = k8sClient.Delete(context.Background(), &item)
			Expect(err).ToNot(HaveOccurred())
		}
		npList := &v1alpha12.NetworkPolicyList{}
		err = k8sClient.List(context.Background(), npList, client.InNamespace(namespace))
		Expect(err).ToNot(HaveOccurred())
		for _, item := range npList.Items {
			err = k8sClient.Delete(context.Background(), &item)
			Expect(err).ToNot(HaveOccurred())
		}
	})

	table.DescribeTable("IP resource pool",
		func(poolName string, prefixLen int32) {
			mgr := resourcepool.NewManager(k8sClient, namespace)
			if prefixLen == 0 {
				prefixLen = 8 + randGen.Int31n(23) // prefixlen 8-30
			}
			rangeSize := 1 + randGen.Int31n(3) //
			blkCnt := 1 + randGen.Int31n(24)
			ipRanges := generateIPRage(prefixLen, blkCnt, rangeSize)
			logf.Log.V(1).Info("Generated range", "PrefixLen", prefixLen, "BlockCnt", blkCnt,
				"RangeCnt", rangeSize, "Range", ipRanges)
			ipBlockPool := mgr.CreateIPv4Pool(poolName, ipRanges, 32-uint(prefixLen))
			Expect(mgr.GetIPv4Pool(poolName)).To(Equal(ipBlockPool))
			err := ipBlockPool.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			count, err := ipBlockPool.Available()
			Expect(err).ToNot(HaveOccurred())

			allocated := make(map[string]struct{})
			By("Get resources from the pool")
			for {
				c, err := ipBlockPool.Available()
				Expect(err).ToNot(HaveOccurred())
				if c == 0 {
					break
				}
				i, err := ipBlockPool.Get()
				Expect(err).ToNot(HaveOccurred())
				Expect(ipBlockPool.Allocated(i)).To(BeTrue())
				allocated[i] = struct{}{}
				verifyIP(i, prefixLen, ipRanges)
			}
			Expect(uint64(len(allocated))).To(Equal(count), "Allocated all resources")
			By("Release resources into the pool")
			for ip := range allocated {
				err := ipBlockPool.Release(ip)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(ipBlockPool.Available()).To(Equal(count), "Restored to initial state")

			By("Reconcile resources from the pool")

			rg1 := &v1alpha12.ResourceGroup{}
			if poolName != string(v1alpha1.OverlayIPv4ResourcePool) {
				rg1.Name = "rg-fabric"
				rg1.Namespace = namespace
				rg1.Spec.FabricIPPool = string(poolName)
				err := k8sClient.Create(context.Background(), rg1)
				Expect(err).ToNot(HaveOccurred())
			}
			for ip := range allocated {
				if poolName == string(v1alpha1.OverlayIPv4ResourcePool) {
					rg := &v1alpha12.ResourceGroup{}
					rg.Name = "rg-" + ip
					rg.Namespace = namespace
					rg.Spec.OverlayIPPool = string(poolName)
					err := k8sClient.Create(context.Background(), rg)
					Expect(err).ToNot(HaveOccurred())
					rg.Status.Network = &v1alpha12.IPNet{
						IP:           v1alpha12.IPAddress(ip),
						PrefixLength: uint32(prefixLen),
					}
					err = k8sClient.Status().Update(context.Background(), rg)
					Expect(err).ToNot(HaveOccurred())
				} else {
					mr := &v1alpha12.ManagedResource{}
					mr.Name = "mr-" + ip
					mr.Namespace = namespace
					mr.Spec.ResourceGroup = rg1.Name
					mr.Spec.HostInterfaceAccess = v1alpha12.HostAccessFabric
					mr.Status.HostAccessIPs = &v1alpha12.IPAssociation{
						FabricIP: v1alpha12.IPAddress(ip),
					}
					err := k8sClient.Create(context.Background(), mr)
					Expect(err).ToNot(HaveOccurred())
					err = k8sClient.Status().Update(context.Background(), mr)
					Expect(err).ToNot(HaveOccurred())
				}
			}
			err = ipBlockPool.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			Expect(ipBlockPool.Available()).To(BeZero(), "Reconciled all resources")

			By("Update resource pool")
			ipRanges = generateIPRage(prefixLen, blkCnt, 1)
			ipBlockPool.Update(ipRanges)
			Expect(ipBlockPool.Available()).To(Equal(uint64(blkCnt)), "Update resource pool")

			err = mgr.Delete(poolName)
			Expect(err).ToNot(HaveOccurred())
		},
		table.Entry("Overlay IP pool", string(v1alpha1.OverlayIPv4ResourcePool), int32(0)),
		table.Entry("Public IP pool", string(v1alpha1.PublicIPv4ResourcePool), int32(32)),
		table.Entry("Datacenter IP pool", string(v1alpha1.DatacenterIPv4ResourcePool), int32(32)))

	table.DescribeTable("Integer resource pool",
		func(poolName string) {
			mgr := resourcepool.NewManager(k8sClient, namespace)
			rangeSize := 1 + randGen.Intn(3)
			cnt := 1 + randGen.Intn(24)
			intRanges := generateIntegerRage(cnt, rangeSize, uint64(^uint16(0)))
			logf.Log.V(1).Info("Generated range", "Count", cnt, "RangeCnt", rangeSize, "Range", intRanges)
			intPool := mgr.CreateIntegerPool(poolName, intRanges)
			Expect(mgr.GetIntegerPool(poolName)).To(Equal(intPool))
			err := intPool.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			count, err := intPool.Available()
			Expect(err).ToNot(HaveOccurred())
			allocated := make(map[uint64]struct{})

			By("Get resources from the pool")
			for {
				c, err := intPool.Available()
				Expect(err).ToNot(HaveOccurred())
				if c == 0 {
					break
				}
				i, err := intPool.Get()
				Expect(err).ToNot(HaveOccurred())
				Expect(intPool.Allocated(i)).To(BeTrue())
				allocated[i] = struct{}{}
				verifyInteger(i, intRanges)
			}
			Expect(uint64(len(allocated))).To(Equal(count), "Allocated all resources")
			By("Release resources into the pool")
			for val := range allocated {
				err := intPool.Release(val)
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(intPool.Available()).To(Equal(count), "Restored to initial state")

			By("Reconcile resources from the pool")
			if poolName == resourcepool.RuntimePoolNetworkPolicyIDPool {
				for val := range allocated {
					np := &v1alpha12.NetworkPolicy{}
					np.Name = fmt.Sprintf("np-%d", val)
					np.Namespace = namespace
					np.Status.ID = uint16(val)
					err := k8sClient.Create(context.Background(), np)
					Expect(err).ToNot(HaveOccurred())
					err = k8sClient.Status().Update(context.Background(), np)
					Expect(err).ToNot(HaveOccurred())
				}
			} else {
				for val := range allocated {
					rg := &v1alpha12.ResourceGroup{}
					rg.Name = fmt.Sprintf("rg-%d", val)
					rg.Namespace = namespace
					rg.Spec.NetworkImplementationType = v1alpha12.OverlayNetworkImplementationTypeFabric
					if poolName == string(v1alpha1.VNIResourcePool) {
						rg.Status.FabricNetworkConfiguration = &v1alpha12.FabricNetworkConfiguration{
							VNI: uint32(val),
						}
					} else if poolName == string(v1alpha1.VlanIDResourcePool) {
						rg.Status.FabricNetworkConfiguration = &v1alpha12.FabricNetworkConfiguration{
							VlanID: uint32(val),
						}
					}
					err := k8sClient.Create(context.Background(), rg)
					Expect(err).ToNot(HaveOccurred())
					err = k8sClient.Status().Update(context.Background(), rg)
					Expect(err).ToNot(HaveOccurred())
				}
			}
			err = intPool.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			Expect(intPool.Available()).To(BeZero(), "Reconciled all resources")

			By("Update resource pool")
			intRanges = generateIntegerRage(cnt, 1, uint64(^uint16(0)))
			intPool.Update(intRanges)
			Expect(intPool.Available()).To(Equal(uint64(cnt)), "Update resource pool")

			err = mgr.Delete(poolName)
			Expect(err).ToNot(HaveOccurred())
		},
		table.Entry("VNI pool", string(v1alpha1.VNIResourcePool)),
		table.Entry("Vlan pool", string(v1alpha1.VlanIDResourcePool)),
		table.Entry("NetworkPolicyID pool", resourcepool.RuntimePoolNetworkPolicyIDPool))
})
