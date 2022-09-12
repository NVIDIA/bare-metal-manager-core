package v1alpha1_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
)

var _ = Describe("Resourcepool", func() {
	DescribeTable("Resource pool",
		func(poolName v1alpha1.WellKnownConfigurationResourcePool,
			rangeType v1alpha1.PoolRangeType,
			start, end string, blkSizeBit int, expectErr bool) {
			pool := &v1alpha1.ConfigurationResourcePool{}
			pool.Name = string(poolName)
			pool.Spec.Type = rangeType
			if len(start)+len(end) > 0 {
				pool.Spec.Ranges = []v1alpha1.PoolRange{
					{start, end},
				}
			}
			pool.Spec.AllocationBlockSize = int32(blkSizeBit)
			err := pool.ValidateCreate()
			if expectErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).ToNot(HaveOccurred())
				err = pool.ValidateUpdate(pool)
				Expect(err).ToNot(HaveOccurred())
			}
		},
		Entry("Overlay IP", v1alpha1.OverlayIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"10.10.0.0", "10.20.0.0", 8, false),
		Entry("Public IP", v1alpha1.PublicIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"2.10.1.5", "10.20.2.5", 0, false),
		Entry("Datacenter IP", v1alpha1.DatacenterIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"2.10.0.0", "10.20.0.0", 0, false),
		Entry("Overlay IP missing range", v1alpha1.OverlayIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"", "", 0, true),
		Entry("Overlay IP un-supported block size", v1alpha1.OverlayIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"10.10.0.0", "10.20.0.0", 10, true),
		Entry("Public IP missing partial range", v1alpha1.PublicIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"2.10.1.5", "", 0, true),
		Entry("Datacenter IP out of order", v1alpha1.DatacenterIPv4ResourcePool, v1alpha1.RangeTypeIPv4,
			"12.10.0.0", "10.20.0.0", 0, true),
		Entry("Overlay IP not IP", v1alpha1.OverlayIPv4ResourcePool, v1alpha1.RangeTypeIPv4, "1", "10", 0, true),
		Entry("Vlan ID", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"100", "200", 0, false),
		Entry("VNI", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"11100", "12200", 0, false),
		Entry("Vlan ID missing range", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"", "", 0, true),
		Entry("VNI missing partial range", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"", "12200", 0, true),
		Entry("Vlan ID range out of order", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"100", "10", 0, true),
		Entry("VNI not integer", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeInteger,
			"ba", "cd", 0, true),
		Entry("Mismatch IP pool type", v1alpha1.OverlayIPv4ResourcePool, v1alpha1.RangeTypeInteger,
			"100", "200", 0, true),
		Entry("Mismatch integer pool type", v1alpha1.VlanIDResourcePool, v1alpha1.RangeTypeIPv4,
			"10.1.1.1", "10.1.1.2", 0, true),
	)
})
