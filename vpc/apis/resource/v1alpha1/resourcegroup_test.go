package v1alpha1_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

var _ = Describe("ResourceGroup", func() {
	var (
		rg *resource.ResourceGroup
	)

	BeforeEach(func() {
		rg = &resource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testResourceGroup",
			},
			Spec: resource.ResourceGroupSpec{
				TenantIdentifier: "tenantID",
				Network: &resource.IPNet{
					IP:           "1.1.1.0",
					PrefixLength: 24,
					Gateway:      "1.1.1.1",
				},
				DHCPServer:                "2.2.2.2",
				NetworkImplementationType: resource.OverlayNetworkImplementationTypeFabric,
			},
		}
	})

	createTest := func(rg *resource.ResourceGroup, expErr bool) {
		rg.Default()
		err := rg.ValidateCreate()
		if expErr {
			log.Log.Info("", "Error", err)
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	}

	updateTest := func(orig, update *resource.ResourceGroup, expErr bool) {
		update.Default()
		err := update.ValidateUpdate(orig)
		if expErr {
			log.Log.Info("", "Error", err)
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	}

	It("Valid create", func() {
		createTest(rg, false)
	})

	It("Valid create with overlay IP", func() {
		rg.Spec.Network = nil
		rg.Spec.OverlayIPPool = string(v1alpha1.OverlayIPv4ResourcePool)
		createTest(rg, false)
	})

	It("Valid update", func() {
		update := rg.DeepCopy()
		update.Spec.DHCPServer = "3.3.3.3"
		updateTest(update, rg, false)
	})

	It("Invalid create: Missing tenant", func() {
		rg.Spec.TenantIdentifier = ""
		createTest(rg, true)
	})

	It("Invalid update:  Changing tenant", func() {
		update := rg.DeepCopy()
		update.Spec.TenantIdentifier = "another"
		updateTest(rg, update, true)
	})

	It("Invalid create: Unknown type", func() {
		rg.Spec.NetworkImplementationType = "unknown"
		createTest(rg, true)
	})

	It("Invalid create: Type mismatch", func() {
		rg.Spec.NetworkImplementationType = resource.OverlayNetworkImplementationTypeSoftware
		rg.Spec.Network = nil
		createTest(rg, true)
	})

	It("Invalid update: Change type", func() {
		update := rg.DeepCopy()
		update.Spec.NetworkImplementationType = resource.OverlayNetworkImplementationTypeSoftware
		updateTest(rg, update, true)
	})

	It("Invalid create: Network mismatch", func() {
		rg.Spec.DHCPServer = ""
		createTest(rg, true)
	})

	It("Invalid create: Network IP", func() {
		rg.Spec.Network.IP = ""
		createTest(rg, true)
	})

	It("Invalid create: Network prefixLen", func() {
		rg.Spec.Network.PrefixLength = 65
		createTest(rg, true)
	})

	It("Invalid create: Missing Network or Overlay IP pool", func() {
		rg.Spec.Network = nil
		createTest(rg, true)
	})

	It("Invalid update: Changing overlay IP pool", func() {
		rg.Spec.OverlayIPPool = "one thing"
		update := rg.DeepCopy()
		update.Spec.OverlayIPPool = "another"
		updateTest(rg, update, true)
	})
})
