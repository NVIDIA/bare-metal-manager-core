package v1alpha1_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

var _ = Describe("ManagedResource", func() {
	var (
		mr *resource.ManagedResource
	)

	BeforeEach(func() {
		mr = &resource.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name: "testManagedResource",
			},
			Spec: resource.ManagedResourceSpec{
				ResourceGroup:       "testResourceGroup",
				Type:                resource.ResourceTypeBareMetal,
				State:               "",
				HostInterfaceIP:     "10.10.10.1",
				HostInterfaceMAC:    "00:01:02:03:04:05",
				DPUIPs:              []resource.IPAddress{"1.1.1.1", "1.1.1.2"},
				HostInterfaceAccess: resource.HostAccessIsolated,
			},
		}
	})
	createTest := func(mr *resource.ManagedResource, expErr bool) {
		mr.Default()
		err := mr.ValidateCreate()
		if expErr {
			log.Log.Info("", "Error", err)
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	}

	updateTest := func(orig, update *resource.ManagedResource, expErr bool) {
		update.Default()
		orig.Default()
		err := update.ValidateUpdate(orig)
		if expErr {
			log.Log.Info("", "Error", err)
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	}

	It("Valid create", func() {
		createTest(mr, false)
	})

	It("Valid update: changing access mode", func() {
		update := mr.DeepCopy()
		update.Spec.HostInterfaceAccess = resource.HostAccessFabric
		updateTest(mr, update, false)
	})

	It("Valid update: Changing identifier", func() {
		update := mr.DeepCopy()
		update.Spec.HostInterface = "other"
		updateTest(mr, update, false)
	})

	It("Invalid create: Type", func() {
		mr.Spec.Type = "other"
		createTest(mr, true)
	})

	It("Invalid create: HostInterfaceIP", func() {
		mr.Spec.HostInterfaceIP = "nonip"
		createTest(mr, true)
	})

	It("Invalid create: HostInterfaceMAC", func() {
		mr.Spec.HostInterfaceMAC = "nonmac"
		createTest(mr, true)
	})

	It("Invalid create: DPUIPs", func() {
		mr.Spec.DPUIPs[0] = "nonip"
		createTest(mr, true)
	})

	It("Invalid create: HostInterfaceAccess", func() {
		mr.Spec.HostInterfaceAccess = "noaccess"
		createTest(mr, true)
	})

	It("Invalid update: Changing type", func() {
		update := mr.DeepCopy()
		update.Spec.Type = resource.ResourceTypeStorage
		updateTest(mr, update, true)
	})

	It("Invalid update: Changing hostMAC", func() {
		update := mr.DeepCopy()
		update.Spec.HostInterfaceMAC = "00:00:00:11:11:12"
		updateTest(mr, update, true)
	})

	It("Invalid update: Changing resourceGroup", func() {
		update := mr.DeepCopy()
		update.Spec.ResourceGroup = "other"
		updateTest(mr, update, true)
	})
})
