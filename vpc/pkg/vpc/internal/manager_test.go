package internal_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Manager", func() {
	BeforeEach(func() {
		initResources()
		startManager()
	})
	AfterEach(func() {
		stopManager()
		err := k8sClient.Delete(context.Background(), mr)
		Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
	})

	It("Event processing", func() {
		err := k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		key := client.ObjectKey{
			Namespace: namespace,
			Name:      mrName,
		}
		vpcManager.AddEvent("ManagedResource", key)
		i := <-vpcManager.GetEvent("ManagedResource")
		Expect(i).To(Equal(key))
	})
})
