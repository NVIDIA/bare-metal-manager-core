package internal_test

import (
	"context"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
)

var _ = Describe("Manager", func() {
	const (
		rgName = "test-rg"
		mrName = "test-mr"
	)

	var (
		mr             *resource.ManagedResource
		manager        vpc.VPCManager
		mockController *gomock.Controller
		ctx            context.Context
		ctxCancel      context.CancelFunc
	)
	BeforeEach(func() {

		mr = &resource.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mrName,
				Namespace: namespace,
			},
			Spec: resource.ManagedResourceSpec{
				ResourceGroup:       rgName,
				Type:                resource.ResourceTypeBareMetal,
				State:               resource.ManagedResourceStateUp,
				HostInterfaceIP:     "10.10.10.5",
				HostInterfaceMAC:    "00:01:02:03:04:05",
				DPUIPs:              []resource.IPAddress{"127.0.0.1", "127.0.0.8"},
				HostInterfaceAccess: resource.HostAccessFabric,
				HostInterface:       "test-mr-mac",
			},
		}
		mockController = gomock.NewController(GinkgoT())
		manager = vpc.NewVPCManager(k8sClient, nil, namespace, nil)
		ctx, ctxCancel = context.WithCancel(context.Background())
		go func() { _ = manager.Start(ctx) }()
	})
	AfterEach(func() {
		mockController.Finish()
		ctxCancel()
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
		manager.AddEvent("ManagedResource", key)
		i := <-manager.GetEvent("ManagedResource")
		Expect(i).To(Equal(key))
	})
})
