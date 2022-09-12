package resource_test

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	vpcresource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/testing"
)

var _ = Describe("ResourceGroup", func() {
	const (
		rgName      = "test-rg"
		rgNamespace = "default"
		tenantID    = "test-tenant"
		mrName      = "test-mr"
	)

	var (
		mockController     *gomock.Controller
		mockVPCMgr         *testing.MockVPCManager
		rg                 *vpcresource.ResourceGroup
		rgKey              client.ObjectKey
		rgCond             vpcresource.ResourceGroupCondition
		networkProperties  *properties.OverlayNetworkProperties
		mr                 *vpcresource.ManagedResource
		mrKey              client.ObjectKey
		mrCond             vpcresource.ManagedResourceCondition
		resourceProperties *properties.ResourceProperties
		getErrCnt          int
		setErrCnt          int
		deleteErrCnt       int
		managedResourceCnt int64
	)

	BeforeEach(func() {
		mockController = gomock.NewController(GinkgoT())
		mockVPCMgr = testing.NewMockVPCManager(mockController)
		rgReconciler.VPCMgr = mockVPCMgr
		mrReconciler.VPCMgr = mockVPCMgr
		rgKey = client.ObjectKey{
			Namespace: rgNamespace,
			Name:      rgName,
		}
		rg = &vpcresource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rgName,
				Namespace: rgNamespace,
			},
			Spec: vpcresource.ResourceGroupSpec{
				TenantIdentifier: tenantID,
				Network: &vpcresource.IPNet{
					IP:           "10.10.10.0",
					PrefixLength: 24,
					Gateway:      "10.10.10.1",
				},
				DHCPServer:                "20.20.20.1",
				NetworkImplementationType: vpcresource.OverlayNetworkImplementationTypeFabric,
			},
		}
		rgCond = vpcresource.ResourceGroupCondition{
			Type:   vpcresource.ResourceGroupConditionTypeCreate,
			Status: corev1.ConditionTrue,
		}
		networkProperties = &properties.OverlayNetworkProperties{
			FabricConfig: &vpcresource.FabricNetworkConfiguration{
				VRF: "test-vrf",
				VNI: 5000,
			},
			DHCPCircID: "vlan10",
			Network: &vpcresource.IPNet{
				IP:           "10.10.10.0",
				PrefixLength: 24,
				Gateway:      "10.10.10.1",
			},
		}
		mrKey = client.ObjectKey{
			Namespace: rgNamespace,
			Name:      mrName,
		}
		mr = &vpcresource.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mrName,
				Namespace: rgNamespace,
			},
			Spec: vpcresource.ManagedResourceSpec{
				ResourceGroup:       rgName,
				Type:                vpcresource.ResourceTypeBareMetal,
				State:               vpcresource.ManagedResourceStateUp,
				HostInterfaceIP:     "10.10.10.5",
				HostInterfaceMAC:    "00:01:02:03:04:05",
				DPUIPs:              []vpcresource.IPAddress{"192.2.1.3, 192.2.1.4, 192.2.1.5"},
				HostInterfaceAccess: vpcresource.HostAccessFabric,
				HostInterface:       "test-id",
			},
		}
		mrCond = vpcresource.ManagedResourceCondition{
			Type:   vpcresource.ManagedResourceConditionTypeAdd,
			Status: corev1.ConditionTrue,
		}
		resourceProperties = &properties.ResourceProperties{
			HostAccessIPs: &vpcresource.IPAssociation{
				HostIP:   "10.10.10.5",
				FabricIP: "192.2.1.3",
			},
		}
		getErrCnt = 0
		setErrCnt = 0
		deleteErrCnt = 0
		managedResourceCnt = 0
	})

	AfterEach(func() {
		err := k8sClient.Get(context.Background(), rgKey, rg)
		Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
		if err == nil {
			mockVPCMgr.EXPECT().DeleteOverlayNetwork(gomock.Any(), rgName).MinTimes(1).Return(nil)
			err = k8sClient.Delete(context.Background(), rg)
			Expect(err).ToNot(HaveOccurred())
			Eventually(func() error {
				err := k8sClient.Get(context.Background(), rgKey, rg)
				if err == nil {
					return fmt.Errorf("still present")
				}
				return client.IgnoreNotFound(err)
			}, 10, 1).Should(BeNil())
		}
		err = k8sClient.Get(context.Background(), mrKey, mr)
		Expect(errors.IsNotFound(err)).To(BeTrue())
		mockController.Finish()
	})

	checkRg := func(spec *vpcresource.ResourceGroupSpec) error {
		rg := &vpcresource.ResourceGroup{}
		if err := k8sClient.Get(context.Background(), rgKey, rg); err != nil {
			return err
		}
		if !reflect.DeepEqual(&rg.Spec, spec) {
			return fmt.Errorf("waiting for updates")
		}
		if !controllerutil.ContainsFinalizer(rg, vpcresource.ResourceGroupFinalizer) {
			return fmt.Errorf("missing finalizer")
		}
		clen := len(rg.Status.Conditions)
		if clen != 1 {
			return fmt.Errorf("incorrect numbers of conditions, %d", clen)
		}
		if rg.Status.Conditions[0].Status != corev1.ConditionTrue {
			return fmt.Errorf("waiting for condition ready")
		}
		rgCond.LastTransitionTime = rg.Status.Conditions[0].LastTransitionTime
		Expect(rg.Status.Conditions[0]).To(Equal(rgCond))
		Expect(rg.Status.SoftwareNetworkConfiguration).To(BeNil())
		Expect(rg.Status.FabricNetworkConfiguration).To(Equal(networkProperties.FabricConfig))
		Expect(rg.Status.ManagedResourceCount).To(Equal(managedResourceCnt))
		Expect(rg.Status.DHCPCircID).To(Equal(networkProperties.DHCPCircID))
		Expect(rg.Status.Network).To(Equal(networkProperties.Network))
		Expect(rg.Status.SNATIPs).To(BeNil())
		return nil
	}

	setRgExpectations := func() {
		mockVPCMgr.EXPECT().CreateOrUpdateOverlayNetwork(gomock.Any(), rgName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				if setErrCnt == 0 {
					return nil
				}
				setErrCnt--
				return fmt.Errorf("transit error")
			})
		mockVPCMgr.EXPECT().GetOverlayNetworkProperties(gomock.Any(), rgName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) (*properties.OverlayNetworkProperties, error) {
				if getErrCnt == 0 {
					return networkProperties, nil
				}
				getErrCnt--
				return nil, fmt.Errorf("transit error")
			})
	}

	testRgCreate := func() {
		setRgExpectations()
		err := k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkRg(&rg.Spec)
		}, 10, 1).Should(BeNil())
	}

	testRgUpdate := func() {
		setRgExpectations()
		err := k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(time.Second * 2)
		err = k8sClient.Get(context.Background(), rgKey, rg)
		Expect(err).ToNot(HaveOccurred())
		rg.Spec.DHCPServer = "30.30.30.30"
		err = k8sClient.Update(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkRg(&rg.Spec)
		}, 10, 1).Should(BeNil())
	}

	checkMr := func(spec *vpcresource.ManagedResourceSpec, checkReady bool) error {
		mr := &vpcresource.ManagedResource{}
		if err := k8sClient.Get(context.Background(), mrKey, mr); err != nil {
			return err
		}
		if !reflect.DeepEqual(&mr.Spec, spec) {
			return fmt.Errorf("waiting for updates")
		}
		if !controllerutil.ContainsFinalizer(mr, vpcresource.ManagedResourceFinalizer) {
			return fmt.Errorf("missing finalizer")
		}
		clen := len(mr.Status.Conditions)
		if clen != 1 {
			return fmt.Errorf("incorrect numbers of conditions, %d", clen)
		}
		if !checkReady {
			return nil
		}
		if mr.Status.Conditions[0].Status != corev1.ConditionTrue {
			return fmt.Errorf("waiting for condition ready")
		}
		mrCond.LastTransitionTime = mr.Status.Conditions[0].LastTransitionTime
		Expect(mr.Status.Conditions[0]).To(Equal(mrCond))
		Expect(mr.Status.HostAccessIPs).To(Equal(resourceProperties.HostAccessIPs))
		return nil
	}

	setMrExpectations := func() {
		mockVPCMgr.EXPECT().AddOrUpdateResourceToNetwork(gomock.Any(), mrName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				if setErrCnt == 0 {
					return nil
				}
				setErrCnt--
				return fmt.Errorf("transit error")
			})
		mockVPCMgr.EXPECT().GetResourceProperties(gomock.Any(), mrName).AnyTimes().DoAndReturn(
			func(_ context.Context, _ string) (*properties.ResourceProperties, error) {
				if getErrCnt == 0 {
					return resourceProperties, nil
				}
				getErrCnt--
				return nil, fmt.Errorf("transit error")
			})
		mockVPCMgr.EXPECT().RemoveResourceToNetwork(gomock.Any(), mrName).MinTimes(1 + deleteErrCnt).DoAndReturn(
			func(_ context.Context, _ string) error {
				if deleteErrCnt == 0 {
					return nil
				}
				deleteErrCnt--
				return fmt.Errorf("transit error")
			})
	}

	testMrCreate := func(checkReady bool) {
		setMrExpectations()
		err := k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMr(&mr.Spec, checkReady)
		}, 10, 1).Should(BeNil())
	}

	testMrDelete := func() {
		mr := &vpcresource.ManagedResource{}
		err := k8sClient.Get(context.Background(), mrKey, mr)
		Expect(err).NotTo(HaveOccurred())
		err = k8sClient.Delete(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			err := k8sClient.Get(context.Background(), mrKey, mr)
			if err == nil {
				return fmt.Errorf("still present")
			}
			return client.IgnoreNotFound(err)
		}, 10, 1).Should(BeNil())
	}

	Context("Normal", func() {
		It("Create ResourceGroup", func() {
			testRgCreate()
		})
		It("Update ResourceGroup", func() {
			testRgUpdate()
		})
		It("Add ManagedResource prior to ResourceGroup", func() {
			testMrCreate(false)
			managedResourceCnt = 1
			testRgCreate()
			Eventually(func() error {
				return checkMr(&mr.Spec, true)
			}, 10, 1).Should(BeNil())
			testMrDelete()
		})

		It("Add ManagedResource after ResourceGroup with auto-delete", func() {
			testRgCreate()
			managedResourceCnt = 1
			testMrCreate(false)
		})

	})

	Context("With backend error", func() {
		JustBeforeEach(func() {
			getErrCnt = 1
			setErrCnt = 1
			deleteErrCnt = 1
		})
		It("Create ResourceGroup", func() {
			testRgCreate()
		})
		It("Update ResourceGroup", func() {
			testRgUpdate()
		})

		It("Add ManagedResource after ResourceGroup with auto-delete", func() {
			testRgCreate()
			managedResourceCnt = 1
			testMrCreate(false)
		})

	})
})
