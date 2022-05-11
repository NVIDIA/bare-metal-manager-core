package networkfabric_test

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/testing"
)

var _ = Describe("Networkfabric", func() {
	const (
		rgName      = "test-rg"
		rgNamespace = "default"
		tenantID    = "test-tenant"
		mrName      = "test-mr"
		torName     = "test-tor"
		resourceID  = "test-identifier"
	)

	var (
		mockController *gomock.Controller
		mockVPCMgr     *testing.MockVPCManager
		rg             *resource.ResourceGroup
		rgKey          client.ObjectKey
		mr             *resource.ManagedResource
		mrKey          client.ObjectKey
		torKey         client.ObjectKey
		tor            *networkfabric.Leaf
		torKnown       bool
	)

	BeforeEach(func() {
		mockController = gomock.NewController(GinkgoT())
		mockVPCMgr = testing.NewMockVPCManager(mockController)
		rgReconciler.VPCMgr = mockVPCMgr
		mrReconciler.VPCMgr = mockVPCMgr
		torReconciler.VPCMgr = mockVPCMgr
		rgKey = client.ObjectKey{
			Namespace: rgNamespace,
			Name:      rgName,
		}
		rg = &resource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rgName,
				Namespace: rgNamespace,
			},
			Spec: resource.ResourceGroupSpec{
				TenantIdentifier: tenantID,
				Network: &resource.IPNet{
					IP:           "10.10.10.0",
					PrefixLength: 24,
					Gateway:      "10.10.10.1",
				},
				DHCPServer:                "20.20.20.1",
				NetworkImplementationType: resource.OverlayNetworkImplementationTypeFabric,
			},
		}
		mrKey = client.ObjectKey{
			Namespace: rgNamespace,
			Name:      mrName,
		}
		mr = &resource.ManagedResource{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mrName,
				Namespace: rgNamespace,
			},
			Spec: resource.ManagedResourceSpec{
				ResourceGroup:       rgName,
				Type:                resource.ResourceTypeBareMetal,
				State:               resource.ManagedResourceStateUp,
				HostInterfaceIP:     "10.10.10.5",
				HostInterfaceMAC:    "00:01:02:03:04:05",
				DPUIPs:              []resource.IPAddress{"192.2.1.3, 192.2.1.4, 192.2.1.5"},
				HostInterfaceAccess: resource.HostAccessFabric,
				HostInterface:       resourceID,
			},
		}
		torKey = client.ObjectKey{
			Namespace: rgNamespace,
			Name:      torName,
		}
		tor = &networkfabric.Leaf{
			ObjectMeta: metav1.ObjectMeta{
				Name:      torName,
				Namespace: rgNamespace,
			},
			Spec: networkfabric.LeafSpec{
				Control: networkfabric.NetworkDeviceControl{
					Vendor:          "Cumulus",
					ManagementIP:    "50.50.50.2",
					MaintenanceMode: false,
				},
				HostInterfaces: map[string]string{resourceID: "swp1"},
			},
		}
		torKnown = false
	})

	AfterEach(func() {
		torKnown = true
		err := k8sClient.Delete(context.Background(), rg)
		Expect(client.IgnoreNotFound(err)).ToNot(HaveOccurred())
		Eventually(func() error {
			err = k8sClient.Get(context.Background(), rgKey, rg)
			if err == nil {
				return fmt.Errorf("rg still present")
			}
			return client.IgnoreNotFound(err)
		}, 10, 1).Should(BeNil())
		err = k8sClient.Get(context.Background(), mrKey, mr)
		Expect(errors.IsNotFound(err)).To(BeTrue())

		err = k8sClient.Delete(context.Background(), tor)
		Expect(client.IgnoreNotFound(err)).ToNot(HaveOccurred())
		Eventually(func() error {
			err := k8sClient.Get(context.Background(), torKey, tor)
			if err == nil {
				return fmt.Errorf("tor still present")
			}
			return client.IgnoreNotFound(err)
		}, 10, 1).Should(BeNil())
		mockController.Finish()
	})

	setTORMaint := func(maint bool) {
		err := k8sClient.Get(context.Background(), torKey, tor)
		Expect(err).ToNot(HaveOccurred())
		torKnown = !maint
		tor.Spec.Control.MaintenanceMode = maint
		err = k8sClient.Update(context.Background(), tor)
		Expect(err).ToNot(HaveOccurred())
	}

	setExpectations := func(torErr error) {
		mockVPCMgr.EXPECT().CreateOrUpdateOverlayNetwork(gomock.Any(), rgName).MinTimes(1).Return(nil)
		mockVPCMgr.EXPECT().GetOverlayNetworkProperties(gomock.Any(), rgName).MinTimes(1).
			Return(&properties.OverlayNetworkProperties{}, nil)
		mockVPCMgr.EXPECT().CreateOrUpdateNetworkDevice(gomock.Any(), reflect.TypeOf(tor).Elem().Name(), tor.Name).
			AnyTimes().Return(nil)
		mockVPCMgr.EXPECT().GetNetworkDeviceProperties(gomock.Any(), reflect.TypeOf(tor).Elem().Name(), tor.Name).
			AnyTimes().Return(&properties.NetworkDeviceProperties{}, nil)
		mockVPCMgr.EXPECT().RemoveNetworkDevice(gomock.Any(), reflect.TypeOf(tor).Elem().Name(), tor.Name).Return(nil)

		mockVPCMgr.EXPECT().AddOrUpdateResourceToNetwork(gomock.Any(), mrName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				if !torKnown {
					return torErr
				}
				return nil
			})
		mockVPCMgr.EXPECT().GetResourceProperties(gomock.Any(), mrName).MinTimes(1).
			Return(&properties.ResourceProperties{}, nil)
		mockVPCMgr.EXPECT().RemoveResourceToNetwork(gomock.Any(), mrName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				if !torKnown {
					return torErr
				}
				return nil
			})
		mockVPCMgr.EXPECT().DeleteOverlayNetwork(gomock.Any(), rgName).Return(nil)
	}

	checkMr := func(status corev1.ConditionStatus, msg string) error {
		mr := &resource.ManagedResource{}
		if err := k8sClient.Get(context.Background(), mrKey, mr); err != nil {
			return err
		}
		clen := len(mr.Status.Conditions)
		if clen != 1 {
			return fmt.Errorf("incorrect numbers of conditions, %d", clen)
		}
		if mr.Status.Conditions[0].Status != status || mr.Status.Conditions[0].Message != msg {
			return fmt.Errorf("waiting for condition ready")
		}
		return nil
	}

	checkMrDelete := func(msg string) error {
		mr := &resource.ManagedResource{}
		if err := k8sClient.Get(context.Background(), mrKey, mr); err != nil {
			if len(msg) == 0 {
				return client.IgnoreNotFound(err)
			}
		}
		if len(mr.Status.Conditions) != 2 || mr.Status.Conditions[1].Message != msg {
			return fmt.Errorf("waiting for conditions")
		}
		return nil
	}

	It("Leaf added before ManagedResource creation", func() {
		setExpectations(nil)
		err := k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		torKnown = true
		err = k8sClient.Create(context.Background(), tor)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMr(corev1.ConditionTrue, "")
		}, 10, 1).Should(BeNil())
	})

	PIt("Disable obsolete test: Leaf added after ManagedResource creation", func() {
		torErr := vpc.NewNetworkDeviceNotAvailableError(reflect.TypeOf(tor).Elem().Name(), tor.Name)
		setExpectations(torErr)
		err := k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMr(corev1.ConditionFalse, torErr.Error())
		}, 10, 1).Should(BeNil())
		time.Sleep(time.Second * 1)
		torKnown = true
		err = k8sClient.Create(context.Background(), tor)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMr(corev1.ConditionTrue, "")
		}, 10, 1).Should(BeNil())
	})

	PIt("Disable obsolete test: Leaf in maintenance", func() {
		torErr := vpc.NewNewNetworkDeviceInMaintenanceError(reflect.TypeOf(tor).Elem().Name(), tor.Name)
		setExpectations(torErr)
		tor.Spec.Control.MaintenanceMode = true
		err := k8sClient.Create(context.Background(), tor)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMr(corev1.ConditionFalse, torErr.Error())
		}, 10, 1).Should(BeNil())
		setTORMaint(false)
		Eventually(func() error {
			return checkMr(corev1.ConditionTrue, "")
		}, 10, 1).Should(BeNil())

		// Delete
		setTORMaint(true)
		err = k8sClient.Delete(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			return checkMrDelete(torErr.Error())
		}, 10, 1).Should(BeNil())
		setTORMaint(false)
		Eventually(func() error {
			return checkMrDelete("")
		}, 10, 1).Should(BeNil())
	})
})
