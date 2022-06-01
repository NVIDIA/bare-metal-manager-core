package internal_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal/testing"
)

var _ = Describe("fabric", func() {
	const (
		rgName   = "test-rg"
		mrName   = "test-mr"
		tenantID = "test-tenant"
	)

	var (
		mockController       *gomock.Controller
		manager              vpc.VPCManager
		resourceManager      *resourcepool.Manager
		rg                   *resource.ResourceGroup
		adminRg              *resource.ResourceGroup
		mockCumulusTransport *testing.MockNetworkDeviceTransport
		mr                   *resource.ManagedResource
		leaf                 *networkfabric.Leaf
		ctx                  context.Context
		ctxCancel            context.CancelFunc

		vniRange       = []uint64{10000, 12000}
		vniPool        *resourcepool.IntegerPool
		vlanRange      = []uint64{1000, 2000}
		vlanPool       *resourcepool.IntegerPool
		fabricIPRange  = []string{"22.3.4.0", "22.3.5.0"}
		fabricIPPool   *resourcepool.IPv4BlockPool
		overlayIPRange = []string{"10.0.0.0", "11.0.0.0"}
		overlayIPPool  *resourcepool.IPv4BlockPool
	)

	BeforeEach(func() {
		mockController = gomock.NewController(GinkgoT())
		mockCumulusTransport = testing.NewMockNetworkDeviceTransport(mockController)
		resourceManager = resourcepool.NewManager(k8sClient, namespace)
		manager = vpc.NewVPCManager(k8sClient, nil, namespace, resourceManager)
		ctx, ctxCancel = context.WithCancel(context.Background())
		go func() { _ = manager.Start(ctx) }()
		rg = &resource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rgName,
				Namespace: namespace,
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
		adminRg = &resource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      resource.WellKnownAdminResourceGroup,
				Namespace: namespace,
			},
			Spec: resource.ResourceGroupSpec{
				TenantIdentifier: "test-",
				Network: &resource.IPNet{
					IP:           "30.30.30.0",
					PrefixLength: 24,
					Gateway:      "30.30.30.1",
				},
				DHCPServer:                "20.20.20.1",
				NetworkImplementationType: resource.OverlayNetworkImplementationTypeFabric,
			},
		}
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
				DPUIPs:              []resource.IPAddress{"192.2.1.3", "192.2.1.4", "192.2.1.5"},
				HostInterfaceAccess: resource.HostAccessFabricDirect,
				HostInterface:       "01:02:03:04:05",
			},
		}
		leaf = &networkfabric.Leaf{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "hbn-1",
				Namespace: namespace,
			},
			Spec: networkfabric.LeafSpec{
				Control: networkfabric.NetworkDeviceControl{
					Vendor:          "Cumulus",
					ManagementIP:    "40.40.40.1",
					MaintenanceMode: false,
				},
				HostInterfaces: map[string]string{"01:02:03:04:05": "swp1"},
				HostAdminIPs:   map[string]string{"swp1": ""},
			},
		}
	})

	AfterEach(func() {
		mockController.Finish()
		ctxCancel()
		err := k8sClient.Delete(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), adminRg)
		Expect(client.IgnoreNotFound(err)).ToNot(HaveOccurred())
	})

	validateNetworkProperties := func(prop *properties.OverlayNetworkProperties, spec *resource.ResourceGroupSpec) {
		Expect(prop.Network).ToNot(BeNil(), "Properties has network")
		if len(spec.OverlayIPPool) > 0 {
			Expect(prop.Network.PrefixLength).To(Equal(overlayIPPool.PrefixLen), "Auto network match IP prefix")
			Expect(overlayIPPool.Allocated(prop.Network.IP)).To(BeTrue(), "Auto network match subnet")
			Expect(overlayIPPool.Allocated(prop.Network.Gateway)).To(BeTrue(), "Auto network match gateway")
		} else {
			Expect(prop.Network.PrefixLength).To(Equal(spec.Network.PrefixLength), "Network match IP prefix")
			Expect(prop.Network.IP).To(Equal(spec.Network.IP), "Network match subnet")
			Expect(prop.Network.Gateway).To(Equal(spec.Network.Gateway), "Network match gateway")
		}
		Expect(prop.FabricConfig).ToNot(BeNil(), "Properties has fabric configuration")
		Expect(vlanPool.Allocated(prop.FabricConfig.VlanID)).To(BeTrue(), "Vlan is allocated")
		Expect(vniPool.Allocated(prop.FabricConfig.VNI)).To(BeTrue(), "Vni is allocated")
		Expect(prop.DHCPCircID).To(Equal(internal.GetVlanInterfaceFromID(prop.FabricConfig.VlanID)))
	}

	validateResourceProperties := func(prop *properties.ResourceProperties, spec *resource.ManagedResourceSpec,
		configState string) {
		Expect(prop.FabricReference.Kind).To(Equal(networkfabric.LeafName), "Fabric reference matches")
		Expect(prop.FabricReference.Name).To(Equal(leaf.Name))
		Expect(prop.FabricReference.Port).To(Equal(leaf.Spec.HostInterfaces[spec.HostInterface]))
		Expect(prop.FabricReference.ConfigurationState).To(Equal(configState))

		Expect(prop.HostAccessIPs.HostIP).To(Equal(spec.HostInterfaceIP))
		if spec.HostInterfaceAccess != resource.HostAccessIsolated && spec.HostInterfaceAccess != resource.HostAccessFabricDirect {
			Expect(fabricIPPool.Allocated(prop.HostAccessIPs.FabricIP)).To(BeTrue(), "Fabric IP is allocated")
		} else if spec.HostInterfaceAccess == resource.HostAccessIsolated {
			Expect(prop.HostAccessIPs.FabricIP).To(BeEmpty(), "No fabric IP assigned for isolated host")
		}
	}

	validateFreedNetworkProperties := func(prop *properties.OverlayNetworkProperties) {
		if vlanPool != nil {
			Expect(vlanPool.Allocated(prop.FabricConfig.VlanID)).To(BeFalse(), "Vlan is freed")
		}
		if vniPool != nil {
			Expect(vniPool.Allocated(prop.FabricConfig.VNI)).To(BeFalse(), "Vni is freed")
		}
		if overlayIPPool != nil {
			Expect(overlayIPPool.Allocated(prop.Network.IP)).To(BeFalse(), "Overlay IP is freed")
			Expect(overlayIPPool.Allocated(prop.Network.Gateway)).To(BeFalse(), "Overlay IP gatewayis freed")
		}
	}

	validateFreedResourceProperties := func(prop *properties.ResourceProperties) {
		if fabricIPPool != nil {
			Expect(fabricIPPool.Allocated(prop.HostAccessIPs.FabricIP)).To(BeFalse())
		}
	}

	testResourceGroup := func(vni, vlan, fabricIP, remove bool, expErr error) {
		// prepare resource pools.
		if vni {
			vniPool = resourceManager.CreateIntegerPool(networkfabric.VNIResourcePool, [][]uint64{vniRange})
			_ = vniPool.Reconcile()
		}
		if vlan {
			vlanPool = resourceManager.CreateIntegerPool(networkfabric.VlanIDResourcePool, [][]uint64{vlanRange})
			_ = vlanPool.Reconcile()
		}
		if len(rg.Spec.OverlayIPPool) > 0 {
			overlayIPPool = resourceManager.CreateIPv4Pool(
				networkfabric.WellKnownConfigurationResourcePool(rg.Spec.OverlayIPPool), [][]string{overlayIPRange}, 8)
			err := overlayIPPool.Reconcile()
			Expect(err).ToNot(HaveOccurred())
		}

		if fabricIP {
			fabricIPPool = resourceManager.CreateIPv4Pool(networkfabric.DatacenterIPv4ResourcePool,
				[][]string{fabricIPRange}, 0)
			_ = fabricIPPool.Reconcile()
			rg.Spec.FabricIPPool = string(networkfabric.DatacenterIPv4ResourcePool)
		}

		var err error
		if vni && vlan {
			err = k8sClient.Create(context.Background(), adminRg)
			Expect(err).ToNot(HaveOccurred())
			err = manager.CreateOrUpdateOverlayNetwork(context.Background(), adminRg.Name)
			Expect(err).ToNot(HaveOccurred())
		}
		// Create resource group
		err = k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		retErr := manager.CreateOrUpdateOverlayNetwork(context.Background(), rg.Name)
		if expErr == nil {
			Expect(retErr).To(BeNil())
		} else {
			Expect(retErr).To(Equal(expErr))
		}
		var networkProp *properties.OverlayNetworkProperties
		if retErr == nil {
			networkProp, err = manager.GetOverlayNetworkProperties(context.Background(), rg.Name)
			Expect(err).ShouldNot(HaveOccurred())
			validateNetworkProperties(networkProp, &rg.Spec)
		}
		if !remove {
			return
		}

		// Delete resource group.
		err = manager.DeleteOverlayNetwork(context.Background(), rg.Name)
		Expect(err).ToNot(HaveOccurred())
		if networkProp != nil {
			validateFreedNetworkProperties(networkProp)
		}
	}

	testHostIPChange := func(_, mrEventChan <-chan client.ObjectKey) {
		logf.Log.V(1).Info("Test host IP changes")
		mr.Spec.HostInterfaceIP = resource.IPAddress("30.40.1.2")
		err := k8sClient.Update(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		err = manager.AddOrUpdateResourceToNetwork(context.Background(), mr.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		Eventually(func() error {
			stop := time.Tick(time.Second)
			select {
			case mrEvt := <-mrEventChan:
				err = manager.AddOrUpdateResourceToNetwork(context.Background(), mrEvt.Name)
				if err != nil {
					return err
				}
				prop, err := manager.GetResourceProperties(context.Background(), mrEvt.Name)
				if err != nil {
					return err
				}
				validateResourceProperties(prop, &mr.Spec, internal.BackendStateComplete.String())
				return err
			case <-stop:
				return fmt.Errorf("no event")
			}

		}, 10, 1).ShouldNot(HaveOccurred())
		// Retry with exact same config,
		err = manager.AddOrUpdateResourceToNetwork(context.Background(), mr.Name)
		Expect(err).ToNot(HaveOccurred())
	}
	testManagedResource := func(commits int,
		modifyTest func(_, _ <-chan client.ObjectKey)) {
		// Setup mock transport
		impl := internal.GetVPCManagerImpl(manager)
		impl.SetNetworkDeviceTransport(
			map[string]func(string, string, string, string, string) (internal.NetworkDeviceTransport, error){
				networkfabric.LeafName: func(_, _, _, _, _ string) (internal.NetworkDeviceTransport, error) {
					return mockCumulusTransport, nil
				},
			})
		mockCumulusTransport.EXPECT().GetMgmtIP().AnyTimes().Return(string(leaf.Spec.Control.ManagementIP))
		mockCumulusTransport.EXPECT().SetMgmtIP(leaf.Spec.Control.ManagementIP).AnyTimes()
		mockCumulusTransport.EXPECT().Send(gomock.Any()).MinTimes(1).DoAndReturn(
			func(req *http.Request) ([]byte, error) {
				defer GinkgoRecover()
				logf.Log.V(1).Info("http mock", "Request", req.URL.String(), "Method", req.Method)
				if req.Method == http.MethodPost && strings.HasSuffix(req.URL.String(), "/revision") {
					return json.Marshal(&map[string]interface{}{
						"revision_1": struct{}{}})
				} else if req.Method == http.MethodGet && strings.Contains(req.URL.String(), "/revision/") {
					return json.Marshal(&map[string]interface{}{
						"state": "applied"})
				} else if req.Method == http.MethodPatch && strings.HasSuffix(req.URL.String(), "/revision/revision_1") {
					commits--
				}

				bgpURI := fmt.Sprintf(internal.BGPNetworkURI, internal.VrfDefault)
				routeURI := fmt.Sprintf(internal.StaticRouteURI, internal.VrfDefault)
				if !strings.Contains(req.URL.String(), "/"+internal.RevisionURI+"/") &&
					!strings.Contains(req.URL.String(), "/"+internal.InterfaceURI) &&
					!strings.Contains(req.URL.String(), "/"+internal.BridgeDomainURI) &&
					!strings.Contains(req.URL.String(), "/"+internal.DHCPRelayURI) &&
					!strings.Contains(req.URL.String(), "/"+routeURI) &&
					!strings.Contains(req.URL.String(), "/"+bgpURI) &&
					!strings.Contains(req.URL.String(), "/"+internal.RouteMapRuleURI) {
					Fail("Unknown request: " + req.URL.String())
				}
				return json.Marshal(&map[string]interface{}{
					"status": 200})
			})

		leafEventChan := manager.GetEvent(networkfabric.LeafName)
		mrEventChan := manager.GetEvent(resource.ManagedResourceName)

		// Create network device.
		err := k8sClient.Create(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
		if len(leaf.Status.Conditions) > 0 {
			err = k8sClient.Status().Update(context.Background(), leaf)
			Expect(err).ToNot(HaveOccurred())
		}
		err = manager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
		Expect(vpc.IsAlreadyExistError(err) || err == nil).To(BeTrue())
		if !vpc.IsAlreadyExistError(err) {
			Eventually(func() error {
				stop := time.Tick(time.Second)
				select {
				case leafEvt := <-leafEventChan:
					err = manager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leafEvt.Name)
					if err != nil {
						return err
					}
					devProp, err := manager.GetNetworkDeviceProperties(context.Background(), networkfabric.LeafName, leaf.Name)
					if err != nil {
						return err
					}
					if !devProp.Alive {
						return fmt.Errorf("wait for liveness")
					}
					return nil
				case <-stop:
					return fmt.Errorf("no Event")

				}
			}, 10, 1).Should(BeNil())
		}
		// Create managed resource.
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		if len(mr.Status.Conditions) > 0 {
			err = k8sClient.Status().Update(context.Background(), mr)
			Expect(err).ToNot(HaveOccurred())
		}
		err = manager.AddOrUpdateResourceToNetwork(context.Background(), mr.Name)
		Expect(vpc.IsBackendConfigurationInProgress(err) || err == nil).To(BeTrue())
		var prop *properties.ResourceProperties
		if err == nil {
			prop, err = manager.GetResourceProperties(context.Background(), mr.Name)
			Expect(err).ToNot(HaveOccurred())
			validateResourceProperties(prop, &mr.Spec, internal.BackendStateComplete.String())
		} else {
			Eventually(func() error {
				stop := time.Tick(time.Second)
				select {
				case mrEvt := <-mrEventChan:
					err = manager.AddOrUpdateResourceToNetwork(context.Background(), mrEvt.Name)
					if err != nil {
						return err
					}
					prop, err = manager.GetResourceProperties(context.Background(), mrEvt.Name)
					if err != nil {
						return err
					}
					validateResourceProperties(prop, &mr.Spec, internal.BackendStateComplete.String())
					return nil
				case <-stop:
					return fmt.Errorf("no event")
				}
			}, 10, 1).ShouldNot(HaveOccurred())
		}

		if modifyTest != nil {
			modifyTest(leafEventChan, mrEventChan)
		}

		// Remove managed resource.
		err = manager.RemoveResourceToNetwork(context.Background(), mr.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		Eventually(func() error {
			stop := time.Tick(time.Second)
			select {
			case mrEvt := <-mrEventChan:
				err = manager.RemoveResourceToNetwork(context.Background(), mrEvt.Name)
				if err != nil {
					return err
				}
				validateFreedResourceProperties(prop)
				return err
			case <-stop:
				return fmt.Errorf("no event")
			}
		}, 10, 1).Should(BeNil())
		err = k8sClient.Delete(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())

		// Remove network device.
		err = manager.RemoveNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
		Expect(commits).To(BeZero())
	}

	table.DescribeTable("ResourceGroup",
		func(vni, vlan, overlay bool, err error) {
			if overlay {
				rg.Spec.OverlayIPPool = string(networkfabric.OverlayIPv4ResourcePool)
				rg.Spec.Network = nil
			}
			testResourceGroup(vni, vlan, false, true, err)
		},
		table.Entry("With tenant provided IP", true, true, false, nil),
		table.Entry("With allocated IP", true, true, true, nil),
		table.Entry("Without VNI", false, true, true,
			internal.NewMissingResourcePoolError(string(networkfabric.VNIResourcePool))),
		table.Entry("Without Vlan", true, false, true,
			internal.NewMissingResourcePoolError(string(networkfabric.VlanIDResourcePool))),
	)

	Context("ManagedResource", func() {
		JustBeforeEach(func() {
			// Setup ResourceGroup.
			testResourceGroup(true, true, true, false, nil)
		})
		JustAfterEach(func() {
			// Delete resource group.
			err := manager.DeleteOverlayNetwork(context.Background(), rg.Name)
			Expect(err).ToNot(HaveOccurred())
		})

		table.DescribeTable("Life cycle",
			func(commits int, // changes commit to the device.
				modifyTest func(_, _ <-chan client.ObjectKey)) {
				testManagedResource(commits, modifyTest)
			},
			table.Entry("Normal", 4, nil),                      // 2 commits for overlay; 2 commits for adminIPs
			table.Entry("Modify host IP", 5, testHostIPChange), // 3 commits for overlay; 2 commits for adminIPs
		)

		It("Reconcile", func() {
			mr.Status.Conditions = []resource.ManagedResourceCondition{{
				Type:               resource.ManagedResourceConditionTypeAdd,
				Status:             v1.ConditionTrue,
				LastTransitionTime: metav1.Time{Time: time.Now()},
			}}
			mr.Status.NetworkFabricReference = &resource.NetworkFabricReference{
				ConfigurationState: internal.BackendStateComplete.String(),
			}
			mr.Status.HostAccessIPs = &resource.IPAssociation{}
			leaf.Status.Conditions = []networkfabric.NetworkDeviceCondition{{
				Type:               networkfabric.NetworkDeviceConditionTypeLiveness,
				Status:             v1.ConditionTrue,
				LastTransitionTime: metav1.Time{Time: time.Now()},
			}}
			oldIntv := internal.CumulusLivenessInterval
			defer func() { internal.CumulusLivenessInterval = oldIntv }()
			internal.CumulusLivenessInterval = 3 * time.Second
			// 1 commit for delete overlay, 1 commit for reconfigure underlay.
			testManagedResource(2, func(_, _ <-chan client.ObjectKey) { time.Sleep(time.Second * 5) })
		})
	})
})
