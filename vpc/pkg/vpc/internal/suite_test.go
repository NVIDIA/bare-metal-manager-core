/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package internal_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/zap/zapcore"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	networkfabricv1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resourcev1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
	mock "gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal/testing"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

const (
	rgName   = "test-rg"
	mrName   = "test-mr"
	tenantID = "test-tenant"
)

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	namespace = "forge-system"

	mockController       *gomock.Controller
	vpcManager           vpc.VPCManager
	resourceManager      *resourcepool.Manager
	rg                   *resourcev1alpha1.ResourceGroup
	adminRg              *resourcev1alpha1.ResourceGroup
	mockCumulusTransport *mock.MockNetworkDeviceTransport
	mr                   *resourcev1alpha1.ManagedResource
	leaf                 *networkfabricv1alpha1.Leaf
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

func initResources() {
	rg = &resourcev1alpha1.ResourceGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rgName,
			Namespace: namespace,
		},
		Spec: resourcev1alpha1.ResourceGroupSpec{
			TenantIdentifier: tenantID,
			Network: &resourcev1alpha1.IPNet{
				IP:           "10.10.10.0",
				PrefixLength: 24,
				Gateway:      "10.10.10.1",
			},
			DHCPServer:                "20.20.20.1",
			NetworkImplementationType: resourcev1alpha1.OverlayNetworkImplementationTypeFabric,
		},
	}
	adminRg = &resourcev1alpha1.ResourceGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      resourcev1alpha1.WellKnownAdminResourceGroup,
			Namespace: namespace,
		},
		Spec: resourcev1alpha1.ResourceGroupSpec{
			TenantIdentifier: "test",
			Network: &resourcev1alpha1.IPNet{
				IP:           "30.30.30.0",
				PrefixLength: 24,
				Gateway:      "30.30.30.1",
			},
			DHCPServer:                "20.20.20.1",
			NetworkImplementationType: resourcev1alpha1.OverlayNetworkImplementationTypeFabric,
		},
	}
	mr = &resourcev1alpha1.ManagedResource{
		ObjectMeta: metav1.ObjectMeta{
			Name:      mrName,
			Namespace: namespace,
		},
		Spec: resourcev1alpha1.ManagedResourceSpec{
			ResourceGroup:       rgName,
			Type:                resourcev1alpha1.ResourceTypeBareMetal,
			State:               resourcev1alpha1.ManagedResourceStateUp,
			HostInterfaceIP:     "10.10.10.5",
			HostInterfaceMAC:    "00:01:02:03:04:05",
			DPUIPs:              []resourcev1alpha1.IPAddress{"192.2.1.3", "192.2.1.4", "192.2.1.5"},
			HostInterfaceAccess: resourcev1alpha1.HostAccessFabricDirect,
			HostInterface:       "01:02:03:04:05",
		},
	}
	leaf = &networkfabricv1alpha1.Leaf{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hbn-1",
			Namespace: namespace,
		},
		Spec: networkfabricv1alpha1.LeafSpec{
			Control: networkfabricv1alpha1.NetworkDeviceControl{
				Vendor:          "Cumulus",
				ManagementIP:    "40.40.40.1",
				MaintenanceMode: false,
			},
			HostInterfaces: map[string]string{"01:02:03:04:05": "pf0hpf"},
			HostAdminIPs:   map[string]string{"pf0hpf": ""},
		},
	}
}

func startManager() {
	mockController = gomock.NewController(GinkgoT())
	mockCumulusTransport = mock.NewMockNetworkDeviceTransport(mockController)
	resourceManager = resourcepool.NewManager(k8sClient, namespace)
	vpcManager = vpc.NewVPCManager(k8sClient, nil, namespace, resourceManager)
	impl := internal.GetVPCManagerImpl(vpcManager)
	impl.SetNetworkDeviceTransport(
		map[string]func(string, string, string) (internal.NetworkDeviceTransport, error){
			networkfabricv1alpha1.LeafName: func(_, _, _ string) (internal.NetworkDeviceTransport, error) {
				return mockCumulusTransport, nil
			},
		})
	ctx, ctxCancel = context.WithCancel(context.Background())
	go func() { _ = vpcManager.Start(ctx) }()
}

func stopManager() {
	mockController.Finish()
	ctxCancel()
}

func drainEvents() {
	leafEventChan := vpcManager.GetEvent(networkfabricv1alpha1.LeafName)
	mrEventChan := vpcManager.GetEvent(resourcev1alpha1.ManagedResourceName)
	npEventChan := vpcManager.GetEvent(resourcev1alpha1.NetworkPolicyName)
	stop := time.Tick(time.Second * 2)
	for {
		select {
		case <-leafEventChan:
			continue
		case <-mrEventChan:
			continue
		case <-npEventChan:
			continue
		case <-stop:
			return
		}
	}
}

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Internal Forge Suite")
}

var _ = BeforeSuite(func() {
	opts := zap.Options{
		Development: true,
		TimeEncoder: zapcore.RFC3339TimeEncoder,
	}
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true), zap.UseFlagOptions(&opts)))
	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = resourcev1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	err = networkfabricv1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	err = k8sClient.Create(context.Background(), ns)
	Expect(err).NotTo(HaveOccurred())

	os.Setenv(internal.EnvCumulusUser, "test-user")
	os.Setenv(internal.EnvCumulusPwd, "test-pwd")

})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
