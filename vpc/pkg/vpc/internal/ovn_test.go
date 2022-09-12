package internal_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	"gitlab-master.nvidia.com/forge/vpc/pkg/agent"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
	"gitlab-master.nvidia.com/forge/vpc/rpc"
	"gitlab-master.nvidia.com/forge/vpc/rpc/testing"
)

var _ = Describe("Ovn", func() {
	var (
		ovnServiceIP    = ""
		mockController  *gomock.Controller
		ovnPod          *corev1.Pod
		rg              *resource.ResourceGroup
		mr              *resource.ManagedResource
		podController   *controllers.PodReconciler
		agentService    *testing.MockAgentServiceServer
		grpcServer      *grpc.Server
		manager         vpc.VPCManager
		resourceManager *resourcepool.Manager
		publicIPRange   = []string{"2.3.4.0", "2.3.5.0"}
		fabricIPRange   = []string{"22.3.4.0", "22.3.5.0"}
		ctx             context.Context
		ctxCancel       context.CancelFunc
	)

	generateOvnPod := func() {
		// Update service IP and update test env.
		ovnService := &corev1.Service{}
		key := client.ObjectKey{
			Namespace: namespace,
			Name:      internal.GetOvnServiceName(rgName),
		}
		err := k8sClient.Get(context.Background(), key, ovnService)
		Expect(err).ToNot(HaveOccurred())
		ovnServiceIP = ovnService.Spec.ClusterIP
		Expect(ovnServiceIP).ToNot(BeEmpty())

		err = utils.Execute("ip", nil, nil, "addr", "add", "dev", "lo", ovnServiceIP+"/16")
		Expect(err).ToNot(HaveOccurred())

		// Update Service Pod.
		err = k8sClient.Create(context.Background(), ovnPod)
		Expect(err).ToNot(HaveOccurred())
		ovnPod.Status.Conditions = []corev1.PodCondition{{
			Type:   corev1.PodReady,
			Status: corev1.ConditionTrue,
		}}
		err = k8sClient.Status().Update(context.Background(), ovnPod)
		Expect(err).ToNot(HaveOccurred())
		_, err = podController.Reconcile(context.Background(),
			ctrl.Request{NamespacedName: types.NamespacedName{
				Namespace: namespace,
				Name:      internal.GetOvnServiceName(rgName)}})
		Expect(err).ToNot(HaveOccurred())
	}

	BeforeEach(func() {
		rg = &resource.ResourceGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rgName,
				Namespace: namespace,
			},
			Spec: resource.ResourceGroupSpec{
				TenantIdentifier: "",
				Network: &resource.IPNet{
					IP:           "10.10.10.0",
					PrefixLength: 24,
					Gateway:      "10.10.10.1",
				},
				DHCPServer:                "20.20.20.1",
				NetworkImplementationType: resource.OverlayNetworkImplementationTypeSoftware,
			},
		}
		ovnPod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      internal.GetOvnServiceName(rgName),
				Namespace: namespace,
				Labels:    map[string]string{"app": internal.GetOvnServiceName(rgName)},
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "test",
				}},
			},
			Status: corev1.PodStatus{
				Conditions: []corev1.PodCondition{{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				}},
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
				DPUIPs:              []resource.IPAddress{"127.0.0.1", "127.0.0.8"},
				HostInterfaceAccess: resource.HostAccessIsolated,
				HostInterface:       "test-mr-mac",
			},
		}

		podController = controllers.NewPodController(k8sClient, scheme.Scheme, namespace)
		mockController = gomock.NewController(GinkgoT())
		go func() {
			defer GinkgoRecover()
			agentService = testing.NewMockAgentServiceServer(mockController)
			grpcServer = grpc.NewServer()
			rpc.RegisterAgentServiceServer(grpcServer, agentService)
			lis, err := net.Listen("tcp", fmt.Sprintf(":%d", agent.AgentServicePort))
			Expect(err).ToNot(HaveOccurred())
			err = grpcServer.Serve(lis)
			Expect(err).ToNot(HaveOccurred())
		}()

		err := utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "start_northd")
		Expect(err).ToNot(HaveOccurred())
		err = utils.Execute("/usr/bin/ovn-sbctl", nil, nil, "set-connection", "ptcp:6642")
		Expect(err).ToNot(HaveOccurred())
		err = utils.Execute("/usr/bin/ovn-nbctl", nil, nil, "set-connection", "ptcp:6641")
		Expect(err).ToNot(HaveOccurred())
		resourceManager = resourcepool.NewManager(k8sClient, namespace)
		pool := resourceManager.CreateIPv4Pool(string(v1alpha1.PublicIPv4ResourcePool),
			[][]string{publicIPRange}, 0)
		_ = pool.Reconcile()
		pool = resourceManager.CreateIPv4Pool(string(v1alpha1.DatacenterIPv4ResourcePool),
			[][]string{fabricIPRange}, 0)
		_ = pool.Reconcile()
		manager = vpc.NewVPCManager(k8sClient, podController, namespace, resourceManager)
		ctx, ctxCancel = context.WithCancel(context.Background())
		go func() { _ = manager.Start(ctx) }()
	})

	AfterEach(func() {
		mockController.Finish()
		grpcServer.Stop()
		out := &bytes.Buffer{}
		ctxCancel()
		err := utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, out, "stop_northd")
		Expect(err).ToNot(HaveOccurred(), out.String())
		err = utils.Execute("/bin/bash", nil, out, "-c", "rm /var/lib/ovn/*")
		Expect(err).ToNot(HaveOccurred(), out.String())
		err = k8sClient.Delete(context.Background(), rg)
		Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
		err = k8sClient.Delete(context.Background(), mr)
		Expect(client.IgnoreNotFound(err)).NotTo(HaveOccurred())
	})

	It("Resource life cycle", func() {
		err := k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = manager.CreateOrUpdateOverlayNetwork(context.Background(), rgName)
		Expect(err).To(Equal(internal.NewBackendConfigurationInProgress("ovn", "ResourceGroup", rgName)))
		generateOvnPod()
		Eventually(func() error {
			// logf.Log.V(1).Info("TODO create polling", "Err", err)
			return manager.CreateOrUpdateOverlayNetwork(context.Background(), rgName)
		}, 10, 1).ShouldNot(HaveOccurred())
		_, err = manager.GetOverlayNetworkProperties(context.Background(), rgName)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		agentService.EXPECT().SetOvn(gomock.Any(), gomock.Any()).Times(2).DoAndReturn(
			func(_ context.Context, config *rpc.OVNConfig) (*rpc.ServiceStatus, error) {
				if len(config.OvnServiceIP) > 0 {
					Expect(config.OvnServiceIP).To(Equal(ovnServiceIP))
					Expect(config.TunnelEndPointIP).To(Equal(string(mr.Spec.DPUIPs[0])))
				} else {
					Expect(config.TunnelEndPointIP).To(Equal(""))
				}
				return &rpc.ServiceStatus{Status: rpc.ErrorCode_OK}, nil
			})
		agentService.EXPECT().AliveProbe(gomock.Any(), gomock.Any()).MinTimes(1).DoAndReturn(
			func(_ context.Context, config *rpc.Probe) (*rpc.AgentStatus, error) {
				return &rpc.AgentStatus{
					Identifier:     mr.Spec.HostInterface,
					Status:         &rpc.ServiceStatus{Status: rpc.ErrorCode_OK},
					PortExternalID: "test-port",
					DhcpExternalID: "test-dhcp-port",
					DefaultGW:      "127.0.0.254",
				}, nil
			})
		agentService.EXPECT().SetDHCPRelay(gomock.Any(), gomock.Any()).DoAndReturn(
			func(_ context.Context, config *rpc.DHCPRelay) (*rpc.ServiceStatus, error) {
				Expect(config.DhcpInterfaceName).To(Equal(internal.GetDHCPPortName(rgName)))
				Expect(config.DhcpInterfaceIP).To(Equal(string(rg.Spec.Network.Gateway)))
				Expect(config.DhcpServer).To(Equal(string(rg.Spec.DHCPServer)))
				return &rpc.ServiceStatus{Status: rpc.ErrorCode_OK}, nil
			})
		err = manager.AddOrUpdateResourceToNetwork(context.Background(), mrName)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(time.Second * 2)

		err = manager.RemoveResourceToNetwork(context.Background(), mrName)
		Expect(err).ToNot(HaveOccurred())
		err = manager.DeleteOverlayNetwork(context.Background(), rgName)
		Expect(err).ToNot(HaveOccurred())
	})
})
