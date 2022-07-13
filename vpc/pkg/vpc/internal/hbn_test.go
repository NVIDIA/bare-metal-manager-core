package internal_test

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
)

var _ = Describe("Hbn", func() {
	var (
		loopbackIPRange = []string{"20.20.20.1", "20.20.20.10"}
		loopbackIPPool  *resourcepool.IPv4BlockPool
		asnRange        = []uint64{65500, 65535}
		asnPool         *resourcepool.IntegerPool
		startupYaml     *bytes.Buffer
		dhcRelayConf    *bytes.Buffer
		hbnContainerID  = "1234"
	)
	setupHBNConfig := func(reset bool) {
		hbnConfig := &internal.HBNConfig
		if reset {
			*hbnConfig = internal.CumulusNetworkDeviceConfig{}
			return
		}
		hbnConfig.HBNDevice = true
		_, fPath, _, _ := runtime.Caller(0)
		configPath := filepath.Join(filepath.Dir(fPath), "../../../config/manager/hbn_nvue_config.yaml")
		var err error
		hbnConfig.NVUEConfig, err = os.ReadFile(configPath)
		Expect(err).ToNot(HaveOccurred(), configPath)
		configPath = filepath.Join(filepath.Dir(fPath), "../../../config/manager/hbn_dhcrelay_config")
		hbnConfig.DHCPRelayConfig, err = os.ReadFile(configPath)
		Expect(err).ToNot(HaveOccurred(), configPath)
		hbnConfig.DefaultASN = 65535
	}
	BeforeEach(func() {
		startupYaml = nil
		dhcRelayConf = nil
		setupHBNConfig(false)
		initResources()
		leaf.Spec.HostInterfaces = nil
		startManager()
		asnPool = resourceManager.CreateIntegerPool(string(networkfabric.ASNResourcePool), [][]uint64{asnRange})
		_ = asnPool.Reconcile()
		vniPool = resourceManager.CreateIntegerPool(string(networkfabric.VNIResourcePool), [][]uint64{vniRange})
		_ = vniPool.Reconcile()
		vlanPool = resourceManager.CreateIntegerPool(string(networkfabric.VlanIDResourcePool), [][]uint64{vlanRange})
		_ = vlanPool.Reconcile()
		loopbackIPPool = resourceManager.CreateIPv4Pool(string(networkfabric.LoopbackIPResourcePool),
			[][]string{loopbackIPRange}, 1)
		_ = loopbackIPPool.Reconcile()
		err := k8sClient.Create(context.Background(), adminRg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
	})
	AfterEach(func() {
		stopManager()
		err := k8sClient.Delete(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), adminRg)
		Expect(err).ToNot(HaveOccurred())
		setupHBNConfig(true)
	})

	testAddLeaf := func(sshCmds, hbnCmds map[string]int, hbnId string, remove bool, modifier func()) {
		mockCumulusTransport.EXPECT().GetHBNContainerID().AnyTimes().DoAndReturn(
			func() (string, error) {
				return hbnId, nil
			})
		mockCumulusTransport.EXPECT().Ssh(gomock.Any()).AnyTimes().DoAndReturn(
			func(cmd string) (string, error) {
				defer GinkgoRecover()
				logf.Log.V(1).Info("Ssh", "Cmd", cmd)
				// Expect HBN container start after kubelet start.
				if strings.Contains(cmd, "start kubelet") {
					hbnId = hbnContainerID
				}
				if strings.HasPrefix(cmd, "echo -e") {
					cmd = "echo -e"
				}
				Expect(sshCmds).Should(HaveKey(cmd))
				sshCmds[cmd]--
				if sshCmds[cmd] == 0 {
					delete(sshCmds, cmd)
				}
				if cmd == "sudo ls /var/lib/hbn/etc/nvue.d/" {
					return "startup.yaml", nil
				} else if cmd == "sudo ls /var/lib/hbn/etc/supervisor/conf.d/" {
					return "supervisor-isc-dhcp-relay.conf", nil
				} else if cmd == "sudo cat /var/lib/hbn/etc/nvue.d/startup.yaml" {
					return startupYaml.String(), nil
				} else if cmd == "sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf" {
					return dhcRelayConf.String(), nil
				}
				return "", nil
			})
		mockCumulusTransport.EXPECT().SshHBN(gomock.Any()).AnyTimes().DoAndReturn(
			func(cmd string) (string, error) {
				defer GinkgoRecover()
				logf.Log.V(1).Info("SshHBN", "Cmd", cmd)
				Expect(hbnCmds).Should(HaveKey(cmd))
				hbnCmds[cmd]--
				if hbnCmds[cmd] == 0 {
					delete(hbnCmds, cmd)
				}
				if strings.Contains(cmd, "status nvued") {
					return "RUNNING", nil
				}
				return "", nil
			})
		mockCumulusTransport.EXPECT().GetMgmtIP().AnyTimes().Return(string(leaf.Spec.Control.ManagementIP))
		mockCumulusTransport.EXPECT().SetMgmtIP(leaf.Spec.Control.ManagementIP).AnyTimes()
		mockCumulusTransport.EXPECT().Send(gomock.Any()).MinTimes(1).DoAndReturn(
			func(req *http.Request) ([]byte, error) {
				logf.Log.V(1).Info("http mock", "Request", req.URL.String(), "Method", req.Method)
				if req.Method == http.MethodPost && strings.HasSuffix(req.URL.String(), "/revision") {
					return json.Marshal(&map[string]interface{}{
						"revision_1": struct{}{}})
				} else if req.Method == http.MethodGet && strings.Contains(req.URL.String(), "/revision/") {
					return json.Marshal(&map[string]interface{}{
						"state": "applied"})
				}
				return json.Marshal(&map[string]interface{}{
					"status": 200})
			})
		err := vpcManager.CreateOrUpdateOverlayNetwork(context.Background(), adminRg.Name)
		Expect(err).ToNot(HaveOccurred())
		_, err = vpcManager.GetOverlayNetworkProperties(context.Background(), adminRg.Name)
		Expect(err).ToNot(HaveOccurred())
		err = vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
		Expect(vpc.IsAlreadyExistError(err) || err == nil).To(BeTrue())
		leafEventChan := vpcManager.GetEvent(networkfabric.LeafName)
		if modifier != nil {
			modifier()
		}
		Eventually(func() error {
			stop := time.Tick(time.Second)
			select {
			case leafEvt := <-leafEventChan:
				err = vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leafEvt.Name)
				if err != nil {
					return err
				}
				devProp, err := vpcManager.GetNetworkDeviceProperties(context.Background(), networkfabric.LeafName, leaf.Name)
				if err != nil {
					return err
				}
				if !devProp.Alive || len(devProp.LoopbackIP) == 0 || devProp.ASN == 0 ||
					len(devProp.AdminDHCPServer) == 0 || len(devProp.AdminHostIPs) == 0 {
					return fmt.Errorf("wait for liveness")
				}
				return nil
			case <-stop:
				return fmt.Errorf("no Event")

			}
		}, 10, 1).Should(BeNil())

		if remove {
			err = vpcManager.RemoveNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
			Expect(err).To(HaveOccurred())
			leafEventChan = vpcManager.GetEvent(networkfabric.LeafName)
			Eventually(func() error {
				stop := time.Tick(time.Second)
				select {
				case leafEvt := <-leafEventChan:
					err := vpcManager.RemoveNetworkDevice(context.Background(), networkfabric.LeafName, leafEvt.Name)
					logf.Log.V(1).Info("Remove device result", "Error", err)
					return err
				case <-stop:
					return fmt.Errorf("no Event")

				}
			}, 10, 1).Should(BeNil())
		}
		Eventually(func() bool {
			return len(sshCmds) == 0
		}, 10, 1).Should(BeTrue(), fmt.Sprintf("%v", sshCmds))
		Eventually(func() bool {
			return len(hbnCmds) == 0
		}, 10, 1).Should(BeTrue(), fmt.Sprintf("%v", hbnCmds))
	}

	It("Add new leaf for new HBN", func() {
		sshCmds := map[string]int{
			"echo -e": 2, // generate startup and dhcrelay files
			"sudo systemctl start containerd.service":                                    1,
			"sudo systemctl enable containerd.service":                                   1,
			"sudo systemctl start kubelet.service":                                       1,
			"sudo systemctl enable kubelet.service":                                      1,
			"sudo ls /var/lib/hbn/etc/supervisor/conf.d/":                                1,
			"sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf": 1,
		}

		hbnCmds := map[string]int{
			"nv config apply startup --assume-yes": 1,
			"supervisorctl update":                 1,
			"supervisorctl status nvued":           1,
		}
		testAddLeaf(sshCmds, hbnCmds, "", false, nil)
	})

	It("Add new leaf for existing HBN", func() {
		sshCmds := map[string]int{
			"echo -e": 2, // generate startup and dhcrelay file
			"sudo ls /var/lib/hbn/etc/supervisor/conf.d/":                                1,
			"sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf": 1,
		}
		hbnCmds := map[string]int{
			"nv config apply startup --assume-yes": 1,
			"supervisorctl update":                 1,
		}
		testAddLeaf(sshCmds, hbnCmds, hbnContainerID, false, nil)
	})

	It("Add existing leaf for existing HBN", func() {
		leaf.Status.LoopbackIP = "20.20.20.1"
		leaf.Status.ASN = 65530
		leaf.Status.Conditions = []networkfabric.NetworkDeviceCondition{{
			Type:               networkfabric.NetworkDeviceConditionTypeLiveness,
			Status:             v1.ConditionTrue,
			LastTransitionTime: metav1.Time{Time: time.Now()},
		}}
		leaf.Status.HostAdminIPs = map[string]string{"port": "nic"}
		err := k8sClient.Status().Update(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())

		t := template.Must(template.New("").Parse(string(internal.HBNConfig.NVUEConfig)))
		startupYaml = &bytes.Buffer{}
		nparam := &struct {
			LoopbackIP         string
			ASN                uint32
			FromUnderlayFilter string
			ToUnderlayFilter   string
			UplinkGroup        string
		}{
			LoopbackIP:         leaf.Status.LoopbackIP,
			ASN:                leaf.Status.ASN,
			FromUnderlayFilter: internal.ForgeFromUnderlayFilter,
			ToUnderlayFilter:   internal.ForgeToUnderlayFilter,
			UplinkGroup:        internal.ForgeUplink,
		}
		err = t.Execute(startupYaml, nparam)
		Expect(err).ToNot(HaveOccurred())

		t = template.Must(template.New("").Parse(string(internal.HBNConfig.DHCPRelayConfig)))
		dhcRelayConf = &bytes.Buffer{}
		dparam := &struct {
			DHCPServer    string
			HostInterface string
		}{
			DHCPServer:    string(adminRg.Spec.DHCPServer),
			HostInterface: fmt.Sprintf("vlan%d", vlanRange[0]),
		}
		err = t.Execute(dhcRelayConf, dparam)
		Expect(err).ToNot(HaveOccurred())
		sshCmds := map[string]int{
			"sudo ls /var/lib/hbn/etc/nvue.d/":              1,
			"sudo cat /var/lib/hbn/etc/nvue.d/startup.yaml": 1,
		}
		hbnCmds := map[string]int{}
		tmpLeaf := &networkfabric.Leaf{}
		key := client.ObjectKey{
			Namespace: leaf.Namespace,
			Name:      leaf.Name,
		}
		err = k8sClient.Get(context.Background(), key, tmpLeaf)
		Expect(err).ToNot(HaveOccurred())
		tmpLeaf.Status.Conditions = []networkfabric.NetworkDeviceCondition{{
			Type:               networkfabric.NetworkDeviceConditionTypeLiveness,
			Status:             v1.ConditionTrue,
			LastTransitionTime: metav1.Time{Time: time.Now()},
		}}
		oldIntv := internal.CumulusLivenessInterval
		defer func() { internal.CumulusLivenessInterval = oldIntv }()
		internal.CumulusLivenessInterval = 3 * time.Second
		modifier := func() {
			time.Sleep(time.Second * 5)
		}
		testAddLeaf(sshCmds, hbnCmds, hbnContainerID, false, modifier)
	})

	It("Update host admin IP", func() {
		sshCmds := map[string]int{
			"echo -e": 3, // generate startup and 2 (one from update) dhcrelay files
			"sudo systemctl start containerd.service":                                    1,
			"sudo systemctl enable containerd.service":                                   1,
			"sudo systemctl start kubelet.service":                                       1,
			"sudo systemctl enable kubelet.service":                                      1,
			"sudo ls /var/lib/hbn/etc/supervisor/conf.d/":                                2,
			"sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf": 2,
		}

		hbnCmds := map[string]int{
			"nv config apply startup --assume-yes": 1,
			"supervisorctl update":                 2,
			"supervisorctl status nvued":           1,
		}
		modifier := func() {
			go func() {
				defer GinkgoRecover()
				time.Sleep(time.Second * 2)
				leaf.Spec.HostAdminIPs["pf0hpf"] = "30.30.30.2"
				err := k8sClient.Update(context.Background(), leaf)
				Expect(err).ToNot(HaveOccurred())
				err = vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
				Expect(err).ToNot(HaveOccurred())
			}()
		}
		testAddLeaf(sshCmds, hbnCmds, "", false, modifier)
	})

	It("Delete a existing leaf", func() {
		sshCmds := map[string]int{
			"echo -e": 2, // generate startup and dhcrelay file
			"sudo systemctl start containerd.service":                                      1,
			"sudo systemctl enable containerd.service":                                     1,
			"sudo systemctl start kubelet.service":                                         1,
			"sudo systemctl enable kubelet.service":                                        1,
			"sudo ls /var/lib/hbn/etc/supervisor/conf.d/":                                  1,
			"sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf":   1,
			"sudo systemctl stop kubelet.service":                                          1,
			"sudo systemctl disable kubelet.service":                                       1,
			"sudo crictl rm -f " + hbnContainerID:                                          1,
			"sudo rm -f /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf": 1,
		}

		hbnCmds := map[string]int{
			"supervisorctl update":                 1,
			"nv config apply startup --assume-yes": 1,
			"supervisorctl status nvued":           1,
		}
		testAddLeaf(sshCmds, hbnCmds, "", true, nil)
	})

	It("ContainerID", func() {
		id := "23cac9c220ef2629be474001273e85eef93ccb466219036f102a138a00af2fad"
		str := fmt.Sprintf(`{
  "containers": [
    {
      "id": "%s",
      "podSandboxId": "a519c83130c23304b5ea68b82933726a2d7503b359ee7ad2e4c509fd6aa3dfa3",
      "metadata": {
        "name": "doca-hbn",
        "attempt": 1
      },
      "image": {
        "image": "sha256:9260cfd631bbf212f861ee6a01c7a9d8e5ff67d3e9f9ed41d4ab51cdd5987229",
        "annotations": {
        }
      },
      "imageRef": "sha256:9260cfd631bbf212f861ee6a01c7a9d8e5ff67d3e9f9ed41d4ab51cdd5987229",
      "state": "CONTAINER_RUNNING",
      "createdAt": "1653110193333797693",
      "labels": {
        "io.kubernetes.container.name": "doca-hbn",
        "io.kubernetes.pod.name": "doca-hbn-service-localhost.localdomain",
        "io.kubernetes.pod.namespace": "default",
        "io.kubernetes.pod.uid": "4a90ae28f00322649d1011579afd9a27"
      },
      "annotations": {
        "io.kubernetes.container.hash": "10888a77",
        "io.kubernetes.container.restartCount": "1",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "30"
      }
    }
  ]
}`, id)
		gid, err := internal.ParseContainerID([]byte(str))
		Expect(err).ToNot(HaveOccurred(), str)
		Expect(gid).To(Equal(id))
	})
})
