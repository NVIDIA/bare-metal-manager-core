package agent_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/json"

	"gitlab-master.nvidia.com/forge/vpc/pkg/agent"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
	"gitlab-master.nvidia.com/forge/vpc/rpc"
)

func ovsdbValidate(i interface{}, kv map[string]string) error {
	list, ok := i.([]interface{})
	if !ok {
		return fmt.Errorf("unknown structure %v %v", reflect.TypeOf(i), i)
	}
	if len(list) == 1 {
		return ovsdbValidate(list[0], kv)
	}

	if len(list) == 2 {
		if n, ok := list[0].(string); ok && n == "map" {
			return ovsdbValidate(list[1], kv)
		}
		return nil
	}

	for _, i := range list {
		tuple := i.([]interface{})
		if len(tuple) != 2 {
			return fmt.Errorf("unknown structure %v", tuple)
		}
		k := tuple[0].(string)
		v := tuple[1].(string)
		if kvv, ok := kv[k]; ok {
			if kvv != v {
				return fmt.Errorf("mismatch key=%s and values %s, %s", k, v, kvv)
			}
			delete(kv, k)
		}
	}
	return nil
}

var _ = Describe("Agent", func() {
	const (
		ovnCentralHostName = "ovn-central-resource.forge-vpc.local"
	)
	var (
		hydAgent      *agent.VPCAgent
		grpcConn      *grpc.ClientConn
		agentStatus   *rpc.AgentStatus
		tunnelIP      netlink.Addr
		dhcpInterface string
		dhcpMAC       string
		dhcpIP        string
		dhcpServer    string
	)
	BeforeEach(func() {
		hydAgent = agent.NewVPCAgent(brName, uplink, hostlink, bindPort)
		go func() {
			defer GinkgoRecover()
			err := hydAgent.Start("")
			Expect(err).ToNot(HaveOccurred())
		}()
		// Wait until bindPort is no longer available.
		Eventually(func() error {
			return utils.Execute("bash", nil, nil, "-c", "ss -nlp | grep "+bindPort)
		}, 10, 1).ShouldNot(HaveOccurred())
		var err error
		grpcConn, err = grpc.Dial("127.0.0.1"+bindPort, grpc.WithInsecure())
		Expect(err).ToNot(HaveOccurred())
		link, _ := netlink.LinkByName(uplink)
		ips, _ := netlink.AddrList(link, netlink.FAMILY_V4)
		tunnelIP = ips[0]
		iden, _ := os.Hostname()
		agentStatus = &rpc.AgentStatus{
			Status: &rpc.ServiceStatus{
				Status: rpc.ErrorCode_OK,
			},
			Identifier:     iden,
			PortExternalID: iden + "-" + hostlink,
			DhcpExternalID: iden + "-dhcp",
			DefaultGW:      "172.17.0.1",
		}
		dhcpInterface = "dh-test-group"
		dhcpMAC = "00:00:00:01:02:03"
		dhcpIP = "10.10.10.1"
		dhcpServer = "1.2.3.4"
	})

	AfterEach(func() {
		err := grpcConn.Close()
		Expect(err).ToNot(HaveOccurred())
		hydAgent.Stop()
	})

	It("Process", func() {
		By("Check keep alive")
		svcClient := rpc.NewAgentServiceClient(grpcConn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()
		status, err := svcClient.AliveProbe(ctx, &rpc.Probe{})
		Expect(err).ToNot(HaveOccurred())
		Expect(status.GetStatus()).To(Equal(agentStatus.GetStatus()))
		Expect(status.GetIdentifier()).To(Equal(agentStatus.GetIdentifier()))
		Expect(status.GetPortExternalID()).To(Equal(agentStatus.GetPortExternalID()))
		Expect(status.GetDhcpExternalID()).To(Equal(agentStatus.GetDhcpExternalID()))
		Expect(status.GetDefaultGW()).To(Equal(agentStatus.GetDefaultGW()))

		By("Start OVN controller")
		svcStatus, err := svcClient.SetOvn(ctx, &rpc.OVNConfig{
			OvnServiceIP:     ovnCentralHostName,
			TunnelEndPointIP: tunnelIP.IP.String(),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "ovn starts")
		out := new(bytes.Buffer)
		err = utils.Execute("ovs-vsctl", nil, out, "--columns=external_ids", "--format=json", "list", "open")
		Expect(err).ToNot(HaveOccurred())
		jMap := make(map[string]interface{})
		err = json.Unmarshal(out.Bytes(), &jMap)
		Expect(err).ToNot(HaveOccurred())
		ovsdbKV := map[string]string{
			"ovn-bridge-mappings": "provider:" + brName,
			"ovn-encap-ip":        tunnelIP.IP.String(),
			"ovn-encap-type":      "geneve",
			"ovn-remote":          fmt.Sprintf("tcp:%s:6642", ovnCentralHostName),
			"system-id":           agentStatus.GetIdentifier(),
		}
		err = ovsdbValidate(jMap["data"], ovsdbKV)
		Expect(err).ToNot(HaveOccurred())
		Expect(ovsdbKV).To(BeEmpty(), fmt.Sprintf("ovsdb setup: %v", ovsdbKV))
		err = utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "status_controller")
		Expect(err).ToNot(HaveOccurred(), "ovn controller started")
		err = utils.Execute("ovs-vsctl", nil, nil, "list", "bridge", brName)
		Expect(err).ToNot(HaveOccurred(), "transport bridge created")
		link, err := netlink.LinkByName(brName)
		Expect(err).ToNot(HaveOccurred(), "transport bridge interface created")
		ips, err := netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).ToNot(HaveOccurred())
		Expect(ips[0].IPNet).To(Equal(tunnelIP.IPNet), "ip on transport bridge")
		err = utils.Execute("ovs-vsctl", nil, nil, "list", "interface", uplink)
		Expect(err).ToNot(HaveOccurred(), "uplink attached to ovs")

		By("Start OVN controller again")
		svcStatus, err = svcClient.SetOvn(ctx, &rpc.OVNConfig{
			OvnServiceIP:     ovnCentralHostName,
			TunnelEndPointIP: tunnelIP.IP.String(),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "ovn start is idempotent")

		By("Set DHCP relay agent")
		svcStatus, err = svcClient.SetDHCPRelay(ctx, &rpc.DHCPRelay{
			DhcpInterfaceName: dhcpInterface,
			DhcpInterfaceMAC:  dhcpMAC,
			DhcpInterfaceIP:   dhcpIP,
			DhcpServer:        dhcpServer,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "Set up DHCP relay agent")
		err = utils.Execute("ovs-vsctl", nil, nil, "list", "interface", dhcpInterface)
		Expect(err).ToNot(HaveOccurred(), "dhcp interface attached to ovs")
		link, err = netlink.LinkByName(dhcpInterface)
		Expect(err).ToNot(HaveOccurred(), "dhcp interface created")
		Expect(link.Attrs().HardwareAddr.String()).To(Equal(dhcpMAC), "dhcp interface mac set")
		ips, err = netlink.AddrList(link, netlink.FAMILY_V4)
		Expect(err).ToNot(HaveOccurred())
		Expect(ips[0].IPNet.String()).To(Equal(dhcpIP+"/32"), "dhcp interface IP set")
		err = utils.Execute("pgrep", nil, nil, "-f", "/usr/sbin/dhcrelay")
		Expect(err).ToNot(HaveOccurred(), "dhcp relay agent running")

		By("Set DHCP relay agent again")
		svcStatus, err = svcClient.SetDHCPRelay(ctx, &rpc.DHCPRelay{
			DhcpInterfaceName: dhcpInterface,
			DhcpInterfaceMAC:  dhcpMAC,
			DhcpInterfaceIP:   dhcpIP,
			DhcpServer:        dhcpServer,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "Set up DHCP relay agent is idempotent")

		By("Unset DHCP relay agent")
		svcStatus, err = svcClient.SetDHCPRelay(ctx, &rpc.DHCPRelay{
			DhcpInterfaceName: dhcpInterface,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "Unset DHCP relay agent")
		err = utils.Execute("ovs-vsctl", nil, nil, "list", "interface", dhcpInterface)
		Expect(err).To(HaveOccurred(), "dhcp interface detached from ovs")
		_, err = netlink.LinkByName(dhcpInterface)
		Expect(err).To(HaveOccurred(), "dhcp interface created")
		err = utils.Execute("pgrep", nil, nil, "-f", "/usr/sbin/dhcrelay")
		Expect(err).To(HaveOccurred(), "dhcp relay agent not running")

		By("Stop OVN controller")
		svcStatus, err = svcClient.SetOvn(ctx, &rpc.OVNConfig{})
		Expect(err).ToNot(HaveOccurred())
		Expect(svcStatus.GetStatus()).To(Equal(rpc.ErrorCode_OK), "ovn stops")
		err = utils.Execute("pgrep", nil, nil, "-f", "/usr/bin/ovn-controller")
		Expect(err).To(HaveOccurred(), "ovn-controller not running")
		err = utils.Execute("ovs-vsctl", nil, nil, "list", "bridge", "br-int")
		Expect(err).To(HaveOccurred(), "integration bridge removed")
	})
})
