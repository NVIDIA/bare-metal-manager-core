package agent_test

import (
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	brName   = "br-transport"
	uplink   = "eth0"
	hostlink = "hostlink"
	bindPort = ":6662"
)

func TestAgent(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Agent Suite")
}

var _ = BeforeSuite(func() {
	By("starting the test environment")
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	cmd := exec.Command("/usr/share/openvswitch/scripts/ovs-ctl", "--system-id=random", "start")
	err := cmd.Run()
	Expect(err).ToNot(HaveOccurred())
	vethLinkAttrs := netlink.NewLinkAttrs()
	vethLinkAttrs.Name = hostlink

	veth := &netlink.Veth{
		LinkAttrs: vethLinkAttrs,
		PeerName:  hostlink + "-peer",
	}
	err = netlink.LinkAdd(veth)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cmd := exec.Command("/usr/share/openvswitch/scripts/ovs-ctl", "stop")
	err := cmd.Run()
	Expect(err).ToNot(HaveOccurred())
	veth, err := netlink.LinkByName(hostlink)
	Expect(err).ToNot(HaveOccurred())
	err = netlink.LinkDel(veth)
	Expect(err).ToNot(HaveOccurred())
})
