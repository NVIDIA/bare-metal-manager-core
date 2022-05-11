/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/wait"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
	"gitlab-master.nvidia.com/forge/vpc/rpc"
)

const (
	OvnProvider      = "provider"
	AgentServicePort = 6666

	ovsIntegrationBridgeName = "br-int"
	ovnSBDBPort              = 6642
	ovsVsCtlBin              = "/usr/bin/ovs-vsctl"
	ovnControllerBin         = "/usr/bin/ovn-controller"
	dhcrelayBin              = "/usr/sbin/dhcrelay"
)

var (
	_ rpc.AgentServiceServer = &VPCAgent{}
)

// VPCAgent sets up environment to run ovn-controller.
type VPCAgent struct {
	rpc.UnimplementedAgentServiceServer
	sync.Mutex
	log logr.Logger
	// transport bridge name.
	transportBrName string
	// uplink name
	uplinkName string
	// hostLink name
	hostLinkName string
	// OVN externalID of host link.
	ovnHostLinkExternalID string
	// OVN externalID of dhcp relay port.
	ovnDHCPLinkExteranlID string
	// agentService bind port.
	bindPort string
	// DPU identifier, use as OVN system/chassis ID.
	identifier string
	// default gw.
	fabricDefaultGW net.IP
	// chan to stop ovn controller
	ovnStop chan struct{}
	// grpcServer
	grpcServer *grpc.Server
}

func NewVPCAgent(transportBrName, uplinkName, hostLinkName, bindPort string) *VPCAgent {
	ret := &VPCAgent{
		log:             logf.Log.WithName("VPCAgent"),
		transportBrName: transportBrName,
		uplinkName:      uplinkName,
		hostLinkName:    hostLinkName,
		bindPort:        bindPort,
	}
	ret.identifier, _ = os.Hostname()
	ret.ovnHostLinkExternalID = fmt.Sprintf("%s-%s", ret.identifier, ret.hostLinkName)
	ret.ovnDHCPLinkExteranlID = fmt.Sprintf("%s-dhcp", ret.identifier)
	return ret
}

func (agent *VPCAgent) Start(certDir string) error {
	if len(certDir) > 0 {
		// TODO mTLS.
	} else {
		agent.grpcServer = grpc.NewServer()
	}
	rpc.RegisterAgentServiceServer(agent.grpcServer, agent)
	lis, err := net.Listen("tcp", agent.bindPort)
	if err != nil {
		agent.log.Error(err, "Failed to listen", "BindAddr", agent.bindPort)
		return err
	}
	agent.log.Info("gRPC server listening on", "BindAddr", lis.Addr())
	if err := agent.grpcServer.Serve(lis); err != nil {
		agent.log.Error(err, "Server failed to serve, exit ...")
		return err
	}
	agent.log.Info("gRPC Server exited")
	return nil
}

func (agent *VPCAgent) Stop() {
	agent.log.Info("Stopping ...")
	agent.Lock()
	defer agent.Unlock()

	if agent.ovnStop != nil {
		agent.ovnStop <- struct{}{}
		close(agent.ovnStop)
		agent.ovnStop = nil
	}
	if agent.grpcServer != nil {
		agent.grpcServer.Stop()
		agent.grpcServer = nil
	}
}

func (agent *VPCAgent) AliveProbe(_ context.Context, _ *rpc.Probe) (*rpc.AgentStatus, error) {
	agent.log.V(1).Info("AliveProbe")
	agent.Lock()
	defer agent.Unlock()
	gw, err := getFabricGW()
	if err != nil {
		agent.log.Error(err, "Failed to get fabric default gateway")
		return nil, err
	}

	return &rpc.AgentStatus{
		Status:         &rpc.ServiceStatus{Status: rpc.ErrorCode_OK},
		Identifier:     agent.identifier,
		PortExternalID: agent.ovnHostLinkExternalID,
		DhcpExternalID: agent.ovnDHCPLinkExteranlID,
		DefaultGW:      gw.String(),
	}, nil
}

func (agent *VPCAgent) SetOvn(_ context.Context, config *rpc.OVNConfig) (*rpc.ServiceStatus, error) {
	agent.log.V(1).Info("SetOvn")
	agent.Lock()
	defer agent.Unlock()
	status := &rpc.ServiceStatus{Status: rpc.ErrorCode_OK}
	if len(config.GetOvnServiceIP()) == 0 {
		// Best effort kill dhcp relay agent.
		agent.log.Info("Stopping OVN controller", "Config", config)
		_ = utils.Execute("pkill", nil, nil, "-f", dhcrelayBin)
		if agent.ovnStop == nil {
			agent.log.V(1).Info("Ovn controller already stopped")
			return status, nil
		}
		agent.ovnStop <- struct{}{}
		close(agent.ovnStop)
		agent.ovnStop = nil
		if err := wait.Poll(time.Second*10, time.Second, func() (bool, error) {
			if err := utils.Execute("pgrep", nil, nil, "-f", ovnControllerBin); err == nil {
				return false, nil
			}
			if err := utils.Execute(ovsVsCtlBin, nil, nil, "list", "bridge", ovsIntegrationBridgeName); err == nil {
				return false, nil
			}
			return true, nil
		}); err != nil {
			agent.log.Error(err, "Failed to stop OVN")
			status.Status = rpc.ErrorCode_OpFailed
			status.Message = err.Error()
		}
		return status, nil
	}
	agent.log.Info("Starting OVN controller", "Config", config)
	if agent.ovnStop != nil {
		agent.log.V(1).Info("Ovn controller already started")
		return status, nil
	}
	agent.ovnStop = make(chan struct{})
	if err := agent.startOvnController(config.GetTunnelEndPointIP(), config.GetOvnServiceIP(), ovnSBDBPort); err != nil {
		agent.log.Error(err, "Failed to start OVN")
		status.Status = rpc.ErrorCode_OpFailed
		status.Message = err.Error()
	}
	return status, nil
}

func (agent *VPCAgent) SetDHCPRelay(_ context.Context, config *rpc.DHCPRelay) (*rpc.ServiceStatus, error) {
	agent.log.V(1).Info("SetDHCPRelay")
	agent.Lock()
	defer agent.Unlock()
	status := &rpc.ServiceStatus{Status: rpc.ErrorCode_OK}
	links, err := netlink.LinkList()
	if err != nil {
		agent.log.Error(err, "Failed to list links")
		status.Status = rpc.ErrorCode_OpFailed
		status.Message = err.Error()
		return status, nil
	}

	// Remove
	if len(config.GetDhcpServer()) == 0 {
		agent.log.Info("Remove DHCP relay agent", "Config", config)
		var err error
		if err = utils.Execute("pkill", nil, nil, "-f", dhcrelayBin); err != nil {
			// TODO check first if dhcagent is running before killing it.
			agent.log.Error(err, "Failed to remove dhcp relay agent")
		}
		for _, link := range links {
			if link.Attrs().Name == config.GetDhcpInterfaceName() {
				if err = utils.Execute(ovsVsCtlBin, nil, nil, "--if-exists", "del-port", ovsIntegrationBridgeName,
					link.Attrs().Name); err != nil {
					agent.log.Error(err, "Failed to remove dhcp port", "Bridge", ovsIntegrationBridgeName, "Port", link.Attrs().Name)
				}
				break
			}
		}
		if err != nil {
			status.Status = rpc.ErrorCode_OpFailed
			status.Message = err.Error()
		}
		return status, nil
	}

	agent.log.Info("Add DHCP relay agent", "Config", config)
	if err := utils.Execute(ovsVsCtlBin, nil, nil, "--may-exist", "add-port", ovsIntegrationBridgeName, config.GetDhcpInterfaceName(),
		"--", "set", "interface", config.GetDhcpInterfaceName(), "type=internal",
		"--", "set", "interface", config.GetDhcpInterfaceName(),
		fmt.Sprintf("external_ids:iface-id=\"%s\"", agent.ovnDHCPLinkExteranlID),
		"--", "set", "interface", config.GetDhcpInterfaceName(),
		fmt.Sprintf("mac=\"%s\"", config.GetDhcpInterfaceMAC())); err != nil {
		agent.log.Error(err, "Failed to add dhcp port to ovs", "Bridge", ovsIntegrationBridgeName, "Port", config.GetDhcpInterfaceName())
		status.Status = rpc.ErrorCode_OpFailed
		status.Message = err.Error()
		return status, nil
	}

	if err = wait.Poll(time.Second*10, time.Second, func() (bool, error) {
		link, err := netlink.LinkByName(config.GetDhcpInterfaceName())
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				return false, nil
			}
			return false, err
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return false, err
		}
		_, ipnet, err := net.ParseCIDR(config.GetDhcpInterfaceIP() + "/32")
		if err != nil {
			return false, err
		}
		addr := &netlink.Addr{IPNet: ipnet}
		return true, netlink.AddrReplace(link, addr)
	}); err != nil {
		status.Status = rpc.ErrorCode_OpFailed
		status.Message = err.Error()
		return status, nil
	}

	// kill dhcp agent just be safe.
	_ = utils.Execute("pkill", nil, nil, "-f", dhcrelayBin)
	if err := utils.Execute(dhcrelayBin, nil, nil, "-4", "-U", agent.transportBrName,
		"-i", config.GetDhcpInterfaceName(), config.GetDhcpServer()); err != nil {
		agent.log.Error(err, "Failed to start dhcp relay agent", "DHCP-uplink", agent.transportBrName,
			"Listen-interface", config.GetDhcpInterfaceName(), "DHCP-Server", config.GetDhcpServer())
		status.Status = rpc.ErrorCode_OpFailed
		status.Message = err.Error()
	}
	return status, nil
}

func (agent *VPCAgent) startOvnController(encapIP, ovnCentral string, ovnCentralPort uint16) error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	var transport, uplink, hostLink netlink.Link
	var ipAddr *netlink.Addr
	var ipOnTransport, ipOnUplink bool
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		tmpLink := link
		if link.Attrs().Name == agent.uplinkName {
			uplink = tmpLink
		} else if link.Attrs().Name == agent.transportBrName {
			transport = tmpLink
		} else if link.Attrs().Name == agent.hostLinkName {
			hostLink = tmpLink
		}
		for _, addr := range addrs {
			tmpAddr := addr
			if addr.IP.String() == encapIP {
				if link.Attrs().Name == agent.uplinkName {
					ipOnUplink = true
				} else if link.Attrs().Name == agent.transportBrName {
					ipOnTransport = true
				} else {
					return fmt.Errorf("encapsulation IP %s is assigned to an unmanaged interface %s",
						encapIP, link.Attrs().Name)
				}
				ipAddr = &tmpAddr
			}
		}
	}

	if hostLink == nil {
		return fmt.Errorf("hostLink %s is not found", agent.hostLinkName)
	}
	if uplink == nil {
		return fmt.Errorf("uplink %s is not found", agent.uplinkName)
	}
	if ipAddr == nil {
		return fmt.Errorf("encap IP %s is not found", encapIP)
	}
	if err := agent.setupTransport(uplink, transport, ipAddr, ipOnUplink, ipOnTransport); err != nil {
		agent.log.V(1).Info("setupTransport failed")
		return err
	}

	// Setup ovsdb fields for ovn-controller
	if err := utils.Execute(ovsVsCtlBin, nil, nil, "set", "open_vswitch", ".",
		fmt.Sprintf("external_ids:ovn-remote=\"tcp:%s:%d\"", ovnCentral, ovnCentralPort),
		fmt.Sprintf("external_ids:ovn-encap-ip=\"%s\"", ipAddr.IP.String()),
		"external_ids:ovn-encap-type=geneve",
		fmt.Sprintf("external_ids:system-id=\"%s\"", agent.getSystemID()),
		fmt.Sprintf("external_ids:ovn-bridge-mappings=\"%s:%s\"",
			OvnProvider, agent.transportBrName)); err != nil {
		return err
	}

	// Start ovn controller
	err = utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "restart_controller")
	if err != nil {
		return err
	}
	if err = wait.Poll(time.Second, time.Second*100, func() (bool, error) {
		if _, err = netlink.LinkByName(ovsIntegrationBridgeName); err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				agent.log.V(1).Info("Bridge not found", "Name", ovsIntegrationBridgeName)
				return false, nil
			}
			return false, err
		}
		if err := netlink.LinkSetUp(hostLink); err != nil {
			return false, err
		}
		return true, utils.Execute(ovsVsCtlBin, nil, nil, "--may-exist",
			"add-port", ovsIntegrationBridgeName, agent.hostLinkName, "--",
			"set", "Interface", agent.hostLinkName, fmt.Sprintf("external_ids:iface-id=\"%s\"", agent.ovnHostLinkExternalID))
	}); err != nil {
		return err
	}

	// Enter monitoring loop in the background.
	go func() {
		ticker := time.NewTicker(time.Second * 10)
		for {
			select {
			case <-agent.ovnStop:
				agent.log.Info("Ovn controller Exiting")
				ticker.Stop()
				if err := utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "stop_controller"); err != nil {
					agent.log.Error(err, "Failed to stop OVN controller")
				}
				if err := utils.Execute(ovsVsCtlBin, nil, nil, "--if-exists", "del-br", ovsIntegrationBridgeName); err != nil {
					agent.log.Error(err, "Failed to delete integration bridge")
				}
				return
			case <-ticker.C:
				if err := utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "status_controller"); err != nil {
					agent.log.Error(err, "OVN controller existed, restarting")
					if err := utils.Execute("/usr/share/ovn/scripts/ovn-ctl", nil, nil, "restart_controller"); err != nil {
						agent.log.Error(err, "OVN controller failed to restart")
					}
				}
			}
		}
	}()
	return nil
}

func (agent *VPCAgent) setupTransport(uplink, transport netlink.Link, ipAddr *netlink.Addr,
	ipOnUplink, ipOnTransport bool) error {

	agent.log.V(1).Info("setupTransport", "onUplink", ipOnUplink, "onTransport", ipOnTransport)
	// Create transport bridge.
	var err error
	if transport == nil {
		if err = utils.Execute(ovsVsCtlBin, nil, nil, "--may-exist", "add-br",
			agent.transportBrName); err != nil {
			return err
		}
		if err := wait.Poll(time.Second*10, time.Millisecond*100, func() (bool, error) {
			var err error
			transport, err = netlink.LinkByName(agent.transportBrName)
			if err != nil {
				return false, nil
			}
			return true, nil
		}); err != nil {
			return err
		}
	}

	if err := netlink.LinkSetUp(transport); err != nil {
		return err
	}

	if ipOnTransport {
		return nil
	}

	// Remove IP on uplink and add it to the transport.
	var savedRts []netlink.Route
	if ipOnUplink {
		var err error
		savedRts, err = netlink.RouteList(uplink, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if err = netlink.AddrDel(uplink, ipAddr); err != nil {
			return err
		}
	}

	// Add uplink to transport bridge.
	if err = utils.Execute(ovsVsCtlBin, nil, nil, "--may-exist",
		"add-port", agent.transportBrName, agent.uplinkName); err != nil {
		return err
	}

	// Assign IP to transport bridge.
	newIP := &netlink.Addr{
		IPNet:     ipAddr.IPNet,
		Flags:     ipAddr.Flags,
		Scope:     ipAddr.Scope,
		Peer:      ipAddr.Peer,
		Broadcast: ipAddr.Broadcast,
	}
	if err = netlink.AddrAdd(transport, newIP); err != nil {
		return err
	}

	// Add uplink routes to transport bridge.
	for _, rt := range savedRts {
		rt.LinkIndex = transport.Attrs().Index
		if err = netlink.RouteReplace(&rt); err != nil {
			return err
		}
	}
	return nil
}

func (agent *VPCAgent) getSystemID() string {
	return agent.identifier
}

func getFabricGW() (net.IP, error) {
	rts, err := netlink.RouteGet(net.ParseIP("8.8.8.8"))
	if len(rts) != 1 {
		return nil, fmt.Errorf("default route not found, err=%v", err)
	}
	return rts[0].Gw, nil
}
