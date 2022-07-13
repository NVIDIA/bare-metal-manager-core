/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

/*
Logical topology bottom-up. This topology enables NATting and on/off ramp network fabric traffic on each local DPU.
1. Distributed Logical Switch
2. Distributed logical router with source-ip based routing
3. transit switch per DPU
4. gateway router per DPU where NATting take place.
5. public switch per DPU to on/off ramp network fabric traffic.
*/

package internal

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/agent"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal/templates"
	"gitlab-master.nvidia.com/forge/vpc/rpc"
)

const (
	ovnNbCtlTimeout    = 10
	agentRPCTimeout    = 5
	agentCheckInterval = 30
	ovnNBDBPort        = 6641

	linuxInterfaceNameSize   = 15
	LinkLocalSubnetPrefixLen = 30
)

type dpuAddState int

const (
	dpuAddStateInit = iota
	dpuAddStateAdding
	dpuAddStateAdded
)

func (s dpuAddState) String() string {
	switch s {
	case dpuAddStateInit:
		return "Init"
	case dpuAddStateAdding:
		return "Adding"
	case dpuAddStateAdded:
		return "Added"
	}
	return "Invalid"
}

var (
	agentBindPort string
)

func init() {
	flag.StringVar(&agentBindPort, "agent-service-port", fmt.Sprintf(":%d", agent.AgentServicePort), "The agent service listening port.")
}

type agentState struct {
	// host/dpu identifier.
	identifier string
	// ovs external_id for host port.
	portExternalID string
	// ovs external_id for dhcp agent port.
	dhcpAgentPortExternalID string
	// network fabric default gateway on dpu.
	fabricDefaultGateway string
	conn                 *grpc.ClientConn
}

// isConnected returns true if agent is alive.
func (a *agentState) isConnected() bool {
	return a.conn != nil
}

type dpuState struct {
	agentState
	dpuIPs  []string
	hostIP  string
	hostMAC string
	// Is not nil if requesting dnat to host.
	dnat *string
	// dpu has been successfully added to logical topology.
	addState dpuAddState
	// K8s ManagedResource corresponding to this DPU.
	key client.ObjectKey
}

func (d *dpuState) IsEmpty() bool {
	return len(d.dpuIPs) == 0 && len(d.hostIP) == 0 && len(d.hostMAC) == 0
}

type networkConfig struct {
	// overlay network
	network string
	// overlay network prefix length
	prefixLen uint32
	// overlay network gateway
	gateway string
	// dhcp server for the overlay network
	dhcpServer string
	// overlay network is ready.
	networkIsReady bool
}

type OvnOverlayNetworkImplementation struct {
	// overlay network of this resource group.
	networkConfig
	resourceGroup string
	mgr           *vpcManager
	// channel to stop this resource group,
	stopChan chan struct{}
	// channel to listen to ovn-central pod changes.
	podChan chan *corev1.Pod
	// OVN central pod's name.
	ovnCentralPodName string
	// OVN central service IP.
	ovnServiceIP string
	log          logr.Logger
	// dpus belongs to this resource group.
	dpus map[string]*dpuState
	// the dpu on which the dhcp relay agent is deployed.
	dhcpRelayLocation *dpuState
}

// NewOvnNetwork returns OverlayNetworkImplementation for resourceGroup.
func NewOvnNetwork(mgr *vpcManager, resourceGroup string) OverlayNetworkImplementation {
	return &OvnOverlayNetworkImplementation{
		mgr:           mgr,
		dpus:          make(map[string]*dpuState),
		resourceGroup: resourceGroup,
		log:           logf.Log.WithName("Ovn-Service-" + resourceGroup),
		podChan:       make(chan *corev1.Pod),
	}
}

// CreateOrUpdateNetwork starts or update the overlay network.
func (i *OvnOverlayNetworkImplementation) CreateOrUpdateNetwork(req *NetworkRequest) error {
	i.log.V(1).Info("CreateOrUpdateNetwork")
	if req.DHCPServer == nil {
		return NewMissingSpecError("DHCPServer")
	}
	if req.IPNet == nil {
		return NewMissingSpecError("Network")
	}

	prefixLen, _ := req.IPNet.Mask.Size()
	if prefixLen < 22 {
		// Assuming a resourceGroup cannot have more than 1K hosts.
		// This is important because we currently use hostIP to derive
		// link local addresses on each gw router. see getLinkLocalIPPair.
		return NewMissingSpecError("Network.PrefixLength")
	}
	i.network = req.IPNet.IP.String()
	i.prefixLen = uint32(prefixLen)
	i.gateway = req.Gateway.String()
	i.dhcpServer = req.DHCPServer.String()
	if err := i.start(); err != nil {
		return err
	}
	if !i.networkIsReady {
		i.log.V(1).Info("CreateOrUpdateNetwork: network is not ready yet.")
		return NewBackendConfigurationInProgress("ovn", "ResourceGroup", i.resourceGroup)
	}
	return nil
}

// AddOrUpdateResourceToNetwork add dpu to resource group and configures overlay network connecting to the dpu.
func (i *OvnOverlayNetworkImplementation) AddOrUpdateResourceToNetwork(req *PortRequest, _ bool) error {
	i.log.V(1).Info("AddOrUpdateResourceToNetwork", "HostInterface", req.Identifier)
	if req.HostIP == nil {
		return NewMissingSpecError("HostInterfaceIP missing")
	}
	if req.HostMAC == nil {
		return NewMissingSpecError("HostInterfaceMAC missing")
	}
	if len(req.Identifier) == 0 {
		return NewMissingSpecError("HostInterface missing")
	}
	if len(req.DPUIPs) < 2 {
		return NewMissingSpecError("DPUIPs must have more than 2 IPs")
	}
	dpu, ok := i.dpus[req.Identifier]
	if !ok {
		dpu = &dpuState{}
		dpu.key = client.ObjectKey{
			Namespace: i.mgr.k8sNamespace,
			Name:      req.name,
		}
		i.dpus[req.Identifier] = dpu
	}
	// DPU IPs changed.
	if len(dpu.dpuIPs) == 0 || req.DPUIPs[0].String() != dpu.dpuIPs[0] {
		if _, err := i.updateAgentState(req.DPUIPs[0].String(), &dpu.agentState); err != nil {
			return err
		}
		if req.Identifier != dpu.identifier {
			return NewMissingSpecError(fmt.Sprintf("HostInterface field mismatch: agentIdentifier=%s",
				dpu.identifier))
		}
		svc := rpc.NewAgentServiceClient(dpu.conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*agentRPCTimeout)
		defer cancel()
		status, err := svc.SetOvn(ctx, &rpc.OVNConfig{
			OvnServiceIP:     i.ovnServiceIP,
			TunnelEndPointIP: req.DPUIPs[0].String(),
		})
		if err != nil || status.Status != rpc.ErrorCode_OK {
			i.log.Error(err, "Failed to setup ovn", "HostInterface", dpu.identifier, "ErrMsg", status.Message)
			return err
		}
		if !dpu.IsEmpty() {
			// Remove stale configurations.
			if err := i.deletePort(dpu); err != nil {
				return err
			}
		}
	}

	dpu.dpuIPs = nil
	for _, ip := range req.DPUIPs {
		dpu.dpuIPs = append(dpu.dpuIPs, ip.String())
	}
	if req.NeedFabricIP {
		dpu.dnat = new(string)
	}
	dpu.hostIP = req.HostIP.String()
	dpu.hostMAC = req.HostMAC.String()
	return i.addPort(dpu)
}

func (i *OvnOverlayNetworkImplementation) DeleteResourceFromNetwork(req *PortRequest) error {
	identifier := req.Identifier
	i.log.V(1).Info("DeleteResourceFromNetwork", "HostInterface", identifier)
	dpu, ok := i.dpus[identifier]
	if !ok {
		i.log.V(1).Info("Resource already deleted", "HostInterface", identifier)
		return nil
	}

	if dpu.isConnected() {
		svc := rpc.NewAgentServiceClient(dpu.conn)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*agentRPCTimeout)
		defer cancel()
		status, err := svc.SetOvn(ctx, &rpc.OVNConfig{})
		if err != nil || status.Status != rpc.ErrorCode_OK {
			return err
		}
	} else {
		i.log.Info("Removing disconnected DPU", "HostInterface", identifier)
	}
	if err := i.deletePort(dpu); err != nil {
		return err
	}
	delete(i.dpus, identifier)
	return nil
}

func (i *OvnOverlayNetworkImplementation) GetNetworkProperties() (*properties.OverlayNetworkProperties, error) {
	i.log.V(1).Info("GetNetworkProperties")
	if !i.networkIsReady {
		return nil, NewBackendConfigurationInProgress("ovn", "ResourceGroup", i.resourceGroup)
	}
	return &properties.OverlayNetworkProperties{
		SwConfig: &v1alpha12.SoftwareNetworkConfiguration{
			OvnService: i.ovnCentralPodName,
		},
	}, nil
}

func (i *OvnOverlayNetworkImplementation) GetResourceProperties(req *PortRequest) (*properties.ResourceProperties, error) {
	i.log.V(1).Info("GetResourceProperties", "HostInterface", req.Identifier)
	dpu, ok := i.dpus[req.Identifier]
	if !ok || dpu.addState != dpuAddStateAdded || !dpu.isConnected() {
		return nil, NewBackendConfigurationInProgress("ovn", "ManagedResource", req.Identifier)
	}
	dnatIP := ""
	if dpu.dnat != nil {
		dnatIP = *dpu.dnat
	}
	return &properties.ResourceProperties{
		LogicalPortReference: &v1alpha12.LogicalPortReference{
			LogicalPort: dpu.portExternalID,
			DPU:         dpu.identifier,
		},
		HostAccessIPs: &v1alpha12.IPAssociation{
			HostIP:   v1alpha12.IPAddress(dpu.hostIP),
			FabricIP: v1alpha12.IPAddress(dnatIP),
		},
	}, nil
}

func (i *OvnOverlayNetworkImplementation) DeleteNetwork() error {
	i.log.V(1).Info("DeleteNetwork")
	return i.stop()
}

func (i *OvnOverlayNetworkImplementation) AddOrUpdateNetworkPolices(_ []*NetworkPolicyRule, _ []string) error {
	// TODO
	return nil
}

func (i *OvnOverlayNetworkImplementation) DeleteNetworkPolices(_ []uint16, _ []string) error {
	return nil

}

func (i *OvnOverlayNetworkImplementation) GetNetworkPolicyProperties(_ string) (*properties.NetworkPolicyProperties, error) {
	return nil, nil
}

// start deploys an ovn-central service for this resource group, and initiates the background watch
func (i *OvnOverlayNetworkImplementation) start() error {
	if i.stopChan != nil {
		i.log.Info("Already started")
		return nil
	}
	ovnServiceName := GetOvnServiceName(i.resourceGroup)
	i.mgr.podController.RegisterListener(ovnServiceName, i.podChan)
	if err := templates.CreateOvnService(ovnServiceName, i.mgr.k8sNamespace, i.mgr.Client); err != nil {
		i.log.Error(err, "start: Failed to deploy ovn-central Service.", "Service", ovnServiceName)
		return err
	}
	i.stopChan = make(chan struct{})
	go i.watch()
	return nil
}

// stop delete the ovn-central services, and terminates the background watch process.
func (i *OvnOverlayNetworkImplementation) stop() error {
	if i.stopChan != nil {
		close(i.stopChan)
		i.stopChan = nil
	}
	ovnServiceName := GetOvnServiceName(i.resourceGroup)
	i.mgr.podController.UnregisterListener(ovnServiceName)
	if err := templates.DeleteOvnService(ovnServiceName, i.mgr.k8sNamespace, i.mgr.Client); err != nil {
		i.log.Error(err, "stop: Failed to delete ovn-central Service.", "Service", ovnServiceName)
		return err
	}
	return nil
}

// watch is background process receiving asynchronous events
func (i *OvnOverlayNetworkImplementation) watch() {
	ticker := time.NewTicker(time.Second)
	enableTicker := false
	for {
		select {
		case <-i.stopChan:
			i.log.Info("watch stops")
			ticker.Stop()
			return
		case pod := <-i.podChan:
			ready := false
			for _, cond := range pod.Status.Conditions {
				if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
					ready = true
					break
				}
			}
			if !ready || pod.Name == i.ovnCentralPodName {
				continue
			}
			enableTicker = true
			i.ovnCentralPodName = pod.Name
			item := &WorkItem{
				Call: func() (interface{}, error) {
					_ = i.updateNetwork(true)
					return nil, nil
				},
				Response: nil,
			}
			i.mgr.getNetwork(i.resourceGroup).WorkQueue.Add(item)
		case <-ticker.C:
			if !enableTicker {
				break
			}
			if time.Now().Second()%agentCheckInterval == 0 {
				item := &WorkItem{
					Call: func() (interface{}, error) {
						i.checkAgents()
						return nil, nil
					},
					Response: nil,
				}
				i.mgr.getNetwork(i.resourceGroup).WorkQueue.Add(item)
			}
			item := &WorkItem{
				Call: func() (interface{}, error) {
					_ = i.checkDHCPRelay()
					return nil, nil
				},
				Response: nil,
			}
			i.mgr.getNetwork(i.resourceGroup).WorkQueue.Add(item)
		}
	}
}

// updateAgentState updates information from the agent. And returns true if agent state changes.
func (i *OvnOverlayNetworkImplementation) updateAgentState(ip string, state *agentState) (bool, error) {
	var err error
	target := ip + agentBindPort
	connected := state.conn != nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*agentRPCTimeout*2)
	defer cancel()
	if state.conn == nil {
		// TODO, use mtls.
		if state.conn, err = grpc.DialContext(ctx, target, grpc.WithInsecure(),
			grpc.WithConnectParams(grpc.ConnectParams{
				MinConnectTimeout: time.Second * agentRPCTimeout,
			})); err != nil {
			i.log.Error(err, "Failed to create connection to agent", "Target", target, "HostInterface", state.identifier)
			return connected, err
		}
	}
	svc := rpc.NewAgentServiceClient(state.conn)
	status, err := svc.AliveProbe(ctx, &rpc.Probe{})
	if err != nil {
		i.log.Error(err, "Probing agent status failed", "Target", target, "HostInterface", state.identifier)
		_ = state.conn.Close()
		state.conn = nil
		return connected, err
	}
	i.log.V(1).Info("Agent status", "Status", status, "HostInterface", state.identifier)
	state.dhcpAgentPortExternalID = status.DhcpExternalID
	state.identifier = status.Identifier
	state.portExternalID = status.PortExternalID
	state.fabricDefaultGateway = status.DefaultGW
	return !connected, nil
}

// checkAgents checks liveness of the agents. And if there are changes, triggering frontend for query.
func (i *OvnOverlayNetworkImplementation) checkAgents() {
	i.log.V(1).Info("checkAgents")
	for identifier, dpu := range i.dpus {
		if len(dpu.dpuIPs) == 0 {
			// DPU setup incomplete, will be retried by controller.
			continue
		}
		if change, _ := i.updateAgentState(dpu.dpuIPs[0], &dpu.agentState); change {
			i.log.V(1).Info("Update agent state change", "HostInterface", dpu.identifier)
			i.mgr.managedResources.NotifyChange(dpu.key.Name)
		}
		if dpu.isConnected() && dpu.identifier != identifier {
			i.log.Error(nil, "DPU identifier mismatch",
				"ClientIdentifier", identifier, "AgentIdentifier", dpu.identifier)
			// TODO how to handle ??
		}
	}
}

// updateNetwork updates the overlay network configuration.
func (i *OvnOverlayNetworkImplementation) updateNetwork(retry bool) error {
	i.log.V(1).Info("updateNetwork", "Retry", retry, "ovn-central", i.ovnCentralPodName)
	var err error
	defer func() {
		if err == nil {
			i.networkIsReady = true
		} else {
			i.networkIsReady = false
		}
		if err != nil && retry {
			i.log.Error(err, "Failed to update logical network topology, retry")
			item := &WorkItem{
				Call: func() (interface{}, error) {
					_ = i.updateNetwork(true)
					return nil, nil
				},
				Response: nil,
			}
			i.mgr.getNetwork(i.resourceGroup).WorkQueue.Add(item)
		}
	}()

	if len(i.ovnServiceIP) == 0 {
		ovnService := &corev1.Service{}
		key := client.ObjectKey{
			Namespace: i.mgr.k8sNamespace,
			Name:      GetOvnServiceName(i.resourceGroup),
		}
		err = i.mgr.Client.Get(context.Background(), key, ovnService)
		if err != nil || len(ovnService.Spec.ClusterIP) == 0 {
			if err != nil {
				err = fmt.Errorf("ovn service not ready")
			}
			return err
		}
		i.ovnServiceIP = ovnService.Spec.ClusterIP
		i.log.V(1).Info("Ovn service IP found", "IP", i.ovnServiceIP)
	}

	if err = i.addNetwork(); err != nil {
		return nil
	}

	for _, dpu := range i.dpus {
		if err = i.addPort(dpu); err != nil {
			return err
		}
	}
	return err
}

// addNetwork configures overlay networks via ovn central.
func (i *OvnOverlayNetworkImplementation) addNetwork() error {
	lsName := getLSName(i.resourceGroup)
	lrName := getLRName(i.resourceGroup)
	lspName := getLSToLRPortName(i.resourceGroup, "")
	lrpName := getLRToLSPortName(i.resourceGroup, "")
	gwMAC := GetMACFromIP(i.gateway)
	gwIP := fmt.Sprintf("%s/%d", i.gateway, i.prefixLen)
	cmds := [][]string{
		// Connect LS with LR and configures overlay L2 gateway.
		{"--may-exist", "ls-add", lsName},
		{"--may-exist", "lr-add", lrName},
		{"--may-exist", "lsp-add", lsName, lspName},
		{"lsp-set-type", lspName, "router"},
		{"lsp-set-addresses", lspName, "router"},
		{"lsp-set-options", lspName, "router-port=" + lrpName},
		{"--may-exist", "lrp-add", lrName, lrpName, gwMAC, gwIP},
	}
	for _, cmd := range cmds {
		if err := i.ovnNbctl(cmd); err != nil {
			i.log.Error(err, "addNetwork: Failed to execute", "Command", cmd)
			return err
		}
	}
	return nil
}

// addPort attaches DPU to overlay network via ovn central.
// It also creates and connects gw router and transit switch for distributed NATting.
func (i *OvnOverlayNetworkImplementation) addPort(dpu *dpuState) error {
	dpu.addState = dpuAddStateAdding
	lsName := getLSName(i.resourceGroup)
	lrName := getLRName(i.resourceGroup)
	lspName := dpu.portExternalID
	transitSwitchName := getTransitLSName(dpu.identifier)
	publicSwitchName := getPublicLSName(dpu.identifier)
	gwRouterName := getGwLRName(dpu.identifier)
	lslrTransitPort := getLSToLRPortName(dpu.identifier, "transit")
	lrlsTransitPort := getLRToLSPortName(dpu.identifier, "transit")
	lrGwIP, gwLRIP := getLinkLocalIPPair(dpu.hostIP, i.prefixLen)
	lrGwMAC := GetMACFromIP(lrGwIP)
	lslrGwPort := getLSToLRPortName(dpu.identifier, "gw")
	lrlsGwPort := getLRToLSPortName(dpu.identifier, "gw")
	gwLRMAC := GetMACFromIP(gwLRIP)
	lslrPublicPort := getLSToLRPortName(dpu.identifier, "pubic")
	lrlsPublicPort := getLRToLSPortName(dpu.identifier, "public")
	gwPublicIP := getDummyFabricIP(dpu.fabricDefaultGateway)
	gwPublicMAC := GetMACFromIP(gwPublicIP)
	publicLSPName := getPublicLSPName(dpu.identifier)
	cmds := [][]string{
		// Add host port to LS
		{"--may-exist", "lsp-add", lsName, lspName},
		{"lsp-set-addresses", lspName, fmt.Sprintf("%s %s", dpu.hostMAC, dpu.hostIP)},
		// Create gw router and connect gw router to LR via transit switch.
		// gw router is tied to the dpu.
		{"--may-exist", "ls-add", transitSwitchName},
		{"--may-exist", "lr-add", gwRouterName},
		{"set", "logical_router", gwRouterName, fmt.Sprintf("options:chassis=%s", dpu.identifier)},
		// Connect transit switch to LR
		{"--may-exist", "lsp-add", transitSwitchName, lslrTransitPort},
		{"lsp-set-type", lslrTransitPort, "router"},
		{"lsp-set-addresses", lslrTransitPort, "router"},
		{"lsp-set-options", lslrTransitPort, fmt.Sprintf("router-port=%s", lrlsTransitPort)},
		{"--may-exist", "lrp-add", lrName, lrlsTransitPort, lrGwMAC, lrGwIP + fmt.Sprintf("/%d", LinkLocalSubnetPrefixLen)},
		// Connect transit switch to gw router
		{"--may-exist", "lsp-add", transitSwitchName, lslrGwPort},
		{"lsp-set-type", lslrGwPort, "router"},
		{"lsp-set-addresses", lslrGwPort, "router"},
		{"lsp-set-options", lslrGwPort, fmt.Sprintf("router-port=%s", lrlsGwPort)},
		{"--may-exist", "lrp-add", gwRouterName, lrlsGwPort, gwLRMAC, gwLRIP + fmt.Sprintf("/%d", LinkLocalSubnetPrefixLen)},
		// Add a public switch to send/receive traffic from fabric.
		{"--may-exist", "ls-add", publicSwitchName},
		// Connect the public switch to the gw router.
		{"--may-exist", "lsp-add", publicSwitchName, lslrPublicPort},
		{"lsp-set-type", lslrPublicPort, "router"},
		{"lsp-set-addresses", lslrPublicPort, "router"},
		{"lsp-set-options", lslrPublicPort, fmt.Sprintf("router-port=%s", lrlsPublicPort)},
		// TODO hard coded fabric subnet mask for now.
		{"--may-exist", "lrp-add", gwRouterName, lrlsPublicPort, gwPublicMAC, gwPublicIP + "/16"},
		// Connect the public switch to fabric.
		{"--may-exist", "lsp-add", publicSwitchName, publicLSPName},
		{"lsp-set-type", publicLSPName, "localnet"},
		{"lsp-set-addresses", publicLSPName, "unknown"},
		{"lsp-set-options", publicLSPName, fmt.Sprintf("network_name=%s", agent.OvnProvider)},
		// Add routes to LR and gw router
		{"--may-exist", "--policy=src-ip", "lr-route-add", lrName, dpu.hostIP, gwLRIP},
		{"--may-exist", "lr-route-add", gwRouterName, dpu.hostIP, lrGwIP},
		{"--may-exist", "lr-route-add", gwRouterName, "0.0.0.0/0", dpu.fabricDefaultGateway},
		// snat on gw router
		{"--may-exist", "lr-nat-add", gwRouterName, "snat", dpu.dpuIPs[1], dpu.hostIP},
	}
	if dpu.dnat != nil {
		*dpu.dnat = dpu.dpuIPs[1]
		cmds = append(cmds,
			[]string{"--may-exist", "lr-nat-add", gwRouterName, "dnat", dpu.dpuIPs[1], dpu.hostIP},
		)
	}
	//TODO for public ip,
	for _, cmd := range cmds {
		if err := i.ovnNbctl(cmd); err != nil {
			i.log.Error(err, "addPort: Failed to execute", "Command", cmd)
			return err
		}
	}
	dpu.addState = dpuAddStateAdded
	return nil
}

// deletePort detaches DPU from overlay network via ovn central.
// It also removes gw router and transit switch and dpu.
func (i *OvnOverlayNetworkImplementation) deletePort(dpu *dpuState) error {
	oldState := dpu.addState
	dpu.addState = dpuAddStateInit
	if oldState < dpuAddStateAdding {
		return nil
	}
	lrName := getLRName(i.resourceGroup)
	lspName := dpu.portExternalID
	transitSwitchName := getTransitLSName(dpu.identifier)
	publicSwitchName := getPublicLSName(dpu.identifier)
	gwRouterName := getGwLRName(dpu.identifier)
	lrlsTransitPort := getLRToLSPortName(dpu.identifier, "transit")

	cmds := [][]string{
		// Remove route on LR
		{"--if-exists", "--policy=src-ip", "lr-route-del", lrName, dpu.hostIP},
		// Remove LSP on LS
		{"--if-exists", "lsp-del", lspName},
		// Remove gw router, public switch, transit switch.
		{"--if-exists", "ls-del", transitSwitchName},
		{"--if-exists", "ls-del", publicSwitchName},
		{"--if-exists", "lr-del", gwRouterName},
		{"--if-exists", "lrp-del", lrlsTransitPort},
	}
	for _, cmd := range cmds {
		if err := i.ovnNbctl(cmd); err != nil {
			i.log.Error(err, "deletePort: Failed to execute", "Command", cmd)
			return err
		}
	}
	return i.setDHCPPort(dpu, false)
}

// setDHCPPort set dhcp relay port on the overlay network.
func (i *OvnOverlayNetworkImplementation) setDHCPPort(dpu *dpuState, isAdd bool) error {
	lsName := getLSName(i.resourceGroup)
	dhcpPortName := dpu.dhcpAgentPortExternalID
	cmds := [][]string{
		{"--may-exist", "lsp-add", lsName, dhcpPortName},
	}
	if !isAdd {
		cmds = [][]string{
			{"--if-exist", "lsp-del", dhcpPortName},
		}
	}
	for _, cmd := range cmds {
		if err := i.ovnNbctl(cmd); err != nil {
			i.log.Error(err, "setDHCPPort: Failed to execute", "Command", cmd)
			return err
		}
	}
	return nil
}

// checkDHCPRelay updates relay agent on a DPU.
func (i *OvnOverlayNetworkImplementation) checkDHCPRelay() error {
	i.log.V(1).Info("checkDHCPRelay")
	if i.dhcpRelayLocation != nil {
		if i.dhcpRelayLocation.isConnected() {
			// No change to dhcp relay.
			return nil
		}
		if err := i.setDHCPPort(i.dhcpRelayLocation, false); err != nil {
			return err
		}
		i.dhcpRelayLocation = nil
	}
	var candidate *dpuState
	for _, dpu := range i.dpus {
		if dpu.addState == dpuAddStateAdded && dpu.isConnected() {
			candidate = dpu
			break
		}
	}
	if candidate == nil {
		return nil
	}

	i.log.V(1).Info("Configure DHCP relay agent", "HostInterface", candidate.identifier)
	agentClient := rpc.NewAgentServiceClient(candidate.conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*agentRPCTimeout)
	defer cancel()

	ip := i.gateway
	mac := GetMACFromIP(ip)
	if status, err := agentClient.SetDHCPRelay(ctx, &rpc.DHCPRelay{
		DhcpInterfaceName: GetDHCPPortName(i.resourceGroup),
		DhcpInterfaceMAC:  mac,
		DhcpInterfaceIP:   ip,
		DhcpServer:        i.dhcpServer,
	}); err != nil {
		i.log.Error(err, "Failed to set dhcp agent", "HostInterface", candidate.identifier)
		return err
	} else if status.GetStatus() != rpc.ErrorCode_OK {
		i.log.Error(err, "Failed to set dhcp agent", "HostInterface", candidate.identifier, "ErrorMsg", status.Message)
		return err
	}
	if err := i.setDHCPPort(candidate, true); err != nil {
		return err
	}
	i.dhcpRelayLocation = candidate
	return nil
}

func (i *OvnOverlayNetworkImplementation) ovnNbctl(_args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*ovnNbCtlTimeout)
	defer cancel()
	args := make([]string, 0)
	// TODO add certificates
	args = append(args, "--db", fmt.Sprintf("tcp:%s:%d", i.ovnServiceIP, ovnNBDBPort))
	args = append(args, _args...)
	out := &bytes.Buffer{}
	err := utils.ExecuteWithContext(ctx, "ovn-nbctl", nil, out, args...)
	if err != nil {
		i.log.V(1).Info("Command failed", "Output", out.String())
	}
	return err
}

func getLSName(rg string) string {
	return rg
}

func getLRName(rg string) string {
	return rg
}

func getLSToLRPortName(id, opt string) string {
	if len(opt) > 0 {
		return fmt.Sprintf("ls-lr-%s-%s", opt, id)
	}
	return fmt.Sprintf("ls-lr-%s", id)
}

func getLRToLSPortName(id, opt string) string {
	if len(opt) > 0 {
		return fmt.Sprintf("lr-ls-%s-%s", opt, id)
	}
	return fmt.Sprintf("lr-ls-%s", id)
}

func getTransitLSName(sysID string) string {
	return "transit-" + sysID
}

func getPublicLSName(sysID string) string {
	return "public-" + sysID
}

func getPublicLSPName(sysID string) string {
	return "public-" + sysID
}

func getGwLRName(sysID string) string {
	return "gw-" + sysID
}

func GetMACFromIP(gwIP string) string {
	var gwMAC net.HardwareAddr = make([]byte, 2)
	gwMAC = append(gwMAC, net.ParseIP(gwIP)[12:]...)
	return gwMAC.String()
}

// getLinkLocalIPPair returns link-local IP pairs used on transit switch.
func getLinkLocalIPPair(hostIP string, prefixLen uint32) (string, string) {
	ip := net.ParseIP(hostIP).To4()
	mask := net.CIDRMask(int(prefixLen), 32)
	for i, b := range mask {
		mask[i] = ^b
	}

	// last byte shift 2
	b3 := (ip[3] & mask[3]) << 2
	// second last byte shift 2 plus carrie over from last byte.
	b2 := (ip[2]&mask[2])<<2 | (ip[3]&mask[3])>>6
	baseIP := net.IP{169, 254, b2, b3}
	o1 := baseIP.String()
	baseIP[3] += 1
	o2 := baseIP.String()
	return o1, o2
}

// getDummyFabricIP returns a dummy IP (never used) assigned to uplink gw router.
// It is (TODO) currently derived from fabricGwIP,
func getDummyFabricIP(fabricGwIP string) string {
	ip := net.ParseIP(fabricGwIP).To4()
	ip[3] = 255
	return ip.String()
}

func GetOvnServiceName(resourceGroup string) string {
	return "ovn-central-" + resourceGroup
}

func GetDHCPPortName(resourceGroup string) string {
	s := "dh-" + resourceGroup
	if len(s) > linuxInterfaceNameSize {
		s = s[:linuxInterfaceNameSize]
	}
	return s
}
