/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"net"
	"reflect"

	v1alpha12 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

type NetworkPolicyDirection int

const (
	NetworkPolicyDirectionEgress NetworkPolicyDirection = iota
	NetworkPolicyDirectionIngress
)

// NetworkPolicyResource specifies K8s resources on which an NetworkPolicy may apply, identified by its Kind and Key.
type NetworkPolicyResource struct {
	Kind                   string
	Name                   string
	Identifier             string
	Labels                 map[string]string
	HostIP                 net.IP
	Status                 bool
	IsDelete               bool
	AppliedNetworkPolicies []string
}

func (n *NetworkPolicyResource) Key() string {
	if n.Kind == v1alpha12.LeafName {
		return getInternalNetworkDeviceName(n.Kind, n.Name)
	}
	return n.Kind + ":" + n.Name
}

func (n *NetworkPolicyResource) Populate(resource interface{}) *NetworkPolicyResource {
	if leaf, ok := resource.(*v1alpha12.Leaf); ok {
		var hostIP net.IP
		for _, ipStr := range leaf.Spec.HostAdminIPs {
			if len(hostIP) > 0 {
				hostIP = net.ParseIP(ipStr)
				break
			}
		}
		return &NetworkPolicyResource{
			Kind:                   v1alpha12.LeafName,
			Name:                   leaf.Name,
			Labels:                 leaf.Labels,
			Status:                 IsNetworkDeviceAlive(leaf),
			AppliedNetworkPolicies: leaf.Status.NetworkPolicies,
			HostIP:                 hostIP,
		}
	}
	mr := resource.(*v1alpha1.ManagedResource)
	return &NetworkPolicyResource{
		Kind:                   v1alpha1.ManagedResourceName,
		Name:                   mr.Name,
		Labels:                 mr.Labels,
		Status:                 IsManagedResourceReady(mr),
		AppliedNetworkPolicies: mr.Status.NetworkPolicies,
		Identifier:             mr.Spec.HostInterface,
		HostIP:                 net.ParseIP(string(mr.Spec.HostInterfaceIP)),
	}
}

func (n *NetworkPolicyResource) ConfigEqual(other *NetworkPolicyResource) bool {
	if n.HostIP.String() != other.HostIP.String() {
		return false
	}
	if n.Identifier != other.Identifier {
		return false
	}
	if len(n.Labels) != len(other.Labels) {
		return false
	}
	for k, v := range n.Labels {
		if vv, ok := other.Labels[k]; !ok || v != vv {
			return false
		}
	}
	return true
}

type NetworkPolicyPorts struct {
	Ports    []uint16
	Protocol string
}

type NetworkPolicyAddress struct {
	Addresses []string
	Selectors []map[string]string
	Ports     []NetworkPolicyPorts
	Related   bool
}

// NetworkPolicy is the internal interpretation of NetworkPolicy CRD.
type NetworkPolicy struct {
	Name                    string
	ManagedResourceSelector map[string]string
	LeafSelector            map[string]string
	Ingress                 []NetworkPolicyAddress
	Egress                  []NetworkPolicyAddress
	ID                      uint16
	Drop                    bool
	stateless               bool
	IsDelete                bool
}

// convert network address from CRD to internal NetworkPolicyAddress
func convertNetworkPolicyAddress(addresses []v1alpha1.NetworkPolicyAddress, ports []v1alpha1.NetworkPolicyPort) NetworkPolicyAddress {
	npAddr := NetworkPolicyAddress{}
	for _, addr := range addresses {
		if len(addr.IPCIDR) > 0 {
			npAddr.Addresses = append(npAddr.Addresses, string(addr.IPCIDR))
		}
		if len(addr.ManagedResourceSelector.MatchLabels) > 0 {
			npAddr.Selectors = append(npAddr.Selectors, addr.ManagedResourceSelector.MatchLabels)
		}
	}
	if len(ports) == 0 {
		// No ports specified, allow all traffic.
		npAddr.Ports = append(npAddr.Ports,
			NetworkPolicyPorts{
				Protocol: string(v1alpha1.NetworkPolicyProtocolUDP)},
			NetworkPolicyPorts{
				Protocol: string(v1alpha1.NetworkPolicyProtocolTCP)},
			NetworkPolicyPorts{
				Protocol: string(v1alpha1.NetworkPolicyProtocolICMP)})
	} else {
		for _, port := range ports {
			if port.Begin > 0 {
				begin := port.Begin
				end := begin + 1
				if port.End > 0 {
					end = port.End
				}
				tPorts := NetworkPolicyPorts{
					Protocol: string(port.Protocol),
				}
				for p := begin; p < end; p++ {
					tPorts.Ports = append(tPorts.Ports, uint16(p))
				}
				npAddr.Ports = append(npAddr.Ports, tPorts)
			}
		}
	}
	return npAddr
}

// Insert NetworkPolicyRules derived from addresses and insert into rules.
func insertNetworkPolicyRules(addresses []NetworkPolicyAddress, dir NetworkPolicyDirection, devicePort string,
	mgr *NetworkPolicyManager, rules *NetworkPolicyRules) {
	for _, i := range addresses {
		// Expand IP addresses.
		var ipnets []*net.IPNet
		for _, addr := range i.Addresses {
			_, ipnet, _ := net.ParseCIDR(addr)
			ipnets = append(ipnets, ipnet)
		}
		var hostIPs []net.IP
		for _, selector := range i.Selectors {
			hostIPs = append(hostIPs, mgr.getResourceIPsByLabels(selector)...)
		}
		for _, hostIP := range hostIPs {
			ipnets = append(ipnets, &net.IPNet{
				IP:   hostIP,
				Mask: net.CIDRMask(32, 32),
			})
		}
		// no addresses specified, allow all.
		if len(ipnets) == 0 {
			ipnets = append(ipnets, nil)
		}
		// no ports specified, allow all
		if len(i.Ports) == 0 {
			i.Ports = append(i.Ports, NetworkPolicyPorts{})
		}
		for _, ipnet := range ipnets {
			for _, port := range i.Ports {
				if len(port.Ports) == 0 {
					rules.Rules = append(rules.Rules, NetworkPolicyRule{
						Addresses: ipnet,
						Protocol:  port.Protocol,
						Direction: dir,
						Related:   i.Related,
					})
				} else {
					for _, p := range port.Ports {
						rules.Rules = append(rules.Rules, NetworkPolicyRule{
							Addresses: ipnet,
							Protocol:  port.Protocol,
							Port:      p,
							Direction: dir,
							Related:   i.Related,
						})
					}
				}
			}
		}
	}
}

func (n *NetworkPolicy) Populate(np *v1alpha1.NetworkPolicy) *NetworkPolicy {
	spec := np.Spec
	n.Name = np.Name
	n.ID = uint16(np.Status.ID)
	if len(spec.LeafSelector.MatchLabels) > 0 {
		n.LeafSelector = spec.LeafSelector.MatchLabels
	}
	if len(spec.ManagedResourceSelector.MatchLabels) > 0 {
		n.ManagedResourceSelector = spec.ManagedResourceSelector.MatchLabels
	}
	for _, r := range spec.IngressRules {
		n.Ingress = append(n.Ingress, convertNetworkPolicyAddress(r.FromAddresses, r.Ports))
	}
	for _, r := range spec.EgressRules {
		n.Egress = append(n.Egress, convertNetworkPolicyAddress(r.ToAddresses, r.Ports))
	}
	return n
}

func (n *NetworkPolicy) GetRules(devicePort string, resourceName, resourceKind string, mgr *NetworkPolicyManager) *NetworkPolicyRules {
	rules := &NetworkPolicyRules{
		NetworkPolicyName: n.Name,
		RuleIDStart:       n.ID,
		ResourceKind:      resourceKind,
		ResourceName:      resourceName,
		DevicePort:        devicePort,
	}
	insertNetworkPolicyRules(n.Ingress, NetworkPolicyDirectionIngress, devicePort, mgr, rules)
	insertNetworkPolicyRules(n.Egress, NetworkPolicyDirectionEgress, devicePort, mgr, rules)
	for i := range rules.Rules {
		rule := &rules.Rules[i]
		// Hack: if IP is bcast, rule cannot be stateful.
		forceStateless := rule.Addresses != nil && rule.Addresses.IP.String() == "255.255.255.255"
		rule.IsStateless = n.stateless || forceStateless
		rule.IsDrop = n.Drop
	}
	return rules
}

// NetworkPolicyRule is internal structure derived from internal NetworkPolicy.
// Each NetworkPolicyRule corresponds to a single underlying ACL rule.
type NetworkPolicyRule struct {
	Addresses   *net.IPNet
	Protocol    string
	Port        uint16
	Direction   NetworkPolicyDirection
	IsStateless bool
	IsDrop      bool
	Related     bool
}

// NetworkPolicyRules is the internal representable of NetworkPolicy CRD configured on
// a Leaf or a ManagedResource.
type NetworkPolicyRules struct {
	NetworkPolicyName string
	ResourceName      string
	ResourceKind      string
	RuleIDStart       uint16
	Rules             []NetworkPolicyRule
	DevicePort        string
}

func (n *NetworkPolicyRules) Key() string {
	return "np/" + n.NetworkPolicyName
}

func (n *NetworkPolicyRules) Equal(request ConfigurationRequest) bool {
	rules, ok := request.(*NetworkPolicyRules)
	if !ok {
		return false
	}
	return reflect.DeepEqual(n, rules)
}

func (n *NetworkPolicyRules) GetBackendState(m *vpcManager) (ConfigurationBackendState, error) {
	rlt := m.networkPolicyMgr.GetNetworkPolicyResourceConfigurationState(n.NetworkPolicyName, n.ResourceName, n.ResourceKind)
	if rlt == nil {
		return BackendStateUnknown, nil
	}
	return rlt.State, rlt.Error
}

func (n *NetworkPolicyRules) SetBackendState(m *vpcManager, state ConfigurationBackendState, err error, notifyChange bool) error {
	ret := m.networkPolicyMgr.updateNetworkPolicyResourceConfigurationState(n.NetworkPolicyName, n.ResourceName, n.ResourceKind,
		ConfigurationBackendResult{
			State: state,
			Error: err,
		}, false)
	if !notifyChange {
		return ret
	}
	if n.ResourceKind == v1alpha1.ManagedResourceName {
		m.managedResources.NotifyChange(n.ResourceName)
	} else if n.ResourceKind == v1alpha12.LeafName {
		m.networkDevices.NotifyChange(getInternalNetworkDeviceName(n.ResourceKind, n.ResourceName), nil)
	}
	return ret

}
