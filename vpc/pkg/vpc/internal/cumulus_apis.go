/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/wait"
)

type CumulusNetworkDeviceConfig struct {
	HBNDevice  bool
	NVUEConfig []byte
	DefaultASN uint32
}

var (
	HBNConfig CumulusNetworkDeviceConfig
)

const (
	emptyRevision = "empty"

	ForgeUplink             = "FORGE_UPLINK"
	ForgeToUnderlayFilter   = "FORGE_TO_UNDERLAY"
	ForgeFromUnderlayFilter = "FORGE_FROM_UNDERLAY"
)

// Cumulus REST API URIs
const (
	ACLURI             = "acl/%s%s"
	InterfaceURI       = "interface"
	InterfaceIPURI     = "interface/%s/ip"
	InterfaceACLURI    = "interface/%s/acl/%s%s"
	BridgeDomainURI    = "bridge/domain"
	RevisionURI        = "revision"
	DHCPRelayURI       = "service/dhcp-relay"
	DHCPRelayServerURI = "service/dhcp-relay/%s/server"
	RouteMapRuleURI    = "router/policy/route-map/" + ForgeToUnderlayFilter + "/rule"
	StaticRouteURI     = "vrf/%s/router/static"
	BGPNetworkURI      = "vrf/%s/router/bgp/address-family/ipv4-unicast/network"
)

const (
	// InterfaceTypeSWP is cumulus interface type swp
	InterfaceTypeSWP = "swp"
)

// Cumulus REST API well-known entities.
const (
	BrDefault             = "br_default"
	VrfDefault            = "default"
	IPv4AddressFamily     = "ipv4-unicast"
	RouteViaTypeInterface = "interface"
)

// Cumulus REST API json structures.
type interfaceIP struct {
	Address map[string]interface{} `json:"address,omitempty"`
}

type InterfaceBridge struct {
	Access uint32 `json:"access,omitempty"`
}

type InterfaceBridges struct {
	Domain map[string]*InterfaceBridge `json:"domain,omitempty"`
}

type Interface struct {
	InterfaceType string `json:"type,omitempty"`
	// Vlan          uint32 `json:"vlan,omitempty"`
	// IP            interfaceIP      `json:"ip,omitempty"`
	Bridge *InterfaceBridges `json:"bridge,omitempty"`
}

type BridgeDomainVlanVni struct {
}

type BridgeDomainVlan struct {
	Vni map[uint32]*BridgeDomainVlanVni `json:"vni,omitempty"`
}

type BridgeDomain struct {
	Vlan map[uint32]*BridgeDomainVlan `json:"vlan,omitempty"`
}

type DHCPRelay struct {
	Server    map[string]interface{} `json:"server,omitempty"`
	Interface map[string]interface{} `json:"interface,omitempty"`
}

type RuleMatch struct {
	Interface string `json:"interface,omitempty"`
}
type Rule struct {
	Match  RuleMatch              `json:"match,omitempty"`
	Action map[string]interface{} `json:"action,omitempty"`
}

type StaticRouteVia struct {
	Type string `json:"type,omitempty"`
}
type StaticRoute struct {
	AddressFamily string                     `json:"address-family,omitempty"`
	Via           map[string]*StaticRouteVia `json:"via,omitempty"`
}

const (
	ACLTypeIPv4 = "ipv4"
)

const (
	ACLProtocolTCP  = "tcp"
	ACLProtocolUDP  = "udp"
	ACLProtocolICMP = "icmp"
)

const (
	ACLConntrackStateEstablished = "established"
	ACLConntrackStateNew         = "new"
	ACLConntrackStateRelated     = "related"
)

const (
	ACLNameSuffixIngress = "Ingress"
	ACLNameSuffixEgress  = "Egress"
)

var (
	ACLReplyConntrackState = map[string]struct{}{
		ACLConntrackStateEstablished: {},
		ACLConntrackStateRelated:     {},
	}
	ACLRequestConntrackState = map[string]struct{}{
		ACLConntrackStateEstablished: {},
		ACLConntrackStateNew:         {},
	}
	ACLActionPermit      = map[string]struct{}{"permit": {}}
	ACLActionDeny        = map[string]struct{}{"deny": {}}
	ACLDirectionInBound  = map[string]struct{}{"inbound": {}}
	ACLDirectionOutBound = map[string]struct{}{"outbound": {}}
)

type AclRuleMatchIP struct {
	DestIP     string              `json:"dest-ip,omitempty"`
	DestPort   map[uint16]struct{} `json:"dest-port,omitempty"`
	SourceIP   string              `json:"source-ip,omitempty"`
	SourcePort map[uint16]struct{} `json:"source-port,omitempty"`
	Protocol   string              `json:"protocol,omitempty"`
}

type AclRuleMatch struct {
	IP        AclRuleMatchIP      `json:"ip,omitempty"`
	Conntrack map[string]struct{} `json:"conntrack,omitempty"`
}

type AclRule struct {
	Match  AclRuleMatch        `json:"match,omitempty"`
	Action map[string]struct{} `json:"action,omitempty"`
}

type Acl struct {
	Type string              `json:"type,omitempty"`
	Rule map[uint16]*AclRule `json:"rule,omitempty"`
}

type Revision struct {
	State      string `json:"state,omitempty"`
	AutoPrompt struct {
		Ays     string `json:"ays,omitempty"`
		Confirm string `json:"confirm,omitempty"`
	} `json:"auto-prompt,omitempty"`
}

var (
	convertIPProtocol = strings.ToLower
)

func aclNamePrune(name string) string {
	// K8s resource name is RFC1123 compliant. Acl name does not accept "-", "."
	return strings.ReplaceAll(strings.ReplaceAll(name, "-", ""), ".", "")
}

func (c *Cumulus) handleResponse(resp []byte) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	if err := json.Unmarshal(resp, &ret); err != nil {
		c.log.Error(err, "Failed to unmarshal response", "Out", string(resp))
		return nil, err
	}
	if status, ok := ret["status"]; ok {
		if status.(int64) != 200 {
			c.log.Error(nil, "Response not OK", "Response", ret)
			return nil, fmt.Errorf("response not OK")
		}
	}
	// c.log.V(1).Info("Response is ", "Response", ret)
	return ret, nil
}

func (c *Cumulus) sendAndGetResponse(method, uri string, body []byte, rev *string) (map[string]interface{}, []byte, error) {
	var buf io.Reader = nil
	if body != nil {
		buf = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, uri, buf)
	if rev != nil {
		modifyRequest(req, map[string]string{"rev": *rev})
	} else {
		modifyRequest(req, map[string]string{})
	}
	out, err := c.Send(req)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.handleResponse(out)
	if err != nil {
		c.log.Error(err, "Send receives errored response")
		return nil, nil, err
	}
	return resp, out, nil
}

func (c *Cumulus) sendContentAndGetResponse(method, uri string, body interface{}, rev *string) (map[string]interface{}, []byte, error) {
	in, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	return c.sendAndGetResponse(method, uri, in, rev)
}

func (c *Cumulus) getRevision(rev string) (string, error) {
	if len(rev) > 0 {
		resp, _, err := c.sendAndGetResponse(http.MethodGet, c.getBaseURI()+RevisionURI+"/"+rev, nil, nil)
		if err != nil {
			return "", err
		}
		if _, ok := resp["state"]; !ok {
			return "", fmt.Errorf("cannot get revision")
		}
		return rev, nil
	}
	resp, _, err := c.sendAndGetResponse(http.MethodPost, c.getBaseURI()+RevisionURI, nil, nil)
	if err != nil {
		return "", err
	}
	for k := range resp {
		return k, nil
	}
	return "", fmt.Errorf("empty revision response")
}

func (c *Cumulus) applyRevision(rev string) error {
	now := time.Now().Unix()
	defer func() {
		c.log.Info("Applied changes in", "Second", time.Now().Unix()-now)
	}()
	aRev := strings.Replace(rev, "/", "%2F", -1)
	revData := &Revision{}
	revData.State = "apply"
	revData.AutoPrompt.Ays = "ays_yes"
	revData.AutoPrompt.Confirm = "confirm_yes"
	in, err := json.Marshal(revData)
	if err != nil {
		c.log.Error(err, "Failed to marshal revision", "Revision", revData)
		return err
	}
	if _, _, err = c.sendAndGetResponse(http.MethodPatch, c.getBaseURI()+RevisionURI+"/"+aRev, in, nil); err != nil {
		return err
	}
	// Wait for changed to be applied.
	if err = wait.Poll(time.Second, cumulusApplyTimeout, func() (bool, error) {
		resp, _, err := c.sendAndGetResponse(http.MethodGet, c.getBaseURI()+RevisionURI+"/"+aRev, nil, nil)
		if err != nil {
			return false, err
		}
		if state, ok := resp["state"]; ok {
			if state.(string) == "applied" {
				return true, nil
			}
		}
		return false, nil
	}); err != nil {
		return err
	}
	return err
}

func (c *Cumulus) getBaseURI() string {
	return "https://" + c.GetMgmtIP() + "/cue_v1/"
}

func (c *Cumulus) updateInterface(vlanid, vni uint32, link string, gwIP string,
	rev *string, isDelete bool) (bool, error) {
	// Remove any residual configurations.
	// Interface.
	if len(link) == 0 {
		return false, fmt.Errorf("ManagedResource and Leaf device identifier out of sync")
	}
	intf := fmt.Sprintf("vlan%d", vlanid)
	ruleId := vlanid
	if vlanid == 0 {
		intf = link
		ruleId = 10
	}
	intfPatch := map[string]*Interface{
		link: nil,
	}
	// Delete physical port configuration only if no other configuration is using it.
	if isDelete && c.portInUseWithLock(link) {
		delete(intfPatch, link)
	}
	if vlanid > 0 {
		intfPatch[fmt.Sprintf("vlan%d", vlanid)] = nil
	}
	routeMapPatch := map[uint32]*Rule{ruleId: nil}
	if isDelete {
		if len(intfPatch) > 0 {
			if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+InterfaceURI, intfPatch, rev); err != nil {
				return true, err
			}
		}
		if vlanid > 0 {
			// Bridge domain.
			bridgeDomainPatch := map[string]*BridgeDomain{BrDefault: {Vlan: map[uint32]*BridgeDomainVlan{vlanid: nil}}}
			if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+BridgeDomainURI, bridgeDomainPatch, rev); err != nil {
				return true, err
			}
		}

		// Route-map
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+RouteMapRuleURI, routeMapPatch, rev); err != nil {
			return true, err
		}
		return false, nil
	}

	// Add Bridge domain.
	if vni > 0 {
		bridgeDomainPatch := map[string]*BridgeDomain{
			BrDefault: {Vlan: map[uint32]*BridgeDomainVlan{
				vlanid: {
					Vni: map[uint32]*BridgeDomainVlanVni{vni: {}},
				},
			}}}
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+BridgeDomainURI, bridgeDomainPatch, rev); err != nil {
			return true, err
		}
	}
	if vlanid > 0 {
		// Add interface.
		intfPatch = map[string]*Interface{
			link: {
				InterfaceType: InterfaceTypeSWP,
				Bridge: &InterfaceBridges{
					Domain: map[string]*InterfaceBridge{
						BrDefault: {
							Access: vlanid,
						},
					},
				},
			},
		}
	} else {
		intfPatch = map[string]*Interface{
			link: {
				InterfaceType: InterfaceTypeSWP,
			},
		}
	}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+InterfaceURI, intfPatch, rev); err != nil {
		return true, err
	}
	// Add IP
	intfIPURI := fmt.Sprintf(c.getBaseURI()+InterfaceIPURI, intf)
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, intfIPURI,
		interfaceIP{
			Address: map[string]interface{}{
				gwIP: struct{}{},
			},
		}, rev); err != nil {
		return true, err
	}
	// Route-map
	routeMapPatch = map[uint32]*Rule{ruleId: {
		Match: RuleMatch{Interface: intf},
		Action: map[string]interface{}{
			"deny": struct{}{},
		},
	}}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+RouteMapRuleURI, routeMapPatch, rev); err != nil {
		return true, err
	}
	return false, nil
}

func (c *Cumulus) updateDHCPRelayAgent(vlanid uint32, intf string, dhcpServer string, rev *string, isDelete bool) error {
	if vlanid != 0 {
		intf = fmt.Sprintf("vlan%d", vlanid)
	}
	dhcpPatch := map[string]*DHCPRelay{
		VrfDefault: {
			Interface: map[string]interface{}{
				intf: nil,
			},
		},
	}
	if isDelete {
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+DHCPRelayURI, dhcpPatch, rev); err != nil {
			return err
		}
		serverURI := fmt.Sprintf(DHCPRelayServerURI, VrfDefault)

		// TODO workaround
		// https://nvbugswb.nvidia.com/NvBugs5/SWBug.aspx?bugid=3764459&cmtNo=
		if false {
			if _, _, err := c.sendContentAndGetResponse(http.MethodDelete, c.getBaseURI()+serverURI, dhcpPatch, rev); err != nil {
				return err
			}
		}
		return nil
	}
	dhcpPatch = map[string]*DHCPRelay{
		VrfDefault: {
			Server: map[string]interface{}{
				dhcpServer: struct{}{},
			},
			Interface: map[string]interface{}{
				intf: struct{}{},
			},
		},
	}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+DHCPRelayURI, dhcpPatch, rev); err != nil {
		return err
	}
	return nil
}

func (c *Cumulus) updateRouteFilter(vlanid uint32, intfName, hostRoute string, rev *string, isDelete bool) error {
	if vlanid != 0 {
		intfName = fmt.Sprintf("vlan%d", vlanid)
	}
	routeURI := fmt.Sprintf(StaticRouteURI, VrfDefault)
	staticRoutePatch := &map[string]*StaticRoute{hostRoute: nil}
	bgpRouteURI := fmt.Sprintf(BGPNetworkURI, VrfDefault)
	bgpRoutePatch := map[string]interface{}{hostRoute: nil}
	if isDelete {
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+routeURI, staticRoutePatch, rev); err != nil {
			return err
		}
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+bgpRouteURI, bgpRoutePatch, rev); err != nil {
			return err
		}
		return nil
	}
	staticRoutePatch = &map[string]*StaticRoute{
		hostRoute: {
			AddressFamily: IPv4AddressFamily,
			Via: map[string]*StaticRouteVia{
				intfName: {Type: RouteViaTypeInterface},
			},
		},
	}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+routeURI, staticRoutePatch, rev); err != nil {
		return err
	}
	bgpRoutePatch = map[string]interface{}{hostRoute: struct{}{}}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+bgpRouteURI, bgpRoutePatch, rev); err != nil {
		return err
	}
	return nil
}

func (c *Cumulus) updateACL(rules *NetworkPolicyRules, rev *string, isDelete bool) error {
	if isDelete {
		for _, suffix := range []string{ACLNameSuffixEgress, ACLNameSuffixIngress} {
			interfaceACLURI := fmt.Sprintf(InterfaceACLURI, rules.DevicePort,
				aclNamePrune(rules.NetworkPolicyName), suffix)
			aclURI := fmt.Sprintf(ACLURI, aclNamePrune(rules.NetworkPolicyName), suffix)
			aclInUse, samePort := c.aclInUseWithLock(rules)
			if !samePort && c.portInUseWithLock(rules.DevicePort) {
				// Don't remove acl from interface, when
				// 1. some other configuration is using it or
				// 2. the interface itself will be removed.
				if _, _, err := c.sendContentAndGetResponse(http.MethodDelete, c.getBaseURI()+interfaceACLURI, nil, rev); err != nil {
					return err
				}
			}
			if !aclInUse {
				if _, _, err := c.sendContentAndGetResponse(http.MethodDelete, c.getBaseURI()+aclURI, nil, rev); err != nil {
					return err
				}
			}
		}
		return nil
	}

	aclEgress := Acl{
		Type: ACLTypeIPv4,
		Rule: make(map[uint16]*AclRule),
	}
	egressRuleIdx := rules.RuleIDStart
	aclIngress := Acl{
		Type: ACLTypeIPv4,
		Rule: make(map[uint16]*AclRule),
	}
	ingressRuleIdx := rules.RuleIDStart

	for _, r := range rules.Rules {
		var matchIP *AclRuleMatchIP
		var protoPort map[uint16]struct{}
		if r.Port > 0 {
			protoPort = map[uint16]struct{}{r.Port: {}}
		}
		if r.Direction == NetworkPolicyDirectionEgress {

			matchIP = &AclRuleMatchIP{
				DestPort: protoPort,
				Protocol: convertIPProtocol(r.Protocol),
			}
			if r.Addresses != nil {
				matchIP.DestIP = r.Addresses.String()
			}
		} else {
			matchIP = &AclRuleMatchIP{
				SourcePort: protoPort,
				Protocol:   convertIPProtocol(r.Protocol),
			}
			if r.Addresses != nil {
				matchIP.SourceIP = r.Addresses.String()
			}
		}
		aclRule := &AclRule{
			Match: AclRuleMatch{
				IP: *matchIP,
			},
		}
		if r.IsDrop {
			aclRule.Action = ACLActionDeny
		} else {
			aclRule.Action = ACLActionPermit
		}
		if !r.IsStateless {
			if r.Related {
				aclRule.Match.Conntrack = ACLReplyConntrackState
			} else {
				aclRule.Match.Conntrack = ACLRequestConntrackState
			}
		}
		if r.Direction == NetworkPolicyDirectionEgress {
			aclEgress.Rule[egressRuleIdx] = aclRule
			egressRuleIdx++
		} else {
			aclIngress.Rule[ingressRuleIdx] = aclRule
			ingressRuleIdx++
		}
	}
	if len(aclIngress.Rule) > 0 {
		// NetworkPolicy direction is specified from host's perspective, and
		// Acl direction is specified from HBN/switch perspective.
		interfaceACLURI := fmt.Sprintf(InterfaceACLURI, rules.DevicePort,
			aclNamePrune(rules.NetworkPolicyName), ACLNameSuffixIngress)
		aclURI := fmt.Sprintf(ACLURI, aclNamePrune(rules.NetworkPolicyName), ACLNameSuffixIngress)
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+interfaceACLURI,
			ACLDirectionOutBound, rev); err != nil {
			return err
		}
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+aclURI, aclIngress, rev); err != nil {
			return err
		}
	}
	if len(aclEgress.Rule) > 0 {
		interfaceACLURI := fmt.Sprintf(InterfaceACLURI, rules.DevicePort, aclNamePrune(rules.NetworkPolicyName), ACLNameSuffixEgress)
		aclURI := fmt.Sprintf(ACLURI, aclNamePrune(rules.NetworkPolicyName), ACLNameSuffixEgress)
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+interfaceACLURI,
			ACLDirectionInBound, rev); err != nil {
			return err
		}
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+aclURI, aclEgress, rev); err != nil {
			return err
		}
	}
	return nil
}
