/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

type CumulusNetworkDeviceConfig struct {
	HBNDevice       bool
	NVUEConfig      []byte
	DHCPRelayConfig []byte
	DefaultASN      uint32
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
	InterfaceURI       = "interface"
	InterfaceIPURI     = "interface/%s/ip"
	BridgeDomainURI    = "bridge/domain"
	RevisionURI        = "revision"
	DHCPRelayURI       = "service/dhcp-relay"
	DHCPRelayServerURI = "service/dhcp-relay/%s/server"
	RouteMapRuleURI    = "router/policy/route-map/" + ForgeToUnderlayFilter + "/rule"
	StaticRouteURI     = "vrf/%s/router/static"
	BGPNetworkURI      = "vrf/%s/router/bgp/address-family/ipv4-unicast/network"
)

// Cumulus REST API Interface types
const (
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

type Revision struct {
	State      string `json:"state,omitempty"`
	AutoPrompt struct {
		Ays     string `json:"ays,omitempty"`
		Confirm string `json:"confirm,omitempty"`
	} `json:"auto-prompt,omitempty"`
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

	if c.hbn != nil {
		_, err = c.SshHBN("supervisorctl update")
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
	if vlanid > 0 {
		intfPatch[fmt.Sprintf("vlan%d", vlanid)] = nil
	}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+InterfaceURI, intfPatch, rev); err != nil {
		return true, err
	}

	if vlanid > 0 {
		// Bridge domain.
		bridgeDomainPatch := map[string]*BridgeDomain{BrDefault: {Vlan: map[uint32]*BridgeDomainVlan{vlanid: nil}}}
		if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+BridgeDomainURI, bridgeDomainPatch, rev); err != nil {
			return true, err
		}
	}

	// Route-map
	routeMapPatch := map[uint32]*Rule{ruleId: nil}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+RouteMapRuleURI, routeMapPatch, rev); err != nil {
		return true, err
	}

	if isDelete {
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
	if HBNConfig.HBNDevice {
		if isDelete {
			// dhcrelay should always be on for hosts on overlay or admin pool.
			return nil
		}
		t := template.Must(template.New("").Parse(string(HBNConfig.DHCPRelayConfig)))
		dhcRelayConfig := &bytes.Buffer{}
		dparam := &struct {
			DHCPServer    string
			HostInterface string
		}{
			DHCPServer:    dhcpServer,
			HostInterface: intf,
		}
		if err := t.Execute(dhcRelayConfig, dparam); err != nil {
			return err
		}
		cConfig, err := c.hbn.getHBNDhcRealyConf()
		if err != nil {
			return err
		}
		r := strings.NewReplacer("\n", "", " ", "")
		dConfig := dhcRelayConfig.String()
		if r.Replace(cConfig) == r.Replace(dConfig) {
			return nil
		}
		c.log.V(1).Info("Different dhrelay", "Current", r.Replace(cConfig), "Desired", r.Replace(dConfig))
		if _, err =
			c.Ssh(fmt.Sprintf("echo -e '%s' | sudo tee /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf",
				dhcRelayConfig.String())); err != nil {
			return err
		}
		return err
	}
	dhcpPatch := map[string]*DHCPRelay{
		VrfDefault: {
			Interface: map[string]interface{}{
				intf: nil,
			},
		},
	}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+DHCPRelayURI, dhcpPatch, rev); err != nil {
		return err
	}
	serverURI := fmt.Sprintf(DHCPRelayServerURI, VrfDefault)
	if _, _, err := c.sendContentAndGetResponse(http.MethodDelete, c.getBaseURI()+serverURI, dhcpPatch, rev); err != nil {
		return err
	}
	if isDelete {
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
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+routeURI, staticRoutePatch, rev); err != nil {
		return err
	}
	bgpRouteURI := fmt.Sprintf(BGPNetworkURI, VrfDefault)
	bgpRoutePatch := map[string]interface{}{hostRoute: nil}
	if _, _, err := c.sendContentAndGetResponse(http.MethodPatch, c.getBaseURI()+bgpRouteURI, bgpRoutePatch, rev); err != nil {
		return err
	}
	if isDelete {
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
