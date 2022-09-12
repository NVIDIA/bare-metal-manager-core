package internal_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/json"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	networkfabric "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
)

var _ = Describe("Networkpolicy", func() {
	type networkPolicyMatch struct {
		Method string
		Url    string
		Body   interface{}
	}
	type matcherState int
	const (
		matcherStageLeaf matcherState = iota
		matcherStageManagedResource
		matcherStageDeleteNP
		matcherStageAddNP
		matcherStageNoManagedResource
		matcherStageNoLeaf
	)
	var (
		matcherStage matcherState
		siteNp       *v1alpha1.NetworkPolicy
		siteNpLabels = map[string]string{"network-policy-site": "true"}
		vpcNp        *v1alpha1.NetworkPolicy
		vpcNpLabels  = map[string]string{"network-policy-vpc": "true"}
		mrLabels     = map[string]string{"network-policy-site": "true", "network-policy-vpc": "true"}
		denyId       = internal.DefaultDenyNetworkPolicy.ID
		denyAllRules = map[uint16]*internal.AclRule{
			denyId: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolUDP,
					},
				},
				Action: internal.ACLActionDeny,
			},
			denyId + 1: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolTCP,
					},
				},
				Action: internal.ACLActionDeny,
			},
			denyId + 2: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolICMP,
					},
				},
				Action: internal.ACLActionDeny,
			},
		}
		permitId           = internal.DefaultPermitNetworkPolicy.ID
		permitRelatedRules = map[uint16]*internal.AclRule{
			permitId: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolUDP,
					},
					Conntrack: internal.ACLReplyConntrackState,
				},
				Action: internal.ACLActionPermit,
			},
			permitId + 1: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolTCP,
					},
					Conntrack: internal.ACLReplyConntrackState,
				},
				Action: internal.ACLActionPermit,
			},
			permitId + 2: {
				Match: internal.AclRuleMatch{
					IP: internal.AclRuleMatchIP{
						Protocol: internal.ACLProtocolICMP,
					},
					Conntrack: internal.ACLReplyConntrackState,
				},
				Action: internal.ACLActionPermit,
			},
		}
		addDefaultPolicies    []networkPolicyMatch
		deleteDefaultPolicies []networkPolicyMatch
		addSiteNpPolicies     []networkPolicyMatch
		deleteSiteNpPolicies  []networkPolicyMatch
		addVpcNpPolicies      []networkPolicyMatch
		deleteVpcNpPolicies   []networkPolicyMatch
	)
	BeforeEach(func() {
		internal.NetworkPolicyPriorityRuleIDMap = []uint16{128, 256, 60000, 60128, 60256}
		internal.EnableNetworkPolicy = true
		startManager()
		initResources()
		siteNp = &v1alpha1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "site-np",
				Namespace: namespace,
			},
			Spec: v1alpha1.NetworkPolicySpec{
				ManagedResourceSelector: v1alpha1.LabelSelector{MatchLabels: siteNpLabels},
				LeafSelector:            v1alpha1.LabelSelector{MatchLabels: siteNpLabels},
				EgressRules: []v1alpha1.NetworkPolicyEgressRule{
					{
						ToAddresses: []v1alpha1.NetworkPolicyAddress{
							{
								IPCIDR: "1.2.3.4/32",
							},
						},
						Ports: []v1alpha1.NetworkPolicyPort{{
							Begin:    53,
							Protocol: internal.ACLProtocolUDP,
						}},
					},
					{
						ToAddresses: []v1alpha1.NetworkPolicyAddress{
							{
								IPCIDR: "1.2.3.5/32",
							},
						},
						Ports: []v1alpha1.NetworkPolicyPort{
							{
								Begin:    80,
								Protocol: internal.ACLProtocolTCP,
							},
							{
								Begin:    8080,
								Protocol: internal.ACLProtocolTCP,
							},
						},
					},
				},
			},
		}

		vpcNp = &v1alpha1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "vpc-np",
				Namespace: namespace,
			},
			Spec: v1alpha1.NetworkPolicySpec{
				ManagedResourceSelector: v1alpha1.LabelSelector{MatchLabels: vpcNpLabels},
				EgressRules: []v1alpha1.NetworkPolicyEgressRule{
					{},
				},
				IngressRules: []v1alpha1.NetworkPolicyIngressRule{
					{
						FromAddresses: []v1alpha1.NetworkPolicyAddress{
							{
								ManagedResourceSelector: v1alpha1.LabelSelector{
									MatchLabels: vpcNpLabels,
								},
							},
						},
					},
				},
			},
		}

		leaf.Labels = siteNpLabels
		mr.Labels = mrLabels
		err := k8sClient.Create(context.Background(), adminRg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), siteNp)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Create(context.Background(), vpcNp)
		Expect(err).ToNot(HaveOccurred())
		vniPool = resourceManager.CreateIntegerPool(string(networkfabric.VNIResourcePool), [][]uint64{vniRange})
		_ = vniPool.Reconcile()
		vlanPool = resourceManager.CreateIntegerPool(string(networkfabric.VlanIDResourcePool), [][]uint64{vlanRange})
		_ = vlanPool.Reconcile()
		err = vpcManager.CreateOrUpdateOverlayNetwork(context.Background(), adminRg.Name)
		Expect(err).ToNot(HaveOccurred())
		_, err = vpcManager.GetOverlayNetworkProperties(context.Background(), adminRg.Name)
		Expect(err).ToNot(HaveOccurred())
		err = vpcManager.CreateOrUpdateOverlayNetwork(context.Background(), rg.Name)
		Expect(err).ToNot(HaveOccurred())
		_, err = vpcManager.GetOverlayNetworkProperties(context.Background(), rg.Name)
		Expect(err).ToNot(HaveOccurred())
	})
	AfterEach(func() {
		err := internal.CheckNetworkPolicyManagerResourceFreed(vpcManager)
		Expect(err).ToNot(HaveOccurred())
		internal.EnableNetworkPolicy = false
		stopManager()
		err = k8sClient.Delete(context.Background(), rg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), adminRg)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), leaf)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), mr)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), siteNp)
		Expect(err).ToNot(HaveOccurred())
		err = k8sClient.Delete(context.Background(), vpcNp)
		Expect(err).ToNot(HaveOccurred())
	})

	generateNPRules := func(np *v1alpha1.NetworkPolicy) (
		egressRules map[uint16]*internal.AclRule,
		ingressRules map[uint16]*internal.AclRule) {

		id := uint16(np.Status.ID)
		Expect(id).ToNot(BeZero())

		if np.Name == vpcNp.Name {
			egressRules = map[uint16]*internal.AclRule{
				id: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							Protocol: internal.ACLProtocolUDP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
				id + 1: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							Protocol: internal.ACLProtocolTCP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
				id + 2: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							Protocol: internal.ACLProtocolICMP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
			}
			ingressRules = map[uint16]*internal.AclRule{
				id: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							SourceIP: string(mr.Spec.HostInterfaceIP + "/32"),
							Protocol: internal.ACLProtocolUDP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
				id + 1: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							SourceIP: string(mr.Spec.HostInterfaceIP + "/32"),
							Protocol: internal.ACLProtocolTCP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
				id + 2: {
					Match: internal.AclRuleMatch{
						IP: internal.AclRuleMatchIP{
							SourceIP: string(mr.Spec.HostInterfaceIP + "/32"),
							Protocol: internal.ACLProtocolICMP,
						},
						Conntrack: internal.ACLRequestConntrackState,
					},
					Action: internal.ACLActionPermit,
				},
			}
			return
		}

		egressRules = make(map[uint16]*internal.AclRule)
		for _, r := range np.Spec.EgressRules {
			for _, addr := range r.ToAddresses {
				for _, port := range r.Ports {
					aclRule := &internal.AclRule{
						Match: internal.AclRuleMatch{
							IP: internal.AclRuleMatchIP{
								DestIP:   string(addr.IPCIDR),
								DestPort: map[uint16]struct{}{uint16(port.Begin): {}},
								Protocol: strings.ToLower(string(port.Protocol)),
							},
							Conntrack: internal.ACLRequestConntrackState,
						},
						Action: internal.ACLActionPermit,
					}
					egressRules[id] = aclRule
					id++
				}
			}
		}
		return
	}

	generateLeafMatchers := func(snp *v1alpha1.NetworkPolicy, toggleNp bool) [][]networkPolicyMatch {
		egressPermitRules := make(map[uint16]*internal.AclRule)
		for k, v := range permitRelatedRules {
			egressPermitRules[k] = v
		}
		egressPermitRules[permitId+3] = &internal.AclRule{
			Match: internal.AclRuleMatch{
				IP: internal.AclRuleMatchIP{
					DestIP:   "255.255.255.255/32",
					DestPort: map[uint16]struct{}{67: {}},
					Protocol: internal.ACLProtocolUDP,
				},
			},
			Action: internal.ACLActionPermit,
		}
		addDefaultPolicies = []networkPolicyMatch{
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixIngress),
				Body: internal.ACLDirectionOutBound,
			},
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixEgress),
				Body: internal.ACLDirectionInBound,
			},
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixIngress),
				Body: internal.ACLDirectionOutBound,
			},
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixEgress),
				Body: internal.ACLDirectionInBound,
			},
			{
				Method: http.MethodPatch,
				Url: "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName),
					internal.ACLNameSuffixIngress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: denyAllRules,
				},
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixEgress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: denyAllRules,
				},
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixIngress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: permitRelatedRules,
				},
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixEgress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: egressPermitRules,
				},
			},
		}
		deleteDefaultPolicies = []networkPolicyMatch{
			/*
				{
					Method: http.MethodDelete,
					Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
						internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixIngress),
				},
				{
					Method: http.MethodDelete,
					Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
						internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixEgress),
				},
				{
					Method: http.MethodDelete,
					Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
						internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixIngress),
				},
				{
					Method: http.MethodDelete,
					Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
						internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixEgress),
				},
			*/
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixIngress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultDenyNetworkPolicyName), internal.ACLNameSuffixEgress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixIngress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(internal.DefaultPermitNetworkPolicyName), internal.ACLNameSuffixEgress),
			},
		}
		matchers := [][]networkPolicyMatch{
			addDefaultPolicies,    // matcherStageLeaf
			{},                    // matcherStageManagedResource
			{},                    // matcherStageDeleteNP
			{},                    // matcherStageAddNP
			{},                    // matcherStageNoManagedResource
			deleteDefaultPolicies, // matcherStageNoLeaf
		}
		if snp == nil {
			return matchers
		}
		egressRules, _ := generateNPRules(snp)
		addSiteNpPolicies = []networkPolicyMatch{
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(snp.Name), internal.ACLNameSuffixEgress),
				Body: internal.ACLDirectionInBound,
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(snp.Name), internal.ACLNameSuffixEgress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: egressRules,
				},
			},
		}
		deleteSiteNpPolicies = []networkPolicyMatch{
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(snp.Name), internal.ACLNameSuffixEgress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(snp.Name), internal.ACLNameSuffixIngress),
			},
			{
				Method: http.MethodDelete,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(snp.Name), internal.ACLNameSuffixEgress),
			},
			{
				Method: http.MethodDelete,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(snp.Name), internal.ACLNameSuffixIngress),
			},
		}
		matchers[matcherStageLeaf] = append(matchers[matcherStageLeaf], addSiteNpPolicies...)
		matchers[matcherStageNoLeaf] = append(matchers[matcherStageNoLeaf], deleteSiteNpPolicies[:2]...)

		if !toggleNp {
			return matchers
		}
		// matcher for test remove and add site-np on leafs.
		matchers[matcherStageDeleteNP] = append(matchers[matcherStageDeleteNP], deleteSiteNpPolicies...)
		matchers[matcherStageAddNP] = append(matchers[matcherStageAddNP], addSiteNpPolicies...)
		return matchers
	}

	generateManagedResourceMatchers := func(matchers [][]networkPolicyMatch, toggoleNp bool) [][]networkPolicyMatch {
		egressRules, ingressRules := generateNPRules(vpcNp)
		addVpcNpPolicies = []networkPolicyMatch{
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixEgress),
				Body: internal.ACLDirectionInBound,
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixEgress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: egressRules,
				},
			},
			{
				Method: http.MethodPatch,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixIngress),
				Body: internal.ACLDirectionOutBound,
			},
			{
				Method: http.MethodPatch,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixIngress),
				Body: internal.Acl{
					Type: internal.ACLTypeIPv4,
					Rule: ingressRules,
				},
			},
		}
		deleteVpcNpPolicies = []networkPolicyMatch{
			{
				Method: http.MethodDelete,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixEgress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixEgress),
			},
			{
				Method: http.MethodDelete,
				Url: fmt.Sprintf(internal.InterfaceACLURI, internal.HostAdminLeafPort,
					internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixIngress),
			},
			{
				Method: http.MethodDelete,
				Url:    "cue_v1/" + fmt.Sprintf(internal.ACLURI, internal.AclNamePrue(vpcNp.Name), internal.ACLNameSuffixIngress),
			},
		}

		matchers[matcherStageManagedResource] = append(matchers[matcherStageManagedResource], addDefaultPolicies...)
		matchers[matcherStageManagedResource] = append(matchers[matcherStageManagedResource], addSiteNpPolicies...)
		matchers[matcherStageManagedResource] = append(matchers[matcherStageManagedResource], addVpcNpPolicies...)
		matchers[matcherStageNoManagedResource] = append(matchers[matcherStageNoManagedResource], deleteVpcNpPolicies...)
		matchers[matcherStageNoManagedResource] = append(matchers[matcherStageNoManagedResource], addDefaultPolicies...)
		matchers[matcherStageNoManagedResource] = append(matchers[matcherStageNoManagedResource], addSiteNpPolicies...)

		if !toggoleNp {
			return matchers
		}
		matchers[matcherStageAddNP] = append(matchers[matcherStageAddNP], addVpcNpPolicies...)
		matchers[matcherStageDeleteNP] = append(matchers[matcherStageDeleteNP], deleteVpcNpPolicies...)
		return matchers
	}

	testExpectations := func(matchers [][]networkPolicyMatch) {
		mockCumulusTransport.EXPECT().GetMgmtIP().AnyTimes().Return(leaf.Spec.Control.ManagementIP)
		mockCumulusTransport.EXPECT().SetMgmtIP(leaf.Spec.Control.ManagementIP).AnyTimes()
		mockCumulusTransport.EXPECT().Send(gomock.Any()).MinTimes(1).DoAndReturn(
			func(req *http.Request) ([]byte, error) {
				defer GinkgoRecover()
				logf.Log.V(1).Info("http mock", "Request", req.URL.String(), "Method", req.Method)
				if req.Method == http.MethodPost && strings.HasSuffix(req.URL.String(), "/revision") {
					return json.Marshal(&map[string]interface{}{
						"revision_1": struct{}{}})
				} else if req.Method == http.MethodGet && strings.Contains(req.URL.String(), "/revision/") {
					return json.Marshal(&map[string]interface{}{
						"state": "applied"})
				}

				if !strings.Contains(req.URL.String(), "/acl/") {
					// Don't care if not NetworkPolicy related in this test.
					return json.Marshal(&map[string]interface{}{
						"status": 200})
				}
				data := make([]byte, 2056)
				n, err := req.Body.Read(data)
				Expect(err).ToNot(HaveOccurred())
				logf.Log.V(1).Info("http mock", "Body", string(data[0:n]))
				tmpMatchers := matchers[matcherStage]
				for i := range tmpMatchers {
					matcher := &tmpMatchers[i]
					expect, err := json.Marshal(matcher.Body)
					Expect(err).ToNot(HaveOccurred())
					if strings.Contains(req.URL.String(), matcher.Url) && req.Method == matcher.Method &&
						string(data[0:n]) == string(expect) {
						tmpMatchers[i] = tmpMatchers[len(tmpMatchers)-1]
						tmpMatchers = tmpMatchers[:len(tmpMatchers)-1]
						break
					}
				}
				if len(tmpMatchers)+1 != len(matchers[matcherStage]) {
					logf.Log.V(1).Info("TODO remove later", "Stage", matcherStage, "Matcher", tmpMatchers)
					Fail("Did not find matching action")
				}
				matchers[matcherStage] = tmpMatchers
				return json.Marshal(&map[string]interface{}{
					"status": 200})
			})
	}

	checkNetworkPolicy := func(l1 []string, prop *properties.NetworkPolicyResourceProperties) bool {
		if prop == nil && len(l1) == 0 {
			return true
		} else if prop == nil {
			return false
		}
		l2 := prop.Applied
		if len(l1) != len(l2) {
			return false
		}
		for _, s1 := range l1 {
			found := false
			for _, s2 := range l2 {
				if s1 == s2 {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	addNetworkPolicy := func(np *v1alpha1.NetworkPolicy) {
		_ = vpcManager.GetEvent(v1alpha1.NetworkPolicyName)
		// Add NetworkPolicies
		err := vpcManager.CreateOrUpdateNetworkPolicy(context.Background(), np.Name)
		Expect(err).ToNot(HaveOccurred())
		npProp, err := vpcManager.GetNetworkPolicyProperties(context.Background(), np.Name)
		Expect(err).ToNot(HaveOccurred())
		if npProp == nil || !(npProp.ID > internal.NetworkPolicyPriorityRuleIDMap[internal.NetworkPolicyPriorityMandatoryDeny] &&
			npProp.ID < internal.NetworkPolicyPriorityRuleIDMap[internal.NetworkPolicyPriorityDefaultPermit]) {
			Fail(fmt.Sprintf("Incorrect NetworkPolicyProperties: %v", npProp.ID))
		}
		np.Status.ID = int32(npProp.ID)
		err = k8sClient.Status().Update(context.Background(), np)
		Expect(err).ToNot(HaveOccurred())
	}

	deleteNetworkPolicyDone := func() {
		npChan := vpcManager.GetEvent(v1alpha1.NetworkPolicyName)
		Eventually(func() error {
			stop := time.Tick(time.Second)
			for {
				select {
				case npEvet := <-npChan:
					return vpcManager.DeleteNetworkPolicy(context.Background(), npEvet.Name)
				case <-stop:
					return fmt.Errorf("no Event")
				}
			}
		}, 10, 1).Should(BeNil())

	}
	testLeaf := func(add, noEvent bool, matchers *[]networkPolicyMatch, appliedPolicies []string) {
		leafEventChan := vpcManager.GetEvent(networkfabric.LeafName)
		if add {
			err := vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
			Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		}
		Eventually(func() error {
			stop := time.Tick(time.Second)
			for {
				select {
				case leafEvt := <-leafEventChan:
					Expect(noEvent).To(BeFalse(), "Unexpected event")
					err := vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leafEvt.Name)
					if err != nil {
						return err
					}
					devProp, err := vpcManager.GetNetworkDeviceProperties(context.Background(), networkfabric.LeafName, leaf.Name)
					if err != nil {
						return err
					}
					if !devProp.Alive || !checkNetworkPolicy(appliedPolicies, devProp.NetworkPolicyProperties) {
						return fmt.Errorf("wait for networkpolicy")
					}
					return nil
				case <-stop:
					if noEvent {
						return nil
					}
					return fmt.Errorf("no Event")

				}
			}
		}, 10, 1).Should(BeNil())
		Expect(*matchers).To(BeEmpty())
	}

	testLeafDelete := func(matchers *[]networkPolicyMatch) {
		leafEventChan := vpcManager.GetEvent(networkfabric.LeafName)
		err := vpcManager.RemoveNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		Eventually(func() error {
			stop := time.Tick(time.Second)
			for {
				select {
				case leafEvt := <-leafEventChan:
					err = vpcManager.RemoveNetworkDevice(context.Background(), networkfabric.LeafName, leafEvt.Name)
					if err != nil {
						return err
					}
					return nil
				case <-stop:
					return fmt.Errorf("no Event")
				}
			}
		}, 10, 1).Should(BeNil())
		Expect(*matchers).To(BeEmpty())
	}

	testManagedResource := func(add, noEvent, checkNp bool, matchers *[]networkPolicyMatch, appliedPolicies []string) {
		mrChan := vpcManager.GetEvent(v1alpha1.ManagedResourceName)
		var npChan <-chan client.ObjectKey
		if checkNp {
			npChan = vpcManager.GetEvent(v1alpha1.NetworkPolicyName)
		}
		if add {
			err := vpcManager.AddOrUpdateResourceToNetwork(context.Background(), mr.Name)
			Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		}
		Eventually(func() error {
			stop := time.Tick(time.Second)
			for {
				select {
				case mrEvt := <-mrChan:
					Expect(noEvent).To(BeFalse(), "Unexpected event")
					err := vpcManager.AddOrUpdateResourceToNetwork(context.Background(), mrEvt.Name)
					if err != nil {
						return err
					}
					prop, err := vpcManager.GetResourceProperties(context.Background(), mrEvt.Name)
					if err != nil {
						return err
					}
					if !checkNetworkPolicy(appliedPolicies, prop.NetworkPolicyProperties) {
						return fmt.Errorf("wait for networkpolicy")
					}
					return nil
				case npEvt := <-npChan:
					err := vpcManager.CreateOrUpdateNetworkPolicy(context.Background(), npEvt.Name)
					Expect(vpc.IsBackendConfigurationInProgress(err) || err == nil).To(BeTrue())
					continue
				case <-stop:
					if noEvent {
						return nil
					}
					return fmt.Errorf("no Event")
				}
			}
		}, 10, 1).Should(BeNil())
		Expect(*matchers).To(BeEmpty())
	}

	testManagedResourceDelete := func(matchers *[]networkPolicyMatch) {
		mrEventChan := vpcManager.GetEvent(v1alpha1.ManagedResourceName)
		npEventChan := vpcManager.GetEvent(v1alpha1.NetworkPolicyName)

		err := vpcManager.RemoveResourceToNetwork(context.Background(), mr.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		Eventually(func() error {
			stop := time.Tick(time.Second)
			for {
				select {
				case mrEvt := <-mrEventChan:
					err = vpcManager.RemoveResourceToNetwork(context.Background(), mrEvt.Name)
					if err != nil {
						return err
					}
					return nil
				case npEvt := <-npEventChan:
					err := vpcManager.CreateOrUpdateNetworkPolicy(context.Background(), npEvt.Name)
					Expect(vpc.IsBackendConfigurationInProgress(err) || err == nil).To(BeTrue())
					continue
				case <-stop:
					return fmt.Errorf("no Event")
				}
			}
		}, 10, 1).Should(BeNil())
		// give time to allow host admin config after resource is removed.
		drainEvents()
		Expect(*matchers).To(BeEmpty())
	}

	It("Host is unassigned", func() {
		// Add NetworkPolicies
		addNetworkPolicy(siteNp)

		matchers := generateLeafMatchers(siteNp, true)
		testExpectations(matchers)
		By("Verify adding Leaf")
		// Create leaf.
		matcherStage = matcherStageLeaf
		testLeaf(true, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name})

		By("Verify deleting NetworkPolicy")
		matcherStage = matcherStageDeleteNP
		err := vpcManager.DeleteNetworkPolicy(context.Background(), siteNp.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		testLeaf(false, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName})
		deleteNetworkPolicyDone()

		By("Verify Adding NetworkPolicy")
		matcherStage = matcherStageAddNP
		addNetworkPolicy(siteNp)
		testLeaf(false, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name})
		drainEvents()

		By("Verify duplicated Leaf")
		err = vpcManager.CreateOrUpdateNetworkDevice(context.Background(), networkfabric.LeafName, leaf.Name)
		Expect(err).ToNot(HaveOccurred())
		testLeaf(false, true, &matchers[matcherStage], nil)

		By("Verify duplicated NetworkPolicy")
		err = vpcManager.CreateOrUpdateNetworkPolicy(context.Background(), siteNp.Name)
		Expect(err).ToNot(HaveOccurred())
		testLeaf(false, true, &matchers[matcherStage], nil)

		By("Verify deleting leaf")
		matcherStage = matcherStageNoLeaf
		testLeafDelete(&matchers[matcherStage])

		err = vpcManager.DeleteNetworkPolicy(context.Background(), siteNp.Name)
		Expect(err).ToNot(HaveOccurred())
	})

	It("Host on overlay network", func() {
		// Add NetworkPolicies
		addNetworkPolicy(siteNp)
		addNetworkPolicy(vpcNp)

		matchers := generateLeafMatchers(siteNp, false)
		matchers = generateManagedResourceMatchers(matchers, true)
		testExpectations(matchers)

		By("Verify adding Leaf")
		// Create leaf.
		matcherStage = matcherStageLeaf
		testLeaf(true, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name})

		By("Verify adding ManagedResource")
		matcherStage = matcherStageManagedResource
		testManagedResource(true, false, true, &matchers[matcherStage],
			[]string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name, vpcNp.Name})
		drainEvents()

		By("Verify deleting NetworkPolicy")
		matcherStage = matcherStageDeleteNP
		err := vpcManager.DeleteNetworkPolicy(context.Background(), vpcNp.Name)
		Expect(err).To(BeAssignableToTypeOf(&internal.BackendConfigurationInProgress{}))
		testManagedResource(false, false, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name})
		deleteNetworkPolicyDone()

		By("Verify Adding NetworkPolicy")
		matcherStage = matcherStageAddNP
		addNetworkPolicy(vpcNp)
		testManagedResource(false, false, false, &matchers[matcherStage], []string{internal.DefaultDenyNetworkPolicyName, internal.DefaultPermitNetworkPolicyName, siteNp.Name, vpcNp.Name})

		By("Verify duplicated ManagedResource")
		err = vpcManager.AddOrUpdateResourceToNetwork(context.Background(), mr.Name)
		Expect(err).ToNot(HaveOccurred())
		testManagedResource(false, true, false, &matchers[matcherStage], nil)

		By("Verify duplicated NetworkPolicy")
		err = vpcManager.CreateOrUpdateNetworkPolicy(context.Background(), vpcNp.Name)
		Expect(err).ToNot(HaveOccurred())
		testManagedResource(false, true, false, &matchers[matcherStage], nil)

		By("Verify deleting ManagedResource")
		matcherStage = matcherStageNoManagedResource
		testManagedResourceDelete(&matchers[matcherStage])

		By("Verify deleting leaf")
		matcherStage = matcherStageNoLeaf
		testLeafDelete(&matchers[matcherStage])

		err = vpcManager.DeleteNetworkPolicy(context.Background(), siteNp.Name)
		Expect(err).ToNot(HaveOccurred())
		err = vpcManager.DeleteNetworkPolicy(context.Background(), vpcNp.Name)
		Expect(err).ToNot(HaveOccurred())
	})

	It("Host in Admin state, reconcile random order", func() {
		By("Verify no transaction on leaf")
	})

	It("Host on overlay network, reconcile random order", func() {
		By("Verify no transaction on leaf")
	})
})
