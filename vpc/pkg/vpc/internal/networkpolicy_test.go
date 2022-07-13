package internal_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		Rules  *internal.NetworkPolicyRules
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
							Protocol: "UDP",
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
								Protocol: "TCP",
							},
							{
								Begin:    8080,
								Protocol: "TCP",
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

	generateLeafMatchers := func(snp *v1alpha1.NetworkPolicy, toggoleNp bool) [][]networkPolicyMatch {
		matchers := [][]networkPolicyMatch{
			{ // matcherStageLeaf
				{
					Method: http.MethodPost,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultPermitNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
				{
					Method: http.MethodPost,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultDenyNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			},
			{ // matcherStageManagedResource
				{
					Method: http.MethodDelete,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultPermitNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
				{
					Method: http.MethodDelete,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultDenyNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			},
			{}, // matcherStageDeleteNP
			{}, // matcherStageAddNP
			{ // matcherStageNoManagedResource
				{
					Method: http.MethodPost,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultPermitNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
				{
					Method: http.MethodPost,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultDenyNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			},
			{ // matcherStageNoLeaf
				{
					Method: http.MethodDelete,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultPermitNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
				{
					Method: http.MethodDelete,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules: internal.DefaultDenyNetworkPolicy.GetRules(
						internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			},
		}
		if snp == nil {
			return matchers
		}
		np := (&internal.NetworkPolicy{}).Populate(snp)
		matchers[matcherStageLeaf] = append(matchers[matcherStageLeaf],
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + networkfabric.LeafName,
				Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
			})
		matchers[matcherStageNoLeaf] = append(matchers[matcherStageNoLeaf],
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + networkfabric.LeafName,
				Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
			})
		matchers[matcherStageManagedResource] = append(matchers[matcherStageManagedResource],
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + networkfabric.LeafName,
				Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
			})
		matchers[matcherStageNoManagedResource] = append(matchers[matcherStageNoManagedResource],
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + networkfabric.LeafName,
				Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
			})
		// matcher for test remove and add site-np on leafs.
		if toggoleNp {
			matchers[matcherStageDeleteNP] = []networkPolicyMatch{
				{
					Method: http.MethodDelete,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			}
			matchers[matcherStageAddNP] = []networkPolicyMatch{
				{
					Method: http.MethodPost,
					Url:    "network-policy/" + networkfabric.LeafName,
					Rules:  np.GetRules(internal.HostAdminLeafPort, leaf.Name, networkfabric.LeafName, nil),
				},
			}

		}
		return matchers
	}

	generateManagedResourceMatchers := func(matchers [][]networkPolicyMatch, snp, vnp *v1alpha1.NetworkPolicy, toggoleNp bool) [][]networkPolicyMatch {
		leafPort := ""
		for _, v := range leaf.Spec.HostInterfaces {
			leafPort = v
		}
		// Re-write ManagedResourceSelector with ManagedResource IP for validation because
		// at this time, ManagedResource is not known to the manager.
		vnp = vnp.DeepCopy()
		for _, rule := range vnp.Spec.IngressRules {
			rule.FromAddresses[0].ManagedResourceSelector.MatchLabels = nil
			rule.FromAddresses[0].IPCIDR = mr.Spec.HostInterfaceIP + "/32"
		}
		ivnp := (&internal.NetworkPolicy{}).Populate(vnp)
		isnp := (&internal.NetworkPolicy{}).Populate(snp)

		matchers[matcherStageManagedResource] = append(matchers[matcherStageManagedResource],
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  internal.DefaultPermitNetworkPolicy.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  internal.DefaultDenyNetworkPolicy.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  isnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodPost,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  ivnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			})
		matchers[matcherStageNoManagedResource] = append(matchers[matcherStageNoManagedResource],
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  internal.DefaultPermitNetworkPolicy.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  internal.DefaultDenyNetworkPolicy.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  isnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			},
			networkPolicyMatch{
				Method: http.MethodDelete,
				Url:    "network-policy/" + v1alpha1.ManagedResourceName,
				Rules:  ivnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
			})

		if toggoleNp {
			matchers[matcherStageAddNP] = append(matchers[matcherStageAddNP],
				networkPolicyMatch{
					Method: http.MethodPost,
					Url:    "network-policy/" + v1alpha1.ManagedResourceName,
					Rules:  ivnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
				})
			matchers[matcherStageDeleteNP] = append(matchers[matcherStageDeleteNP],
				networkPolicyMatch{
					Method: http.MethodDelete,
					Url:    "network-policy/" + v1alpha1.ManagedResourceName,
					Rules:  ivnp.GetRules(leafPort, mr.Name, v1alpha1.ManagedResourceName, nil),
				})
		}
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
				} /* else if req.Method == http.MethodPatch && strings.HasSuffix(req.URL.String(), "/revision/revision_1") {
					// Validate commits here.
				} */
				if !strings.Contains(req.URL.String(), "/network-policy") {
					// Don't care if not NetworkPolicy related in this test.
					return json.Marshal(&map[string]interface{}{
						"status": 200})
				}
				var rules internal.NetworkPolicyRules
				data := make([]byte, 1024)
				n, err := req.Body.Read(data)
				Expect(err).ToNot(HaveOccurred())
				err = json.Unmarshal(data[0:n], &rules)
				Expect(err).ToNot(HaveOccurred())
				for _, rule := range rules.Rules {
					if rule.Addresses != nil {
						rule.Addresses.IP = rule.Addresses.IP.To4()
					}
				}
				logf.Log.V(1).Info("http mock", "NetworkPolicyRules", rules)
				tmpMatchers := matchers[matcherStage]
				for i := range tmpMatchers {
					matcher := &tmpMatchers[i]
					if strings.Contains(req.URL.String(), matcher.Url) && req.Method == matcher.Method &&
						rules.Equal(matcher.Rules) {
						matchers[matcherStage][i] = matchers[matcherStage][len(tmpMatchers)-1]
						tmpMatchers = tmpMatchers[:len(tmpMatchers)-1]
						break
					}
				}
				if len(tmpMatchers)+1 != len(matchers[matcherStage]) {
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
		np.Status.ID = npProp.ID
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
		Expect(*matchers).To(BeEmpty())
	}

	drainEvents := func() {
		leafEventChan := vpcManager.GetEvent(networkfabric.LeafName)
		mrEventChan := vpcManager.GetEvent(v1alpha1.ManagedResourceName)
		npEventChan := vpcManager.GetEvent(v1alpha1.NetworkPolicyName)
		stop := time.Tick(time.Second * 2)
		for {
			select {
			case <-leafEventChan:
				continue
			case <-mrEventChan:
				continue
			case <-npEventChan:
				continue
			case <-stop:
				return
			}
		}
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
		matchers = generateManagedResourceMatchers(matchers, siteNp, vpcNp, true)
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
