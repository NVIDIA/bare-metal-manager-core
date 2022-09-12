package v1alpha1_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	resource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

var _ = Describe("NetworkPolicy", func() {
	var (
		np *resource.NetworkPolicy
	)

	BeforeEach(func() {
		np = &resource.NetworkPolicy{
			Spec: resource.NetworkPolicySpec{
				ManagedResourceSelector: resource.LabelSelector{MatchLabels: map[string]string{"mr": "label"}},
				IngressRules: []resource.NetworkPolicyIngressRule{{
					FromAddresses: []resource.NetworkPolicyAddress{
						{IPCIDR: "1.2.3.4/32"},
						{IPCIDR: "1.2.3.5/32"},
					},
					Ports: []resource.NetworkPolicyPort{{
						Begin:    22,
						Protocol: resource.NetworkPolicyProtocolTCP,
					}},
				}},
				EgressRules: []resource.NetworkPolicyEgressRule{{
					ToAddresses: []resource.NetworkPolicyAddress{
						{IPCIDR: "0.0.0.0/0"},
					},
				}},
			},
		}
	})

	It("Test defaulting", func() {
		npCpy := np.Spec.DeepCopy()
		np.Spec.IngressRules[0].Ports[0].Protocol = ""
		np.Spec.IngressRules[0].FromAddresses[0] = resource.NetworkPolicyAddress{
			IPCIDR: "1.2.3.4",
		}
		np.Spec.EgressRules[0] = resource.NetworkPolicyEgressRule{}
		np.Default()
		Expect(np.Spec).To(Equal(*npCpy))
	})
	It("Test validating", func() {
		Expect(np.ValidateCreate()).ToNot(HaveOccurred())
	})
	It("Test validating error missing selector", func() {
		np.Spec.ManagedResourceSelector.MatchLabels = nil
		Expect(np.ValidateCreate()).To(HaveOccurred())
	})
	It("Test validating error bad port range", func() {
		np.Spec.IngressRules[0].Ports[0].End = 1
		Expect(np.ValidateCreate()).To(HaveOccurred())
	})
	It("Test validating error conflicting address spec", func() {
		np.Spec.IngressRules[0].FromAddresses[0].ManagedResourceSelector = resource.LabelSelector{
			MatchLabels: map[string]string{"mr": "label"}}
		Expect(np.ValidateCreate()).To(HaveOccurred())
	})
})
