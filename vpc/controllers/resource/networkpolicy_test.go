package resource_test

import (
	"context"
	"fmt"
	"reflect"

	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	vpcresource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/testing"
)

var _ = Describe("Networkpolicy", func() {
	const (
		npName      = "test-np"
		npNamespace = "default"
	)

	var (
		mockController *gomock.Controller
		mockVPCMgr     *testing.MockVPCManager
		np             *vpcresource.NetworkPolicy
		npKey          client.ObjectKey
		npCond         *vpcresource.NetworkPolicyCondition
		npProperties   *properties.NetworkPolicyProperties
	)

	BeforeEach(func() {
		mockController = gomock.NewController(GinkgoT())
		mockVPCMgr = testing.NewMockVPCManager(mockController)
		npReconciler.VPCMgr = mockVPCMgr
		npKey = client.ObjectKey{
			Namespace: npNamespace,
			Name:      npName,
		}
		np = &vpcresource.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      npName,
				Namespace: npNamespace,
			},
			Spec: vpcresource.NetworkPolicySpec{
				ManagedResourceSelector: vpcresource.LabelSelector{},
				LeafSelector:            vpcresource.LabelSelector{},
				IngressRules:            nil,
				EgressRules:             nil,
			},
		}
		npCond = &vpcresource.NetworkPolicyCondition{
			Type:   vpcresource.NetworkPolicyConditionTypeCreate,
			Status: corev1.ConditionTrue,
		}
		npProperties = &properties.NetworkPolicyProperties{ID: 1}
	})

	AfterEach(func() {
		mockController.Finish()
	})

	setNpExpectations := func() {
		mockVPCMgr.EXPECT().CreateOrUpdateNetworkPolicy(gomock.Any(), npName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				return nil
			})
		mockVPCMgr.EXPECT().GetNetworkPolicyProperties(gomock.Any(), npName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) (*properties.NetworkPolicyProperties, error) {
				return npProperties, nil
			})
	}

	setNpDeleteExpectations := func() {
		mockVPCMgr.EXPECT().DeleteNetworkPolicy(gomock.Any(), npName).MinTimes(1).DoAndReturn(
			func(_ context.Context, _ string) error {
				return nil
			})
	}

	It("Network policy", func() {
		setNpExpectations()
		setNpDeleteExpectations()

		By("Create NetworkPolicy")
		err := k8sClient.Create(context.Background(), np)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			tnp := &vpcresource.NetworkPolicy{}
			if err := k8sClient.Get(context.Background(), npKey, tnp); err != nil {
				return err
			}
			if !controllerutil.ContainsFinalizer(tnp, vpcresource.NetworkPolicyFinalizer) {
				return fmt.Errorf("missing finalizer")
			}
			if len(tnp.Status.Conditions) == 0 {
				return fmt.Errorf("wait for condition")
			}
			tnp.Status.Conditions[0].LastTransitionTime = metav1.Time{}
			if !reflect.DeepEqual(&tnp.Status.Conditions[0], npCond) || tnp.Status.ID != npProperties.ID {
				return fmt.Errorf("wait for status")
			}
			return nil
		}, 10, 1).Should(BeNil())

		By("Delete NetworkPolicy")
		err = k8sClient.Delete(context.Background(), np)
		Expect(err).ToNot(HaveOccurred())
		Eventually(func() error {
			err := k8sClient.Get(context.Background(), npKey, np)
			if err == nil {
				return fmt.Errorf("still present")
			}
			return client.IgnoreNotFound(err)
		}, 10, 1).Should(BeNil())
	})
})
