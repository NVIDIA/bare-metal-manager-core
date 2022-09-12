package resourcepool_test

import (
	"context"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	resourcev1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/utils"
)

var (
	k8sClient client.Client
	testEnv   *envtest.Environment
	randGen   *rand.Rand
	namespace = "forge-system"
)

func generateIPRage(prefixLen, blkCnt, size int32) [][]string {
	var ret [][]string
	mask := uint32(0xffffffff) << (32 - prefixLen)
	for i := int32(0); i < size; {
		start := randGen.Uint32() & mask
		end := start + uint32(blkCnt<<(32-prefixLen))
		if start > end {
			continue
		}
		ret = append(ret, []string{utils.Int2ip(start).String(), utils.Int2ip(end).String()})
		// logf.Log.V(1).Info("Added IP range", "Start", start, "End", end,
		//	"Blocks", blkCnt, "PrefixLen", prefixLen)
		i++
	}
	return ret
}

func generateIntegerRage(cnt, size int, lower, upper uint64) [][]uint64 {
	var ret [][]uint64
	for i := 0; i < size; {
		start := lower + uint64(randGen.Int63n(int64(upper)))
		end := start + uint64(cnt)
		if start > end || end >= upper {
			continue
		}
		ret = append(ret, []uint64{start, end})
		i++
	}
	return ret
}

func TestResourcepool(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resourcepool Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	randGen = rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = resourcev1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	err = k8sClient.Create(context.Background(), ns)
	Expect(err).NotTo(HaveOccurred())

})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
