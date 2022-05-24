/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	networkfabricv1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	resourcev1alpha1 "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
	config2 "gitlab-master.nvidia.com/forge/vpc/cmd/controller/config"
	"gitlab-master.nvidia.com/forge/vpc/controllers"
	networkfabriccontrollers "gitlab-master.nvidia.com/forge/vpc/controllers/networkfabric"
	resourcecontrollers "gitlab-master.nvidia.com/forge/vpc/controllers/resource"
	"gitlab-master.nvidia.com/forge/vpc/pkg/resourcepool"
	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(resourcev1alpha1.AddToScheme(scheme))
	utilruntime.Must(networkfabricv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var configFile, nvueFile, dhcrelayFile string

	flag.StringVar(&configFile, "config", "", "Configuration file")
	flag.StringVar(&nvueFile, "hbn-nvue-config", "", "HBN Nvue configuration file")
	flag.StringVar(&dhcrelayFile, "hbn-dhcrelay-config", "", "HBN DHCRelay configuration file")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	in, err := os.ReadFile(configFile)
	if err != nil {
		setupLog.Error(err, "Failed to open config file", "Path", configFile)
		os.Exit(1)
	}
	config := &config2.Config{}
	if err := config.Parse(in); err != nil {
		setupLog.Error(err, "Failed to parse config file")
		os.Exit(1)
	}
	vpc.HBNConfig.HBNDevice = config.Forge.HBNDevice
	vpc.HBNConfig.DefaultASN = config.Forge.DefaultASN
	vpc.HBNConfig.NVUEConfig, err = os.ReadFile(nvueFile)
	if err != nil {
		setupLog.Error(err, "Failed to open nvue config file", "Path", nvueFile)
		os.Exit(1)
	}
	vpc.HBNConfig.DHCPRelayConfig, err = os.ReadFile(dhcrelayFile)
	if err != nil {
		setupLog.Error(err, "Failed to open dhcrelay config file", "Path", dhcrelayFile)
		os.Exit(1)
	}
	setupLog.Info("Input configurations", "Config", config)
	setupLog.WithName("NVUE").Info(fmt.Sprintln(string(vpc.HBNConfig.NVUEConfig)))
	setupLog.WithName("DHCRelay").Info(fmt.Sprintln(string(vpc.HBNConfig.DHCPRelayConfig)))

	ns := os.Getenv("K8S_NAMESPACE")
	if len(ns) == 0 {
		ns = "forge-system"
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		MetricsBindAddress:      config.Metrics.BindAddress,
		Namespace:               ns,
		Port:                    config.Webhook.Port,
		HealthProbeBindAddress:  config.Health.HealthProbeBindAddress,
		LeaderElection:          config.LeaderElection.LeaderElect,
		LeaderElectionID:        config.LeaderElection.ResourceName,
		LeaderElectionNamespace: ns,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	podController := controllers.NewPodController(mgr.GetClient(), mgr.GetScheme(), ns)
	if err = podController.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Pod")
		os.Exit(1)
	}
	resourceMgr := resourcepool.NewManager(mgr.GetClient(), ns)
	vpcMgr := vpc.NewVPCManager(mgr.GetClient(), podController, ns, resourceMgr)
	_ = mgr.Add(vpcMgr)
	rgMgr := &resourcecontrollers.ResourceGroupReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		VPCMgr: vpcMgr,
	}
	if err = rgMgr.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ResourceGroup")
		os.Exit(1)
	}
	_ = mgr.Add(rgMgr)
	mrContrl := &resourcecontrollers.ManagedResourceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		VPCMgr: vpcMgr,
	}
	if err = mrContrl.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ManagedResource")
		os.Exit(1)
	}
	_ = mgr.Add(mrContrl)
	if err = (&resourcecontrollers.SharedResourceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "SharedResource")
		os.Exit(1)
	}
	leafMgr := &networkfabriccontrollers.LeafReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		VPCMgr: vpcMgr,
	}
	if err = leafMgr.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Leaf")
		os.Exit(1)
	}
	_ = mgr.Add(leafMgr)
	if err = (&resourcev1alpha1.ResourceGroup{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ResourceGroup")
		os.Exit(1)
	}
	if err = (&resourcev1alpha1.ManagedResource{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ManagedResource")
		os.Exit(1)
	}
	if err = (&networkfabriccontrollers.ConfigurationResourcePoolReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		ResourceMgr: resourceMgr,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ConfigurationResourcePool")
		os.Exit(1)
	}
	if err = (&networkfabricv1alpha1.ConfigurationResourcePool{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "ConfigurationResourcePool")
		os.Exit(1)
	}
	if err = (&networkfabricv1alpha1.Leaf{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "Leaf")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
