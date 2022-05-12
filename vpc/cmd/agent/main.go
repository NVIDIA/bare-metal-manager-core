package main

import (
	"flag"
	"fmt"
	"os"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	agent2 "gitlab-master.nvidia.com/forge/vpc/pkg/agent"
)

func main() {
	var transportBr, uplink, hostlink, bindPort, certDir string
	flag.StringVar(&transportBr, "transport-bridge", "br-transport", "The OVN transport bridge name.")
	flag.StringVar(&bindPort, "service-port", fmt.Sprintf(":%d", agent2.AgentServicePort), "The agent service listening port.")
	flag.StringVar(&uplink, "uplink", "p0", "The link connecting to the outside.")
	flag.StringVar(&hostlink, "host-link", "pf0", "The link connecting to the host.")
	flag.StringVar(&certDir, "certificate-dir", "", "The directory contains mTLS certificates between agent and controller.")
	flag.StringVar(&certDir, "ovn-certificate-dir", "", "The directory contains mTLS OVN certificates.")

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	logf.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	agent := agent2.NewVPCAgent(transportBr, uplink, hostlink, bindPort)
	if err := agent.Start(certDir); err != nil {
		logf.Log.Error(err, "Starting agent failed")
		os.Exit(-1)
	}
}
