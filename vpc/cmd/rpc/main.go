/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"path"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"gitlab-master.nvidia.com/forge/vpc/rpc"
)

// mTLS example
// https://github.com/kbehouse/gRPC-go-mTLS/tree/master/helloworld_mTLS

func main() {
	var bindAddr string
	var certDir string
	flag.StringVar(&bindAddr, "rpc-bind-address", ":8080", "The address the rpc server binds to")
	flag.StringVar(&certDir, "cert-dir", "", "The directory containing certificate files")
	flag.StringVar(&rpc.K8sNamespace, "crd-namespace", "forge-system", "k8s namespace to create CRDs")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	logger := zap.New(zap.UseFlagOptions(&opts))
	var s *grpc.Server
	if len(certDir) > 0 {
		//mTLS Setting
		certificate, err := tls.LoadX509KeyPair(
			path.Join(certDir, "cacert.pem"),
			path.Join(certDir, "key.pem"),
		)
		if err != nil {
			logger.Error(err, "Failed to load server certificate", "Dir", certDir)
			os.Exit(-1)
		}

		certPool := x509.NewCertPool()
		bs, err := ioutil.ReadFile(path.Join(certDir, "clientcert.pem"))
		if err != nil {
			logger.Error(err, "Failed to read client certificate", "Dir", certDir)
			os.Exit(-1)
		}

		if ok := certPool.AppendCertsFromPEM(bs); !ok {
			logger.Error(nil, "failed to append client certs")
			os.Exit(-1)
		}

		tlsConfig := &tls.Config{
			ClientAuth:   tls.RequireAndVerifyClientCert,
			Certificates: []tls.Certificate{certificate},
			ClientCAs:    certPool,
		}

		cred := grpc.Creds(credentials.NewTLS(tlsConfig))
		s = grpc.NewServer(cred)
	} else {
		s = grpc.NewServer()
	}
	// Start gRPC server.
	vpcSvr, err := rpc.NewResourceGroupServer(logger.WithName("RPC-Server"))
	if err != nil {
		logger.Error(err, "Failed to create VPC server")
		os.Exit(-1)
	}
	rpc.RegisterResourceGroupServer(s, vpcSvr)
	lis, err := net.Listen("tcp", bindAddr)
	if err != nil {
		logger.Error(err, "Failed to listen", "BindAddr", bindAddr)
		os.Exit(-1)
	}
	logger.Info("gRPC server listening on", "BindAddr", lis.Addr())
	if err := s.Serve(lis); err != nil {
		logger.Error(err, "Server failed to serve, exit ...")
		os.Exit(-1)
	}
}
