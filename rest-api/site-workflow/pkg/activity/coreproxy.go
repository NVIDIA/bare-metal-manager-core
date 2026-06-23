// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
	cloudutils "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	"github.com/rs/zerolog/log"
)

// ManageCoreProxy is the activity wrapper for the generic NICo Core gRPC proxy.
type ManageCoreProxy struct {
	coreGrpcAtomicClient *client.CoreGrpcAtomicClient
	// secretKey decrypts the redacted secret fields carried in
	// coreproxy.Request.EncryptedSecrets. It is the shared site key (the
	// site/cluster ID), matching the key the cloud used to encrypt them.
	secretKey string
}

// NewManageCoreProxy returns a new ManageCoreProxy bound to the Core gRPC client
// and the site secret key used to decrypt redacted request fields.
func NewManageCoreProxy(coreGrpcClient *client.CoreGrpcAtomicClient, secretKey string) ManageCoreProxy {
	return ManageCoreProxy{
		coreGrpcAtomicClient: coreGrpcClient,
		secretKey:            secretKey,
	}
}

// InvokeCoreGRPCOnSite proxies a single Core gRPC call described by req. Any
// redacted secret fields are decrypted and merged back into the request before
// it reaches Core. The request body is intentionally never logged because it
// may contain secrets (e.g. BMC credential passwords); only the method is.
func (m *ManageCoreProxy) InvokeCoreGRPCOnSite(ctx context.Context, req coreproxy.Request) (coreproxy.Response, error) {
	logger := log.With().Str("Activity", "InvokeCoreGRPCOnSite").Str("Method", req.FullMethod).Logger()
	logger.Info().Msg("Starting activity")

	grpcClient := m.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return coreproxy.Response{}, client.ErrCoreGrpcClientNotConnected
	}

	reqJSON := req.RequestJSON
	if len(req.EncryptedSecrets) > 0 {
		secretsJSON := cloudutils.DecryptData(req.EncryptedSecrets, m.secretKey)
		merged, err := coreproxy.MergeSecrets(reqJSON, secretsJSON)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to merge request secrets")
			return coreproxy.Response{}, swe.WrapErr(err)
		}
		reqJSON = merged
	}

	respJSON, err := grpcClient.InvokeJSON(ctx, req.FullMethod, reqJSON)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to proxy Core gRPC call")
		return coreproxy.Response{}, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return coreproxy.Response{ResponseJSON: respJSON}, nil
}
