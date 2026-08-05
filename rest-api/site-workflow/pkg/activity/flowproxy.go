// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/flowproxy"
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/secretjson"
	cloudutils "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	"github.com/rs/zerolog/log"
)

// ManageFlowProxy is the activity wrapper for the generic Flow gRPC proxy.
type ManageFlowProxy struct {
	flowGrpcAtomicClient *client.FlowGrpcAtomicClient
	// secretKey decrypts the redacted secret fields carried in
	// flowproxy.Request.EncryptedSecrets. It is the shared site key (the
	// site/cluster ID), matching the key the cloud used to encrypt them.
	secretKey string
}

// NewManageFlowProxy returns a new ManageFlowProxy bound to the Flow gRPC
// client and the site secret key used to decrypt redacted request fields.
func NewManageFlowProxy(flowGrpcClient *client.FlowGrpcAtomicClient, secretKey string) ManageFlowProxy {
	return ManageFlowProxy{
		flowGrpcAtomicClient: flowGrpcClient,
		secretKey:            secretKey,
	}
}

// InvokeFlowGRPCOnSite proxies a single Flow gRPC call described by req. Any
// redacted secret fields are decrypted and merged back into the request before
// it reaches Flow. The request body is intentionally never logged because it
// may contain secrets; only the method is.
func (m *ManageFlowProxy) InvokeFlowGRPCOnSite(ctx context.Context, req flowproxy.Request) (flowproxy.Response, error) {
	logger := log.With().Str("Activity", "InvokeFlowGRPCOnSite").Str("Method", req.FullMethod).Logger()
	logger.Info().Msg("Starting activity")

	grpcClient := m.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return flowproxy.Response{}, client.ErrFlowGrpcClientNotConnected
	}

	reqJSON := req.RequestJSON
	if len(req.EncryptedSecrets) > 0 {
		secretsJSON := cloudutils.DecryptData(req.EncryptedSecrets, m.secretKey)
		merged, err := secretjson.Merge(reqJSON, secretsJSON)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to merge request secrets")
			return flowproxy.Response{}, swe.WrapErr(err)
		}
		reqJSON = merged
	}

	respJSON, err := grpcClient.InvokeJSON(ctx, req.FullMethod, reqJSON)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to proxy Flow gRPC call")
		return flowproxy.Response{}, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return flowproxy.Response{ResponseJSON: respJSON}, nil
}
