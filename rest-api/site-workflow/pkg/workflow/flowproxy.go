// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/flowproxy"
	"github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// InvokeFlowGRPC is the generic workflow that proxies one already-built Flow
// (v1.Flow) gRPC request on the site. It replaces per-method workflow/activity
// pairs: the cloud handler validates and builds each typed request, chooses the
// Temporal workflow ID and conflict policy, and this workflow forwards one
// proxy invocation to the site activity that holds the Flow connection.
//
// The function name must match flowproxy.WorkflowName.
func InvokeFlowGRPC(ctx workflow.Context, req flowproxy.Request) (flowproxy.Response, error) {
	logger := log.With().Str("Workflow", "InvokeFlowGRPC").Str("Method", req.FullMethod).Logger()
	logger.Info().Msg("Starting workflow")

	// No automatic retries: a proxied call may be a non-idempotent mutation, so
	// the activity runs exactly once and the caller decides whether to retry.
	options := workflow.ActivityOptions{
		StartToCloseTimeout: flowproxy.ActivityStartToCloseTimeout,
		RetryPolicy: &temporal.RetryPolicy{
			MaximumAttempts: 1,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, options)

	var manager activity.ManageFlowProxy
	var resp flowproxy.Response
	err := workflow.ExecuteActivity(ctx, manager.InvokeFlowGRPCOnSite, req).Get(ctx, &resp)
	if err != nil {
		logger.Error().Err(err).Str("Activity", "InvokeFlowGRPCOnSite").Msg("Failed to execute activity from workflow")
		return flowproxy.Response{}, err
	}

	logger.Info().Msg("Completing workflow")
	return resp, nil
}
