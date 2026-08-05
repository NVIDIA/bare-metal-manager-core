// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkactivity "go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/flowproxy"
)

func TestInvokeFlowGRPCActivityDeadlinePrecedesWorkflowTimeout(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	var activityDeadline time.Time
	var hasActivityDeadline bool

	env.RegisterActivityWithOptions(
		func(ctx context.Context, _ flowproxy.Request) (flowproxy.Response, error) {
			activityDeadline, hasActivityDeadline = ctx.Deadline()
			return flowproxy.Response{}, nil
		},
		sdkactivity.RegisterOptions{Name: "InvokeFlowGRPCOnSite"},
	)

	env.ExecuteWorkflow(InvokeFlowGRPC, flowproxy.Request{FullMethod: "/v1.Flow/Version"})

	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	require.True(t, hasActivityDeadline)

	// The deadline must track ActivityStartToCloseTimeout rather than any fixed
	// duration, so tuning the ladder does not require editing this test.
	remaining := time.Until(activityDeadline)
	require.Greater(t, remaining, flowproxy.ActivityStartToCloseTimeout-time.Second)
	require.LessOrEqual(t, remaining, flowproxy.ActivityStartToCloseTimeout)
}
