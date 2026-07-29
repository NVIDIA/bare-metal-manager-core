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

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
)

func TestInvokeCoreGRPCActivityDeadlinePrecedesWorkflowTimeout(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	var activityDeadline time.Time
	var hasActivityDeadline bool

	env.RegisterActivityWithOptions(
		func(ctx context.Context, _ coreproxy.Request) (coreproxy.Response, error) {
			activityDeadline, hasActivityDeadline = ctx.Deadline()
			return coreproxy.Response{}, nil
		},
		sdkactivity.RegisterOptions{Name: "InvokeCoreGRPCOnSite"},
	)

	env.ExecuteWorkflow(InvokeCoreGRPC, coreproxy.Request{FullMethod: "/forge.Forge/Test"})

	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	require.True(t, hasActivityDeadline)
	require.Equal(t, 40*time.Second, coreproxy.ActivityStartToCloseTimeout)
	remaining := time.Until(activityDeadline)
	require.Greater(t, remaining, coreproxy.ActivityStartToCloseTimeout-time.Second)
	require.LessOrEqual(t, remaining, coreproxy.ActivityStartToCloseTimeout)
	require.Less(t, coreproxy.ActivityStartToCloseTimeout, coreproxy.WorkflowExecutionTimeout)
}
