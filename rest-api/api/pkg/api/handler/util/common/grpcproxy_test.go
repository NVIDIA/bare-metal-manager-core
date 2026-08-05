// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	temporalEnums "go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/grpcproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

// startedProxyWorkflow captures what a proxy helper handed to Temporal.
type startedProxyWorkflow struct {
	options      tclient.StartWorkflowOptions
	workflowName string
}

// newTimingOutProxyClient returns a Temporal client whose workflow never
// produces a result, so helpers take their timeout path.
func newTimingOutProxyClient() (*tmocks.Client, *startedProxyWorkflow) {
	workflowRun := &tmocks.WorkflowRun{}
	workflowRun.On("Get", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)

	started := &startedProxyWorkflow{}
	temporalClient := &tmocks.Client{}
	temporalClient.On(
		"ExecuteWorkflow",
		mock.Anything,
		mock.MatchedBy(func(options tclient.StartWorkflowOptions) bool {
			started.options = options
			return true
		}),
		mock.Anything,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		started.workflowName = args.Get(2).(string)
	}).Return(workflowRun, nil)

	return temporalClient, started
}

func TestExecuteCoreGRPC(t *testing.T) {
	temporalClient, started := newTimingOutProxyClient()

	err := ExecuteCoreGRPC(
		context.Background(),
		temporalClient,
		"/forge.Forge/Test",
		&emptypb.Empty{},
		nil,
		"",
	)

	t.Run("starts the Core proxy workflow", func(t *testing.T) {
		assert.Equal(t, grpcproxy.Core.WorkflowName, started.workflowName)
	})

	t.Run("generates a fresh workflow ID so identical calls never coalesce", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(started.options.ID, "core-grpc-Test-"), "got %q", started.options.ID)
		assert.Equal(t, temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_UNSPECIFIED, started.options.WorkflowIDConflictPolicy)
	})

	t.Run("expires before the caller gives up", func(t *testing.T) {
		assert.Equal(t, grpcproxy.WorkflowExecutionTimeout, started.options.WorkflowExecutionTimeout)
		assert.Less(t, started.options.WorkflowExecutionTimeout, cutil.WorkflowContextTimeout)
	})

	t.Run("reports a timeout as 504", func(t *testing.T) {
		require.NotNil(t, err)
		assert.Equal(t, http.StatusGatewayTimeout, err.Code)
		assert.Equal(t, "Core proxy request timed out", err.Message)
	})
}

func TestExecuteFlowGRPC(t *testing.T) {
	temporalClient, started := newTimingOutProxyClient()

	const workflowID = "flow-grpc-get-operation-run-run-1-true"
	err := ExecuteFlowGRPC(
		context.Background(),
		temporalClient,
		"/v1.Flow/GetOperationRun",
		&emptypb.Empty{},
		nil,
		workflowID,
		temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		"",
	)

	t.Run("starts the Flow proxy workflow", func(t *testing.T) {
		assert.Equal(t, grpcproxy.Flow.WorkflowName, started.workflowName)
	})

	t.Run("passes the caller's ID and conflict policy through", func(t *testing.T) {
		assert.Equal(t, workflowID, started.options.ID)
		assert.Equal(t, temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING, started.options.WorkflowIDConflictPolicy)
		assert.Equal(t, temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE, started.options.WorkflowIDReusePolicy)
	})

	t.Run("expires before the caller gives up", func(t *testing.T) {
		assert.Equal(t, grpcproxy.WorkflowExecutionTimeout, started.options.WorkflowExecutionTimeout)
		assert.Less(t, started.options.WorkflowExecutionTimeout, cutil.WorkflowContextTimeout)
	})

	t.Run("reports a timeout as 504", func(t *testing.T) {
		require.NotNil(t, err)
		assert.Equal(t, http.StatusGatewayTimeout, err.Code)
		assert.Equal(t, "Flow proxy request timed out", err.Message)
	})
}
