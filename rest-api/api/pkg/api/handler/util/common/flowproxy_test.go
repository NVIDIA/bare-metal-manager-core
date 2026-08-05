// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	temporalEnums "go.temporal.io/api/enums/v1"
	tclient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/flowproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

func TestExecuteFlowGRPCPassesCallerIDAndConflictPolicy(t *testing.T) {
	workflowRun := &tmocks.WorkflowRun{}
	workflowRun.On("Get", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)

	var workflowOptions tclient.StartWorkflowOptions
	var workflowName string
	temporalClient := &tmocks.Client{}
	temporalClient.On(
		"ExecuteWorkflow",
		mock.Anything,
		mock.MatchedBy(func(options tclient.StartWorkflowOptions) bool {
			workflowOptions = options
			return true
		}),
		mock.Anything,
		mock.Anything,
	).Run(func(args mock.Arguments) {
		workflowName = args.Get(2).(string)
	}).Return(workflowRun, nil)

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

	require.Equal(t, flowproxy.WorkflowName, workflowName)
	require.Equal(t, workflowID, workflowOptions.ID)
	require.Equal(t, temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING, workflowOptions.WorkflowIDConflictPolicy)
	require.Equal(t, temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE, workflowOptions.WorkflowIDReusePolicy)
	require.Equal(t, flowproxy.WorkflowExecutionTimeout, workflowOptions.WorkflowExecutionTimeout)
	require.Less(t, flowproxy.ActivityStartToCloseTimeout, flowproxy.WorkflowExecutionTimeout)
	require.Less(t, flowproxy.WorkflowExecutionTimeout, cutil.WorkflowContextTimeout)
	require.NotNil(t, err)
	require.Equal(t, http.StatusGatewayTimeout, err.Code)
	require.Equal(t, "Flow proxy request timed out", err.Message)
}
