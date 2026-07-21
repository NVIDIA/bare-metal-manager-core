// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package common

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	tclient "go.temporal.io/sdk/client"
	tmocks "go.temporal.io/sdk/mocks"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/NVIDIA/infra-controller/rest-api/common/pkg/coreproxy"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

func TestExecuteCoreGRPCWorkflowExpiresBeforeCallerTimeout(t *testing.T) {
	workflowRun := &tmocks.WorkflowRun{}
	workflowRun.On("Get", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)

	var workflowOptions tclient.StartWorkflowOptions
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
	).Return(workflowRun, nil)

	err := ExecuteCoreGRPC(
		context.Background(),
		temporalClient,
		"/forge.Forge/Test",
		&emptypb.Empty{},
		nil,
		"",
	)

	require.Equal(t, 45*time.Second, coreproxy.WorkflowExecutionTimeout)
	require.Equal(t, coreproxy.WorkflowExecutionTimeout, workflowOptions.WorkflowExecutionTimeout)
	require.Less(t, workflowOptions.WorkflowExecutionTimeout, cutil.WorkflowContextTimeout)
	require.NotNil(t, err)
	require.Equal(t, http.StatusGatewayTimeout, err.Code)
	require.Equal(t, "Core proxy request timed out", err.Message)
}
