// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	rActivity "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
)

// RunWorkflowTestSuite exercises the eight Run
// workflows. Each workflow is a thin pass-through to a ManageTaskRun activity,
// so the tests assert the happy path forwards the activity result and that an
// activity failure surfaces as a workflow ApplicationError.
type RunWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *RunWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *RunWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func TestTaskRunWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(RunWorkflowTestSuite))
}

func (s *RunWorkflowTestSuite) assertActivityError(err error, errMsg string) {
	s.Require().Error(err)
	var applicationErr *temporal.ApplicationError
	s.Require().ErrorAs(err, &applicationErr)
	s.Equal(errMsg, applicationErr.Error())
}

func (s *RunWorkflowTestSuite) Test_CreateTaskRun_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.CreateOperationRunResponse{Id: &flowv1.UUID{Id: "run-id"}}

	s.env.RegisterActivity(mc.CreateTaskRunOnFlow)
	s.env.OnActivity(mc.CreateTaskRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CreateTaskRun, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CreateOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_CreateTaskRun_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "flow rejected configuration"

	s.env.RegisterActivity(mc.CreateTaskRunOnFlow)
	s.env.OnActivity(mc.CreateTaskRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CreateTaskRun, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetTaskRun_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.GetOperationRunResponse{
		OperationRun: &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}},
	}

	s.env.RegisterActivity(mc.GetTaskRunFromFlow)
	s.env.OnActivity(mc.GetTaskRunFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetTaskRun, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.GetOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetOperationRun().GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_GetTaskRun_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "run not found"

	s.env.RegisterActivity(mc.GetTaskRunFromFlow)
	s.env.OnActivity(mc.GetTaskRunFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetTaskRun, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetAllTaskRuns_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.ListOperationRunsResponse{
		OperationRuns: []*flowv1.OperationRunSummary{{Id: &flowv1.UUID{Id: "run-id"}}},
		Total:         1,
	}

	s.env.RegisterActivity(mc.GetAllTaskRunsFromFlow)
	s.env.OnActivity(mc.GetAllTaskRunsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetAllTaskRuns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetOperationRuns()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *RunWorkflowTestSuite) Test_GetAllTaskRuns_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "flow connection failed"

	s.env.RegisterActivity(mc.GetAllTaskRunsFromFlow)
	s.env.OnActivity(mc.GetAllTaskRunsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetAllTaskRuns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetAllTaskRunTargets_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.ListOperationRunTargetsResponse{
		Targets: []*flowv1.OperationRunTarget{{Id: &flowv1.UUID{Id: "target-id"}}},
		Total:   1,
	}

	s.env.RegisterActivity(mc.GetAllTaskRunTargetsFromFlow)
	s.env.OnActivity(mc.GetAllTaskRunTargetsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetAllTaskRunTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunTargetsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTargets()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *RunWorkflowTestSuite) Test_GetAllTaskRunTargets_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "run not found"

	s.env.RegisterActivity(mc.GetAllTaskRunTargetsFromFlow)
	s.env.OnActivity(mc.GetAllTaskRunTargetsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetAllTaskRunTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_PauseTaskRun_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.PauseTaskRunOnFlow)
	s.env.OnActivity(mc.PauseTaskRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(PauseTaskRun, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_PauseTaskRun_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "run already terminal"

	s.env.RegisterActivity(mc.PauseTaskRunOnFlow)
	s.env.OnActivity(mc.PauseTaskRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PauseTaskRun, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_ResumeTaskRun_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.ResumeTaskRunOnFlow)
	s.env.OnActivity(mc.ResumeTaskRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(ResumeTaskRun, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_ResumeTaskRun_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "run not paused"

	s.env.RegisterActivity(mc.ResumeTaskRunOnFlow)
	s.env.OnActivity(mc.ResumeTaskRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(ResumeTaskRun, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_AdvanceTaskRunPhase_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.AdvanceTaskRunPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceTaskRunPhaseOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(AdvanceTaskRunPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_AdvanceTaskRunPhase_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "unexpected phase index"

	s.env.RegisterActivity(mc.AdvanceTaskRunPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceTaskRunPhaseOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(AdvanceTaskRunPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_CancelTaskRun_Success() {
	var mc rActivity.ManageTaskRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.CancelTaskRunOnFlow)
	s.env.OnActivity(mc.CancelTaskRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CancelTaskRun, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_CancelTaskRun_ActivityFails() {
	var mc rActivity.ManageTaskRun
	errMsg := "run already terminal"

	s.env.RegisterActivity(mc.CancelTaskRunOnFlow)
	s.env.OnActivity(mc.CancelTaskRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CancelTaskRun, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}
