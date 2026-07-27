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
// workflows. Each workflow is a thin pass-through to a ManageRun activity,
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

func TestRunWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(RunWorkflowTestSuite))
}

func (s *RunWorkflowTestSuite) assertActivityError(err error, errMsg string) {
	s.Error(err)
	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *RunWorkflowTestSuite) Test_CreateRun_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.CreateOperationRunResponse{Id: &flowv1.UUID{Id: "run-id"}}

	s.env.RegisterActivity(mc.CreateRunOnFlow)
	s.env.OnActivity(mc.CreateRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CreateRun, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CreateOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_CreateRun_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "flow rejected configuration"

	s.env.RegisterActivity(mc.CreateRunOnFlow)
	s.env.OnActivity(mc.CreateRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CreateRun, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetRun_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.GetOperationRunResponse{
		OperationRun: &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}},
	}

	s.env.RegisterActivity(mc.GetRunFromFlow)
	s.env.OnActivity(mc.GetRunFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetRun, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.GetOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetOperationRun().GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_GetRun_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "run not found"

	s.env.RegisterActivity(mc.GetRunFromFlow)
	s.env.OnActivity(mc.GetRunFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetRun, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetAllRuns_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.ListOperationRunsResponse{
		OperationRuns: []*flowv1.OperationRunSummary{{Id: &flowv1.UUID{Id: "run-id"}}},
		Total:         1,
	}

	s.env.RegisterActivity(mc.GetAllRunsFromFlow)
	s.env.OnActivity(mc.GetAllRunsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetAllRuns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetOperationRuns()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *RunWorkflowTestSuite) Test_GetAllRuns_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "flow connection failed"

	s.env.RegisterActivity(mc.GetAllRunsFromFlow)
	s.env.OnActivity(mc.GetAllRunsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetAllRuns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_GetRunTargets_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.ListOperationRunTargetsResponse{
		Targets: []*flowv1.OperationRunTarget{{Id: &flowv1.UUID{Id: "target-id"}}},
		Total:   1,
	}

	s.env.RegisterActivity(mc.GetRunTargetsFromFlow)
	s.env.OnActivity(mc.GetRunTargetsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetRunTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunTargetsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTargets()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *RunWorkflowTestSuite) Test_GetRunTargets_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "run not found"

	s.env.RegisterActivity(mc.GetRunTargetsFromFlow)
	s.env.OnActivity(mc.GetRunTargetsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetRunTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_PauseRun_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.PauseRunOnFlow)
	s.env.OnActivity(mc.PauseRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(PauseRun, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_PauseRun_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "run already terminal"

	s.env.RegisterActivity(mc.PauseRunOnFlow)
	s.env.OnActivity(mc.PauseRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PauseRun, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_ResumeRun_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.ResumeRunOnFlow)
	s.env.OnActivity(mc.ResumeRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(ResumeRun, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_ResumeRun_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "run not paused"

	s.env.RegisterActivity(mc.ResumeRunOnFlow)
	s.env.OnActivity(mc.ResumeRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(ResumeRun, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_AdvanceRunPhase_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.AdvanceRunPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceRunPhaseOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(AdvanceRunPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_AdvanceRunPhase_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "unexpected phase index"

	s.env.RegisterActivity(mc.AdvanceRunPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceRunPhaseOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(AdvanceRunPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "run-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *RunWorkflowTestSuite) Test_CancelRun_Success() {
	var mc rActivity.ManageRun
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "run-id"}}}

	s.env.RegisterActivity(mc.CancelRunOnFlow)
	s.env.OnActivity(mc.CancelRunOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CancelRun, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("run-id", response.GetSummary().GetId().GetId())
}

func (s *RunWorkflowTestSuite) Test_CancelRun_ActivityFails() {
	var mc rActivity.ManageRun
	errMsg := "run already terminal"

	s.env.RegisterActivity(mc.CancelRunOnFlow)
	s.env.OnActivity(mc.CancelRunOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CancelRun, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "run-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}
