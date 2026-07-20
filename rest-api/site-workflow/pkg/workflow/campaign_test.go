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

// CampaignWorkflowTestSuite exercises the eight Campaign (operation-run)
// workflows. Each workflow is a thin pass-through to a ManageCampaign activity,
// so the tests assert the happy path forwards the activity result and that an
// activity failure surfaces as a workflow ApplicationError.
type CampaignWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *CampaignWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *CampaignWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func TestCampaignWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(CampaignWorkflowTestSuite))
}

func (s *CampaignWorkflowTestSuite) assertActivityError(err error, errMsg string) {
	s.Error(err)
	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *CampaignWorkflowTestSuite) Test_CreateCampaign_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.CreateOperationRunResponse{Id: &flowv1.UUID{Id: "campaign-id"}}

	s.env.RegisterActivity(mc.CreateCampaignOnFlow)
	s.env.OnActivity(mc.CreateCampaignOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CreateCampaign, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CreateOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_CreateCampaign_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "flow rejected configuration"

	s.env.RegisterActivity(mc.CreateCampaignOnFlow)
	s.env.OnActivity(mc.CreateCampaignOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CreateCampaign, &flowv1.CreateOperationRunRequest{Name: "fw-rollout"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_GetCampaign_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.GetOperationRunResponse{
		OperationRun: &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "campaign-id"}}},
	}

	s.env.RegisterActivity(mc.GetCampaignFromFlow)
	s.env.OnActivity(mc.GetCampaignFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetCampaign, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.GetOperationRunResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetOperationRun().GetSummary().GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_GetCampaign_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "campaign not found"

	s.env.RegisterActivity(mc.GetCampaignFromFlow)
	s.env.OnActivity(mc.GetCampaignFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetCampaign, &flowv1.GetOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_GetAllCampaigns_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.ListOperationRunsResponse{
		OperationRuns: []*flowv1.OperationRunSummary{{Id: &flowv1.UUID{Id: "campaign-id"}}},
		Total:         1,
	}

	s.env.RegisterActivity(mc.GetAllCampaignsFromFlow)
	s.env.OnActivity(mc.GetAllCampaignsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetAllCampaigns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetOperationRuns()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *CampaignWorkflowTestSuite) Test_GetAllCampaigns_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "flow connection failed"

	s.env.RegisterActivity(mc.GetAllCampaignsFromFlow)
	s.env.OnActivity(mc.GetAllCampaignsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetAllCampaigns, &flowv1.ListOperationRunsRequest{})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_GetCampaignTargets_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.ListOperationRunTargetsResponse{
		Targets: []*flowv1.OperationRunTarget{{Id: &flowv1.UUID{Id: "target-id"}}},
		Total:   1,
	}

	s.env.RegisterActivity(mc.GetCampaignTargetsFromFlow)
	s.env.OnActivity(mc.GetCampaignTargetsFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetCampaignTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRunTargetsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTargets()))
	s.Equal(int32(1), response.GetTotal())
}

func (s *CampaignWorkflowTestSuite) Test_GetCampaignTargets_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "campaign not found"

	s.env.RegisterActivity(mc.GetCampaignTargetsFromFlow)
	s.env.OnActivity(mc.GetCampaignTargetsFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetCampaignTargets, &flowv1.ListOperationRunTargetsRequest{OperationRunId: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_PauseCampaign_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "campaign-id"}}}

	s.env.RegisterActivity(mc.PauseCampaignOnFlow)
	s.env.OnActivity(mc.PauseCampaignOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(PauseCampaign, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetSummary().GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_PauseCampaign_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "campaign already terminal"

	s.env.RegisterActivity(mc.PauseCampaignOnFlow)
	s.env.OnActivity(mc.PauseCampaignOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PauseCampaign, &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_ResumeCampaign_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "campaign-id"}}}

	s.env.RegisterActivity(mc.ResumeCampaignOnFlow)
	s.env.OnActivity(mc.ResumeCampaignOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(ResumeCampaign, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetSummary().GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_ResumeCampaign_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "campaign not paused"

	s.env.RegisterActivity(mc.ResumeCampaignOnFlow)
	s.env.OnActivity(mc.ResumeCampaignOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(ResumeCampaign, &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_AdvanceCampaignPhase_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "campaign-id"}}}

	s.env.RegisterActivity(mc.AdvanceCampaignPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceCampaignPhaseOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(AdvanceCampaignPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetSummary().GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_AdvanceCampaignPhase_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "unexpected phase index"

	s.env.RegisterActivity(mc.AdvanceCampaignPhaseOnFlow)
	s.env.OnActivity(mc.AdvanceCampaignPhaseOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(AdvanceCampaignPhase, &flowv1.AdvanceOperationRunPhaseRequest{Id: &flowv1.UUID{Id: "campaign-id"}})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}

func (s *CampaignWorkflowTestSuite) Test_CancelCampaign_Success() {
	var mc rActivity.ManageCampaign
	expected := &flowv1.OperationRun{Summary: &flowv1.OperationRunSummary{Id: &flowv1.UUID{Id: "campaign-id"}}}

	s.env.RegisterActivity(mc.CancelCampaignOnFlow)
	s.env.OnActivity(mc.CancelCampaignOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CancelCampaign, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRun
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("campaign-id", response.GetSummary().GetId().GetId())
}

func (s *CampaignWorkflowTestSuite) Test_CancelCampaign_ActivityFails() {
	var mc rActivity.ManageCampaign
	errMsg := "campaign already terminal"

	s.env.RegisterActivity(mc.CancelCampaignOnFlow)
	s.env.OnActivity(mc.CancelCampaignOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CancelCampaign, &flowv1.CancelOperationRunRequest{Id: &flowv1.UUID{Id: "campaign-id"}, Reason: "operator"})
	s.True(s.env.IsWorkflowCompleted())
	s.assertActivityError(s.env.GetWorkflowError(), errMsg)
}
