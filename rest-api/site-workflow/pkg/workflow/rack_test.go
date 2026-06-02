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

	rActivity "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

// GetRackTestSuite tests the GetRack workflow
type GetRackTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetRackTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetRackTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetRackTestSuite) Test_GetRack_Success() {
	var rackManager rActivity.ManageRack

	rackID := "test-rack-id"
	request := &flowv1.GetRackInfoByIDRequest{
		Id: &flowv1.UUID{Id: rackID},
	}

	expectedResponse := &flowv1.GetRackInfoResponse{
		Rack: &flowv1.Rack{
			Info: &flowv1.DeviceInfo{
				Id:   &flowv1.UUID{Id: rackID},
				Name: "test-rack",
			},
		},
	}

	// Mock GetRack activity
	s.env.RegisterActivity(rackManager.GetRack)
	s.env.OnActivity(rackManager.GetRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute GetRack workflow
	s.env.ExecuteWorkflow(GetRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	// Verify result
	var response flowv1.GetRackInfoResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.NotNil(response.Rack)
	s.NotNil(response.Rack.Info)
	s.Equal(rackID, response.Rack.Info.Id.Id)
}

func (s *GetRackTestSuite) Test_GetRack_ActivityFails() {
	var rackManager rActivity.ManageRack

	rackID := "test-rack-id"
	request := &flowv1.GetRackInfoByIDRequest{
		Id: &flowv1.UUID{Id: rackID},
	}

	errMsg := "Flow connection failed"

	// Mock GetRack activity failure
	s.env.RegisterActivity(rackManager.GetRack)
	s.env.OnActivity(rackManager.GetRack, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute GetRack workflow
	s.env.ExecuteWorkflow(GetRack, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetRackTestSuite(t *testing.T) {
	suite.Run(t, new(GetRackTestSuite))
}

// GetRacksTestSuite tests the GetRacks workflow
type GetRacksTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetRacksTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetRacksTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetRacksTestSuite) Test_GetRacks_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.GetListOfRacksRequest{}

	expectedResponse := &flowv1.GetListOfRacksResponse{
		Racks: []*flowv1.Rack{
			{
				Info: &flowv1.DeviceInfo{
					Id:   &flowv1.UUID{Id: "rack-1"},
					Name: "Rack 1",
				},
			},
			{
				Info: &flowv1.DeviceInfo{
					Id:   &flowv1.UUID{Id: "rack-2"},
					Name: "Rack 2",
				},
			},
		},
		Total: 2,
	}

	// Mock GetRacks activity
	s.env.RegisterActivity(rackManager.GetRacks)
	s.env.OnActivity(rackManager.GetRacks, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute GetRacks workflow
	s.env.ExecuteWorkflow(GetRacks, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	// Verify result
	var response flowv1.GetListOfRacksResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.NotNil(response.Racks)
	s.Equal(int32(2), response.Total)
	s.Equal(2, len(response.Racks))
}

func (s *GetRacksTestSuite) Test_GetRacks_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.GetListOfRacksRequest{}

	errMsg := "Flow connection failed"

	// Mock GetRacks activity failure
	s.env.RegisterActivity(rackManager.GetRacks)
	s.env.OnActivity(rackManager.GetRacks, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute GetRacks workflow
	s.env.ExecuteWorkflow(GetRacks, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetRacksTestSuite(t *testing.T) {
	suite.Run(t, new(GetRacksTestSuite))
}

// ValidateRackComponentsTestSuite tests the ValidateRackComponents workflow
type ValidateRackComponentsTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *ValidateRackComponentsTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *ValidateRackComponentsTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *ValidateRackComponentsTestSuite) Test_ValidateRackComponents_Success_NoDiffs() {
	var rackManager rActivity.ManageRack

	request := &flowv1.ValidateComponentsRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	expectedResponse := &flowv1.ValidateComponentsResponse{
		Diffs:           []*flowv1.ComponentDiff{},
		TotalDiffs:      0,
		MissingCount:    0,
		UnexpectedCount: 0,
		MismatchCount:   0,
		MatchCount:      5,
	}

	// Mock ValidateRackComponents activity
	s.env.RegisterActivity(rackManager.ValidateRackComponents)
	s.env.OnActivity(rackManager.ValidateRackComponents, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute ValidateRackComponents workflow
	s.env.ExecuteWorkflow(ValidateRackComponents, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	// Verify result
	var response flowv1.ValidateComponentsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(int32(0), response.TotalDiffs)
	s.Equal(int32(5), response.MatchCount)
	s.Equal(0, len(response.Diffs))
}

func (s *ValidateRackComponentsTestSuite) Test_ValidateRackComponents_Success_WithDiffs() {
	var rackManager rActivity.ManageRack

	request := &flowv1.ValidateComponentsRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	expectedResponse := &flowv1.ValidateComponentsResponse{
		Diffs: []*flowv1.ComponentDiff{
			{
				Type:        flowv1.DiffType_DIFF_TYPE_MISSING,
				ComponentId: "comp-1",
			},
			{
				Type:        flowv1.DiffType_DIFF_TYPE_MISMATCH,
				ComponentId: "comp-2",
				FieldDiffs: []*flowv1.FieldDiff{
					{
						FieldName:     "firmware_version",
						ExpectedValue: "1.0.0",
						ActualValue:   "2.0.0",
					},
				},
			},
		},
		TotalDiffs:      2,
		MissingCount:    1,
		UnexpectedCount: 0,
		MismatchCount:   1,
		MatchCount:      3,
	}

	// Mock ValidateRackComponents activity
	s.env.RegisterActivity(rackManager.ValidateRackComponents)
	s.env.OnActivity(rackManager.ValidateRackComponents, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute ValidateRackComponents workflow
	s.env.ExecuteWorkflow(ValidateRackComponents, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	// Verify result
	var response flowv1.ValidateComponentsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(int32(2), response.TotalDiffs)
	s.Equal(int32(1), response.MissingCount)
	s.Equal(int32(1), response.MismatchCount)
	s.Equal(int32(3), response.MatchCount)
	s.Equal(2, len(response.Diffs))
}

func (s *ValidateRackComponentsTestSuite) Test_ValidateRackComponents_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.ValidateComponentsRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	// Mock ValidateRackComponents activity failure
	s.env.RegisterActivity(rackManager.ValidateRackComponents)
	s.env.OnActivity(rackManager.ValidateRackComponents, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute ValidateRackComponents workflow
	s.env.ExecuteWorkflow(ValidateRackComponents, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestValidateRackComponentsTestSuite(t *testing.T) {
	suite.Run(t, new(ValidateRackComponentsTestSuite))
}

// PowerOnRackTestSuite tests the PowerOnRack workflow
type PowerOnRackTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *PowerOnRackTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *PowerOnRackTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *PowerOnRackTestSuite) Test_PowerOnRack_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerOnRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Description: "API power on Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.PowerOnRack)
	s.env.OnActivity(rackManager.PowerOnRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(PowerOnRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *PowerOnRackTestSuite) Test_PowerOnRack_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerOnRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(rackManager.PowerOnRack)
	s.env.OnActivity(rackManager.PowerOnRack, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PowerOnRack, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestPowerOnRackTestSuite(t *testing.T) {
	suite.Run(t, new(PowerOnRackTestSuite))
}

// PowerOffRackTestSuite tests the PowerOffRack workflow
type PowerOffRackTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *PowerOffRackTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *PowerOffRackTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *PowerOffRackTestSuite) Test_PowerOffRack_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerOffRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Description: "API power off Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.PowerOffRack)
	s.env.OnActivity(rackManager.PowerOffRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(PowerOffRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *PowerOffRackTestSuite) Test_PowerOffRack_Forced() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerOffRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Forced:      true,
		Description: "API force power off Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.PowerOffRack)
	s.env.OnActivity(rackManager.PowerOffRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(PowerOffRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *PowerOffRackTestSuite) Test_PowerOffRack_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerOffRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(rackManager.PowerOffRack)
	s.env.OnActivity(rackManager.PowerOffRack, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PowerOffRack, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestPowerOffRackTestSuite(t *testing.T) {
	suite.Run(t, new(PowerOffRackTestSuite))
}

// PowerResetRackTestSuite tests the PowerResetRack workflow
type PowerResetRackTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *PowerResetRackTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *PowerResetRackTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *PowerResetRackTestSuite) Test_PowerResetRack_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerResetRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Description: "API power cycle Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.PowerResetRack)
	s.env.OnActivity(rackManager.PowerResetRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(PowerResetRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *PowerResetRackTestSuite) Test_PowerResetRack_Forced() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerResetRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Forced:      true,
		Description: "API force power cycle Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}, {Id: "task-2"}},
	}

	s.env.RegisterActivity(rackManager.PowerResetRack)
	s.env.OnActivity(rackManager.PowerResetRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(PowerResetRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(2, len(response.GetTaskIds()))
}

func (s *PowerResetRackTestSuite) Test_PowerResetRack_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.PowerResetRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(rackManager.PowerResetRack)
	s.env.OnActivity(rackManager.PowerResetRack, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(PowerResetRack, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestPowerResetRackTestSuite(t *testing.T) {
	suite.Run(t, new(PowerResetRackTestSuite))
}

// BringUpRackTestSuite tests the BringUpRack workflow
type BringUpRackTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *BringUpRackTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *BringUpRackTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *BringUpRackTestSuite) Test_BringUpRack_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.BringUpRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Description: "API bring up Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.BringUpRack)
	s.env.OnActivity(rackManager.BringUpRack, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(BringUpRack, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *BringUpRackTestSuite) Test_BringUpRack_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.BringUpRackRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(rackManager.BringUpRack)
	s.env.OnActivity(rackManager.BringUpRack, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(BringUpRack, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestBringUpRackTestSuite(t *testing.T) {
	suite.Run(t, new(BringUpRackTestSuite))
}

// UpgradeFirmwareTestSuite tests the UpgradeFirmware workflow
type UpgradeFirmwareTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpgradeFirmwareTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpgradeFirmwareTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpgradeFirmwareTestSuite) Test_UpgradeFirmware_Success() {
	var rackManager rActivity.ManageRack

	request := &flowv1.UpgradeFirmwareRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		Description: "API firmware upgrade Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.UpgradeFirmware)
	s.env.OnActivity(rackManager.UpgradeFirmware, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(UpgradeFirmware, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *UpgradeFirmwareTestSuite) Test_UpgradeFirmware_WithVersion() {
	var rackManager rActivity.ManageRack

	version := "24.11.0"
	request := &flowv1.UpgradeFirmwareRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
		TargetVersion: &version,
		Description:   "API firmware upgrade Rack",
	}

	expectedResponse := &flowv1.SubmitTaskResponse{
		TaskIds: []*flowv1.UUID{{Id: "task-1"}},
	}

	s.env.RegisterActivity(rackManager.UpgradeFirmware)
	s.env.OnActivity(rackManager.UpgradeFirmware, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(UpgradeFirmware, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.SubmitTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTaskIds()))
}

func (s *UpgradeFirmwareTestSuite) Test_UpgradeFirmware_ActivityFails() {
	var rackManager rActivity.ManageRack

	request := &flowv1.UpgradeFirmwareRequest{
		TargetSpec: &flowv1.OperationTargetSpec{
			Targets: &flowv1.OperationTargetSpec_Racks{
				Racks: &flowv1.RackTargets{
					Targets: []*flowv1.RackTarget{
						{
							Identifier: &flowv1.RackTarget_Id{
								Id: &flowv1.UUID{Id: "test-rack-id"},
							},
						},
					},
				},
			},
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(rackManager.UpgradeFirmware)
	s.env.OnActivity(rackManager.UpgradeFirmware, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(UpgradeFirmware, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestUpgradeFirmwareTestSuite(t *testing.T) {
	suite.Run(t, new(UpgradeFirmwareTestSuite))
}
