// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	tActivity "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller-rest/workflow-schema/flow/protobuf/v1"
)

// ~~~~~ GetTray Workflow Tests ~~~~~ //

type GetTrayWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetTrayWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetTrayWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetTrayWorkflowTestSuite) Test_GetTray_Success() {
	var trayManager tActivity.ManageTray

	trayID := uuid.New().String()
	request := &flowv1.GetComponentInfoByIDRequest{
		Id: &flowv1.UUID{Id: trayID},
	}

	expectedResponse := &flowv1.GetComponentInfoResponse{
		Component: &flowv1.Component{
			Info: &flowv1.DeviceInfo{
				Id:   &flowv1.UUID{Id: trayID},
				Name: "tray-0",
			},
			Type: flowv1.ComponentType_COMPONENT_TYPE_COMPUTE,
		},
	}

	// Mock GetTray activity
	s.env.RegisterActivity(trayManager.GetTray)
	s.env.OnActivity(trayManager.GetTray, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute GetTray workflow
	s.env.ExecuteWorkflow(GetTray, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var result flowv1.GetComponentInfoResponse
	s.env.GetWorkflowResult(&result)
	s.Equal(trayID, result.GetComponent().GetInfo().GetId().GetId())
	s.Equal("tray-0", result.GetComponent().GetInfo().GetName())
}

func (s *GetTrayWorkflowTestSuite) Test_GetTray_ActivityFails() {
	var trayManager tActivity.ManageTray

	trayID := uuid.New().String()
	request := &flowv1.GetComponentInfoByIDRequest{
		Id: &flowv1.UUID{Id: trayID},
	}

	errMsg := "Flow communication error"

	// Mock GetTray activity failure
	s.env.RegisterActivity(trayManager.GetTray)
	s.env.OnActivity(trayManager.GetTray, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute GetTray workflow
	s.env.ExecuteWorkflow(GetTray, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *GetTrayWorkflowTestSuite) Test_GetTray_NilRequest() {
	var trayManager tActivity.ManageTray

	expectedResponse := &flowv1.GetComponentInfoResponse{}

	// Mock GetTray activity with nil request
	s.env.RegisterActivity(trayManager.GetTray)
	s.env.OnActivity(trayManager.GetTray, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute GetTray workflow with nil request
	s.env.ExecuteWorkflow(GetTray, (*flowv1.GetComponentInfoByIDRequest)(nil))
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func TestGetTrayWorkflowSuite(t *testing.T) {
	suite.Run(t, new(GetTrayWorkflowTestSuite))
}

// ~~~~~ GetTrays Workflow Tests ~~~~~ //

type GetTraysWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetTraysWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetTraysWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetTraysWorkflowTestSuite) Test_GetTrays_Success() {
	var trayManager tActivity.ManageTray

	request := &flowv1.GetComponentsRequest{}

	expectedResponse := &flowv1.GetComponentsResponse{
		Components: []*flowv1.Component{
			{Info: &flowv1.DeviceInfo{Id: &flowv1.UUID{Id: uuid.New().String()}, Name: "tray-0"}},
			{Info: &flowv1.DeviceInfo{Id: &flowv1.UUID{Id: uuid.New().String()}, Name: "tray-1"}},
		},
		Total: 2,
	}

	// Mock GetTrays activity
	s.env.RegisterActivity(trayManager.GetTrays)
	s.env.OnActivity(trayManager.GetTrays, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	// Execute GetTrays workflow
	s.env.ExecuteWorkflow(GetTrays, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var result flowv1.GetComponentsResponse
	s.env.GetWorkflowResult(&result)
	s.Equal(int32(2), result.GetTotal())
	s.Equal(2, len(result.GetComponents()))
}

func (s *GetTraysWorkflowTestSuite) Test_GetTrays_ActivityFails() {
	var trayManager tActivity.ManageTray

	request := &flowv1.GetComponentsRequest{}

	errMsg := "Flow communication error"

	// Mock GetTrays activity failure
	s.env.RegisterActivity(trayManager.GetTrays)
	s.env.OnActivity(trayManager.GetTrays, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute GetTrays workflow
	s.env.ExecuteWorkflow(GetTrays, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetTraysWorkflowSuite(t *testing.T) {
	suite.Run(t, new(GetTraysWorkflowTestSuite))
}
