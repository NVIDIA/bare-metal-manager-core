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

// GetTaskTestSuite tests the GetTask workflow
type GetTaskTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetTaskTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetTaskTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetTaskTestSuite) Test_GetTask_Success() {
	var taskManager rActivity.ManageTask

	taskID := "test-task-id"
	request := &flowv1.GetTasksByIDsRequest{
		TaskIds: []*flowv1.UUID{{Id: taskID}},
	}

	expectedResponse := &flowv1.GetTasksByIDsResponse{
		Tasks: []*flowv1.Task{
			{
				Id:          &flowv1.UUID{Id: taskID},
				Operation:   "power_on",
				Description: "Power on rack",
				Status:      flowv1.TaskStatus_TASK_STATUS_RUNNING,
				Message:     "Processing",
			},
		},
	}

	s.env.RegisterActivity(taskManager.GetTaskFromFlow)
	s.env.OnActivity(taskManager.GetTaskFromFlow, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(GetTask, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.GetTasksByIDsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTasks()))
	s.Equal(taskID, response.GetTasks()[0].GetId().GetId())
}

func (s *GetTaskTestSuite) Test_GetTask_EmptyResult() {
	var taskManager rActivity.ManageTask

	request := &flowv1.GetTasksByIDsRequest{
		TaskIds: []*flowv1.UUID{{Id: "nonexistent-task"}},
	}

	expectedResponse := &flowv1.GetTasksByIDsResponse{
		Tasks: []*flowv1.Task{},
	}

	s.env.RegisterActivity(taskManager.GetTaskFromFlow)
	s.env.OnActivity(taskManager.GetTaskFromFlow, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(GetTask, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.GetTasksByIDsResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(0, len(response.GetTasks()))
}

func (s *GetTaskTestSuite) Test_GetTask_ActivityFails() {
	var taskManager rActivity.ManageTask

	request := &flowv1.GetTasksByIDsRequest{
		TaskIds: []*flowv1.UUID{{Id: "test-task-id"}},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(taskManager.GetTaskFromFlow)
	s.env.OnActivity(taskManager.GetTaskFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetTask, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetTaskTestSuite(t *testing.T) {
	suite.Run(t, new(GetTaskTestSuite))
}

// CancelTaskTestSuite tests the CancelTask workflow
type CancelTaskTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *CancelTaskTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *CancelTaskTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *CancelTaskTestSuite) Test_CancelTask_Success() {
	var taskManager rActivity.ManageTask

	taskID := "test-task-id"
	request := &flowv1.CancelTaskRequest{
		TaskId: &flowv1.UUID{Id: taskID},
	}

	expectedResponse := &flowv1.CancelTaskResponse{
		Task: &flowv1.Task{
			Id:      &flowv1.UUID{Id: taskID},
			Status:  flowv1.TaskStatus_TASK_STATUS_TERMINATED,
			Message: "Cancelled by user",
		},
	}

	s.env.RegisterActivity(taskManager.CancelTaskOnFlow)
	s.env.OnActivity(taskManager.CancelTaskOnFlow, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(CancelTask, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CancelTaskResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(taskID, response.GetTask().GetId().GetId())
	s.Equal(flowv1.TaskStatus_TASK_STATUS_TERMINATED, response.GetTask().GetStatus())
}

func (s *CancelTaskTestSuite) Test_CancelTask_ActivityFails() {
	var taskManager rActivity.ManageTask

	request := &flowv1.CancelTaskRequest{
		TaskId: &flowv1.UUID{Id: "test-task-id"},
	}

	errMsg := "Flow cancel rejected: task already finished"

	s.env.RegisterActivity(taskManager.CancelTaskOnFlow)
	s.env.OnActivity(taskManager.CancelTaskOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CancelTask, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestCancelTaskTestSuite(t *testing.T) {
	suite.Run(t, new(CancelTaskTestSuite))
}

// GetTasksTestSuite tests the GetTasks workflow
type GetTasksTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetTasksTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetTasksTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetTasksTestSuite) Test_GetTasks_Success() {
	var taskManager rActivity.ManageTask

	request := &flowv1.ListTasksRequest{
		RackId:     &flowv1.UUID{Id: "test-rack-id"},
		ActiveOnly: true,
		Pagination: &flowv1.Pagination{
			Offset: 1,
			Limit:  10,
		},
	}

	expectedResponse := &flowv1.ListTasksResponse{
		Tasks: []*flowv1.Task{
			{
				Id: &flowv1.UUID{Id: "test-task-id"},
			},
		},
	}

	s.env.RegisterActivity(taskManager.GetTasksFromFlow)
	s.env.OnActivity(taskManager.GetTasksFromFlow, mock.Anything, mock.Anything).Return(expectedResponse, nil)

	s.env.ExecuteWorkflow(GetTasks, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListTasksResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetTasks()))
	s.Equal("test-task-id", response.GetTasks()[0].GetId().GetId())
}

func (s *GetTasksTestSuite) Test_GetTasks_ActivityFails() {
	var taskManager rActivity.ManageTask

	request := &flowv1.ListTasksRequest{
		RackId:     &flowv1.UUID{Id: "test-rack-id"},
		ActiveOnly: true,
		Pagination: &flowv1.Pagination{
			Offset: 1,
			Limit:  10,
		},
	}

	errMsg := "Flow connection failed"

	s.env.RegisterActivity(taskManager.GetTasksFromFlow)
	s.env.OnActivity(taskManager.GetTasksFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetTasks, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetTasksTestSuite(t *testing.T) {
	suite.Run(t, new(GetTasksTestSuite))
}
