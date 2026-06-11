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

	rActivity "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// CreateTaskRuleTestSuite tests the CreateTaskRule workflow
type CreateTaskRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *CreateTaskRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *CreateTaskRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *CreateTaskRuleTestSuite) Test_CreateTaskRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.CreateOperationRuleRequest{
		Name:               "rule-1",
		OperationType:      flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
		OperationCode:      "power_on",
		RuleDefinitionJson: `{"stages":[]}`,
	}
	expected := &flowv1.CreateOperationRuleResponse{
		Id: &flowv1.UUID{Id: "rule-id"},
	}

	s.env.RegisterActivity(ruleManager.CreateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.CreateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(CreateTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CreateOperationRuleResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("rule-id", response.GetId().GetId())
}

func (s *CreateTaskRuleTestSuite) Test_CreateTaskRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.CreateOperationRuleRequest{Name: "rule-1"}
	errMsg := "flow rejected duplicate rule"

	s.env.RegisterActivity(ruleManager.CreateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.CreateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CreateTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestCreateTaskRuleTestSuite(t *testing.T) {
	suite.Run(t, new(CreateTaskRuleTestSuite))
}

// GetTaskRuleTestSuite tests the GetTaskRule workflow
type GetTaskRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetTaskRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetTaskRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetTaskRuleTestSuite) Test_GetTaskRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	ruleID := "rule-id"
	request := &flowv1.GetOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: ruleID},
	}
	expected := &flowv1.OperationRule{
		Id:            &flowv1.UUID{Id: ruleID},
		Name:          "rule-1",
		OperationType: flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL,
		OperationCode: "power_on",
	}

	s.env.RegisterActivity(ruleManager.GetTaskRuleFromFlow)
	s.env.OnActivity(ruleManager.GetTaskRuleFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRule
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(ruleID, response.GetId().GetId())
	s.Equal("rule-1", response.GetName())
}

func (s *GetTaskRuleTestSuite) Test_GetTaskRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.GetOperationRuleRequest{RuleId: &flowv1.UUID{Id: "rule-id"}}
	errMsg := "rule not found"

	s.env.RegisterActivity(ruleManager.GetTaskRuleFromFlow)
	s.env.OnActivity(ruleManager.GetTaskRuleFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetTaskRuleTestSuite(t *testing.T) {
	suite.Run(t, new(GetTaskRuleTestSuite))
}

// GetAllTaskRulesTestSuite tests the GetAllTaskRules workflow
type GetAllTaskRulesTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetAllTaskRulesTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetAllTaskRulesTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetAllTaskRulesTestSuite) Test_GetAllTaskRules_Success() {
	var ruleManager rActivity.ManageTaskRule

	opType := flowv1.OperationType_OPERATION_TYPE_POWER_CONTROL
	request := &flowv1.ListOperationRulesRequest{
		OperationType: &opType,
	}
	expected := &flowv1.ListOperationRulesResponse{
		Rules: []*flowv1.OperationRule{
			{Id: &flowv1.UUID{Id: "rule-id"}, Name: "rule-1"},
		},
		TotalCount: 1,
	}

	s.env.RegisterActivity(ruleManager.GetAllTaskRulesFromFlow)
	s.env.OnActivity(ruleManager.GetAllTaskRulesFromFlow, mock.Anything, mock.Anything).Return(expected, nil)

	s.env.ExecuteWorkflow(GetAllTaskRules, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRulesResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetRules()))
	s.Equal(int32(1), response.GetTotalCount())
}

func (s *GetAllTaskRulesTestSuite) Test_GetAllTaskRules_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.ListOperationRulesRequest{}
	errMsg := "flow connection failed"

	s.env.RegisterActivity(ruleManager.GetAllTaskRulesFromFlow)
	s.env.OnActivity(ruleManager.GetAllTaskRulesFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetAllTaskRules, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetAllTaskRulesTestSuite(t *testing.T) {
	suite.Run(t, new(GetAllTaskRulesTestSuite))
}

// UpdateTaskRuleTestSuite tests the UpdateTaskRule workflow
type UpdateTaskRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateTaskRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateTaskRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateTaskRuleTestSuite) Test_UpdateTaskRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.UpdateOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}

	s.env.RegisterActivity(ruleManager.UpdateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.UpdateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil)

	s.env.ExecuteWorkflow(UpdateTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateTaskRuleTestSuite) Test_UpdateTaskRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.UpdateOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}
	errMsg := "rule not found"

	s.env.RegisterActivity(ruleManager.UpdateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.UpdateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(errors.New(errMsg))

	s.env.ExecuteWorkflow(UpdateTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestUpdateTaskRuleTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateTaskRuleTestSuite))
}

// DeleteTaskRuleTestSuite tests the DeleteTaskRule workflow
type DeleteTaskRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *DeleteTaskRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *DeleteTaskRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *DeleteTaskRuleTestSuite) Test_DeleteTaskRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.DeleteOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}

	s.env.RegisterActivity(ruleManager.DeleteTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.DeleteTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil)

	s.env.ExecuteWorkflow(DeleteTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *DeleteTaskRuleTestSuite) Test_DeleteTaskRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.DeleteOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}
	errMsg := "rule still associated with racks"

	s.env.RegisterActivity(ruleManager.DeleteTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.DeleteTaskRuleOnFlow, mock.Anything, mock.Anything).Return(errors.New(errMsg))

	s.env.ExecuteWorkflow(DeleteTaskRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestDeleteTaskRuleTestSuite(t *testing.T) {
	suite.Run(t, new(DeleteTaskRuleTestSuite))
}
