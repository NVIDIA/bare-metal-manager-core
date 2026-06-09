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
	"google.golang.org/protobuf/types/known/emptypb"

	rActivity "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow/protobuf/v1"
)

// CreateOperationRuleTestSuite tests the CreateOperationRule workflow
type CreateOperationRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *CreateOperationRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *CreateOperationRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *CreateOperationRuleTestSuite) Test_CreateOperationRule_Success() {
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

	s.env.ExecuteWorkflow(CreateOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.CreateOperationRuleResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal("rule-id", response.GetId().GetId())
}

func (s *CreateOperationRuleTestSuite) Test_CreateOperationRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.CreateOperationRuleRequest{Name: "rule-1"}
	errMsg := "flow rejected duplicate rule"

	s.env.RegisterActivity(ruleManager.CreateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.CreateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(CreateOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestCreateOperationRuleTestSuite(t *testing.T) {
	suite.Run(t, new(CreateOperationRuleTestSuite))
}

// GetOperationRuleTestSuite tests the GetOperationRule workflow
type GetOperationRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetOperationRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetOperationRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetOperationRuleTestSuite) Test_GetOperationRule_Success() {
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

	s.env.ExecuteWorkflow(GetOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.OperationRule
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(ruleID, response.GetId().GetId())
	s.Equal("rule-1", response.GetName())
}

func (s *GetOperationRuleTestSuite) Test_GetOperationRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.GetOperationRuleRequest{RuleId: &flowv1.UUID{Id: "rule-id"}}
	errMsg := "rule not found"

	s.env.RegisterActivity(ruleManager.GetTaskRuleFromFlow)
	s.env.OnActivity(ruleManager.GetTaskRuleFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(GetOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetOperationRuleTestSuite(t *testing.T) {
	suite.Run(t, new(GetOperationRuleTestSuite))
}

// ListOperationRulesTestSuite tests the ListOperationRules workflow
type ListOperationRulesTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *ListOperationRulesTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *ListOperationRulesTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *ListOperationRulesTestSuite) Test_ListOperationRules_Success() {
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

	s.env.ExecuteWorkflow(ListOperationRules, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var response flowv1.ListOperationRulesResponse
	s.NoError(s.env.GetWorkflowResult(&response))
	s.Equal(1, len(response.GetRules()))
	s.Equal(int32(1), response.GetTotalCount())
}

func (s *ListOperationRulesTestSuite) Test_ListOperationRules_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.ListOperationRulesRequest{}
	errMsg := "flow connection failed"

	s.env.RegisterActivity(ruleManager.GetAllTaskRulesFromFlow)
	s.env.OnActivity(ruleManager.GetAllTaskRulesFromFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(ListOperationRules, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestListOperationRulesTestSuite(t *testing.T) {
	suite.Run(t, new(ListOperationRulesTestSuite))
}

// UpdateOperationRuleTestSuite tests the UpdateOperationRule workflow
type UpdateOperationRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateOperationRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateOperationRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateOperationRuleTestSuite) Test_UpdateOperationRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.UpdateOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}

	s.env.RegisterActivity(ruleManager.UpdateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.UpdateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	s.env.ExecuteWorkflow(UpdateOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateOperationRuleTestSuite) Test_UpdateOperationRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.UpdateOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}
	errMsg := "rule not found"

	s.env.RegisterActivity(ruleManager.UpdateTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.UpdateTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(UpdateOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestUpdateOperationRuleTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateOperationRuleTestSuite))
}

// DeleteOperationRuleTestSuite tests the DeleteOperationRule workflow
type DeleteOperationRuleTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *DeleteOperationRuleTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *DeleteOperationRuleTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *DeleteOperationRuleTestSuite) Test_DeleteOperationRule_Success() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.DeleteOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}

	s.env.RegisterActivity(ruleManager.DeleteTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.DeleteTaskRuleOnFlow, mock.Anything, mock.Anything).Return(&emptypb.Empty{}, nil)

	s.env.ExecuteWorkflow(DeleteOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *DeleteOperationRuleTestSuite) Test_DeleteOperationRule_ActivityFails() {
	var ruleManager rActivity.ManageTaskRule

	request := &flowv1.DeleteOperationRuleRequest{
		RuleId: &flowv1.UUID{Id: "rule-id"},
	}
	errMsg := "rule still associated with racks"

	s.env.RegisterActivity(ruleManager.DeleteTaskRuleOnFlow)
	s.env.OnActivity(ruleManager.DeleteTaskRuleOnFlow, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	s.env.ExecuteWorkflow(DeleteOperationRule, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestDeleteOperationRuleTestSuite(t *testing.T) {
	suite.Run(t, new(DeleteOperationRuleTestSuite))
}
