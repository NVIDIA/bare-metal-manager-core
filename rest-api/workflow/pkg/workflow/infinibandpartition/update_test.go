// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package infinibandpartition

import (
	"errors"
	"testing"

	ibpActivity "github.com/NVIDIA/infra-controller-rest/workflow/pkg/activity/infinibandpartition"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

type UpdateInfiniBandPartitionTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateInfiniBandPartitionTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateInfiniBandPartitionTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateInfiniBandPartitionTestSuite) Test_UpdateInfiniBandPartitionInventory_Success() {

	var ibpManager ibpActivity.ManageInfiniBandPartition

	siteID := uuid.New()
	ibpInventory := &cwssaws.InfiniBandPartitionInventory{
		IbPartitions: []*cwssaws.IBPartition{
			{
				Id: &cwssaws.IBPartitionId{Value: uuid.NewString()},
			},
			{
				Id: &cwssaws.IBPartitionId{Value: uuid.NewString()},
			},
		},
	}

	// Mock UpdateInfiniBandPartitionViaSiteAgent activity
	s.env.RegisterActivity(ibpManager.UpdateInfiniBandPartitionsInDB)
	s.env.OnActivity(ibpManager.UpdateInfiniBandPartitionsInDB, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateInfiniBandPartitionInventory workflow
	s.env.ExecuteWorkflow(UpdateInfiniBandPartitionInventory, siteID.String(), ibpInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateInfiniBandPartitionTestSuite) Test_UpdateInfiniBandPartitionInventory_ActivityFails() {

	var ibpManager ibpActivity.ManageInfiniBandPartition

	siteID := uuid.New()
	InfiniBandPartitionInventory := &cwssaws.InfiniBandPartitionInventory{
		IbPartitions: []*cwssaws.IBPartition{
			{
				Id: &cwssaws.IBPartitionId{Value: uuid.NewString()},
			},
			{
				Id: &cwssaws.IBPartitionId{Value: uuid.NewString()},
			},
		},
	}

	// Mock UpdateInfiniBandPartitionsViaSiteAgent activity failure
	s.env.RegisterActivity(ibpManager.UpdateInfiniBandPartitionsInDB)
	s.env.OnActivity(ibpManager.UpdateInfiniBandPartitionsInDB, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("UpdateInfiniBandPartitionInventory Failure"))

	// execute UpdateInfiniBandPartitionStatus workflow
	s.env.ExecuteWorkflow(UpdateInfiniBandPartitionInventory, siteID.String(), InfiniBandPartitionInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("UpdateInfiniBandPartitionInventory Failure", applicationErr.Error())
}

func TestUpdateInfiniBandPartitionSuite(t *testing.T) {
	suite.Run(t, new(UpdateInfiniBandPartitionTestSuite))
}
