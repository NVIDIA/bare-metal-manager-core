// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpcpeering

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	vpcPeeringActivity "github.com/NVIDIA/infra-controller-rest/workflow/pkg/activity/vpcpeering"
)

type UpdateVpcPeeringTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateVpcPeeringTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateVpcPeeringTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateVpcPeeringTestSuite) Test_UpdateVpcPeeringsInventory_Success() {
	var VpcPeeringManager vpcPeeringActivity.ManageVpcPeering

	siteID := uuid.New()
	VpcPeeringInventory := &cwssaws.VPCPeeringInventory{
		VpcPeerings: []*cwssaws.VpcPeering{
			{Id: &cwssaws.VpcPeeringId{Value: uuid.NewString()}},
			{Id: &cwssaws.VpcPeeringId{Value: uuid.NewString()}},
		},
	}

	// Mock UpdateVpcPeeringsInDB activity
	s.env.RegisterActivity(VpcPeeringManager.UpdateVpcPeeringsInDB)
	s.env.OnActivity(VpcPeeringManager.UpdateVpcPeeringsInDB, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateVpcPeeringsInventory workflow
	s.env.ExecuteWorkflow(UpdateVpcPeeringInventory, siteID.String(), VpcPeeringInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateVpcPeeringTestSuite) Test_UpdateVpcPeeringsInventory_ActivityFails() {
	var VpcPeeringManager vpcPeeringActivity.ManageVpcPeering

	siteID := uuid.New()
	VpcPeeringInventory := &cwssaws.VPCPeeringInventory{
		VpcPeerings: []*cwssaws.VpcPeering{
			{Id: &cwssaws.VpcPeeringId{Value: uuid.NewString()}},
			{Id: &cwssaws.VpcPeeringId{Value: uuid.NewString()}},
		},
	}

	// Mock UpdateVpcPeeringsInDB activity failure
	s.env.RegisterActivity(VpcPeeringManager.UpdateVpcPeeringsInDB)
	s.env.OnActivity(VpcPeeringManager.UpdateVpcPeeringsInDB, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("UpdateVpcPeeringsInventory Failure"))

	// execute UpdateVpcPeeringsInventory workflow
	s.env.ExecuteWorkflow(UpdateVpcPeeringInventory, siteID.String(), VpcPeeringInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("UpdateVpcPeeringsInventory Failure", applicationErr.Error())
}

func TestUpdateVpcPeeringSuite(t *testing.T) {
	suite.Run(t, new(UpdateVpcPeeringTestSuite))
}
