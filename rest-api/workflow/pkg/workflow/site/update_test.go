// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	siteActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/site"
)

type UpdateSiteConfigInventoryWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateSiteConfigInventoryWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateSiteConfigInventoryWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateSiteConfigInventoryWorkflowTestSuite) Test_UpdateSiteConfigInventoryWorkflow_Success() {
	var siteManager siteActivity.ManageSite

	siteID := uuid.New()
	prefixes := []string{"10.0.0.0/16", "2001:db8::/64"}

	s.env.RegisterActivity(siteManager.UpdateIPBlocksInDBFromFabricPrefixes)
	s.env.OnActivity(siteManager.UpdateIPBlocksInDBFromFabricPrefixes, mock.Anything, siteID, prefixes).Return(nil)

	s.env.ExecuteWorkflow(UpdateSiteConfigInventory, siteID.String(), prefixes)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateSiteConfigInventoryWorkflowTestSuite) Test_UpdateSiteConfigInventoryWorkflow_ActivityFails() {
	var siteManager siteActivity.ManageSite

	siteID := uuid.New()
	prefixes := []string{"10.0.0.0/16"}

	s.env.RegisterActivity(siteManager.UpdateIPBlocksInDBFromFabricPrefixes)
	s.env.OnActivity(siteManager.UpdateIPBlocksInDBFromFabricPrefixes, mock.Anything, siteID, prefixes).Return(errors.New("failed to update Site IP Blocks"))

	s.env.ExecuteWorkflow(UpdateSiteConfigInventory, siteID.String(), prefixes)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("failed to update Site IP Blocks", applicationErr.Error())
}

func (s *UpdateSiteConfigInventoryWorkflowTestSuite) Test_UpdateSiteConfigInventoryWorkflow_InvalidSiteID() {
	s.env.ExecuteWorkflow(UpdateSiteConfigInventory, "not-a-site-id", []string{"10.0.0.0/16"})
	s.True(s.env.IsWorkflowCompleted())
	s.Error(s.env.GetWorkflowError())
}

func TestUpdateSiteConfigInventoryWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateSiteConfigInventoryWorkflowTestSuite))
}
