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

type UpdateSiteIPBlockInventoryWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite
	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateSiteIPBlockInventoryWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateSiteIPBlockInventoryWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateSiteIPBlockInventoryWorkflowTestSuite) Test_UpdateSiteIPBlockInventoryWorkflow_Success() {
	var siteManager siteActivity.ManageSite

	siteID := uuid.New()
	prefixes := []string{"10.0.0.0/16", "2001:db8::/64"}

	s.env.RegisterActivity(siteManager.UpdateSiteIPBlocksInDB)
	s.env.OnActivity(siteManager.UpdateSiteIPBlocksInDB, mock.Anything, siteID, prefixes).Return(nil)

	s.env.ExecuteWorkflow(UpdateSiteIPBlockInventory, siteID.String(), prefixes)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateSiteIPBlockInventoryWorkflowTestSuite) Test_UpdateSiteIPBlockInventoryWorkflow_ActivityFails() {
	var siteManager siteActivity.ManageSite

	siteID := uuid.New()
	prefixes := []string{"10.0.0.0/16"}

	s.env.RegisterActivity(siteManager.UpdateSiteIPBlocksInDB)
	s.env.OnActivity(siteManager.UpdateSiteIPBlocksInDB, mock.Anything, siteID, prefixes).Return(errors.New("failed to update Site IP Blocks"))

	s.env.ExecuteWorkflow(UpdateSiteIPBlockInventory, siteID.String(), prefixes)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("failed to update Site IP Blocks", applicationErr.Error())
}

func (s *UpdateSiteIPBlockInventoryWorkflowTestSuite) Test_UpdateSiteIPBlockInventoryWorkflow_InvalidSiteID() {
	s.env.ExecuteWorkflow(UpdateSiteIPBlockInventory, "not-a-site-id", []string{"10.0.0.0/16"})
	s.True(s.env.IsWorkflowCompleted())
	s.Error(s.env.GetWorkflowError())
}

func TestUpdateSiteIPBlockInventoryWorkflowTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateSiteIPBlockInventoryWorkflowTestSuite))
}
