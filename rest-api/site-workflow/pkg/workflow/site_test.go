// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"testing"

	iActivity "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
)

type InventorySiteIPBlockTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (isibts *InventorySiteIPBlockTestSuite) SetupTest() {
	isibts.env = isibts.NewTestWorkflowEnvironment()
}

func (isibts *InventorySiteIPBlockTestSuite) AfterTest(suiteName, testName string) {
	isibts.env.AssertExpectations(isibts.T())
}

func (isibts *InventorySiteIPBlockTestSuite) Test_DiscoverSiteIPBlockInventory_Success() {
	var inventoryManager iActivity.ManageSiteIPBlockInventory

	isibts.env.RegisterActivity(inventoryManager.DiscoverSiteIPBlockInventory)
	isibts.env.OnActivity(inventoryManager.DiscoverSiteIPBlockInventory, mock.Anything).Return(nil)

	isibts.env.ExecuteWorkflow(DiscoverSiteIPBlockInventory)
	isibts.True(isibts.env.IsWorkflowCompleted())
	isibts.NoError(isibts.env.GetWorkflowError())
}

func (isibts *InventorySiteIPBlockTestSuite) Test_DiscoverSiteIPBlockInventory_ActivityFails() {
	var inventoryManager iActivity.ManageSiteIPBlockInventory

	errMsg := "Site Controller communication error"

	isibts.env.RegisterActivity(inventoryManager.DiscoverSiteIPBlockInventory)
	isibts.env.OnActivity(inventoryManager.DiscoverSiteIPBlockInventory, mock.Anything).Return(errors.New(errMsg))

	isibts.env.ExecuteWorkflow(DiscoverSiteIPBlockInventory)
	isibts.True(isibts.env.IsWorkflowCompleted())
	err := isibts.env.GetWorkflowError()
	isibts.Error(err)

	var applicationErr *temporal.ApplicationError
	isibts.True(errors.As(err, &applicationErr))
	isibts.Equal(errMsg, applicationErr.Error())
}

func TestInventorySiteIPBlockTestSuite(t *testing.T) {
	suite.Run(t, new(InventorySiteIPBlockTestSuite))
}
