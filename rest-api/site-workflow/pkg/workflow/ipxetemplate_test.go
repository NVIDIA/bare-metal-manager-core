/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

type InventoryIpxeTemplateTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *InventoryIpxeTemplateTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *InventoryIpxeTemplateTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *InventoryIpxeTemplateTestSuite) Test_DiscoverIpxeTemplateInventory_Success() {
	var inventoryManager iActivity.ManageIpxeTemplateInventory

	s.env.RegisterActivity(inventoryManager.DiscoverIpxeTemplateInventory)
	s.env.OnActivity(inventoryManager.DiscoverIpxeTemplateInventory, mock.Anything).Return(nil)

	s.env.ExecuteWorkflow(DiscoverIpxeTemplateInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *InventoryIpxeTemplateTestSuite) Test_DiscoverIpxeTemplateInventory_ActivityFails() {
	var inventoryManager iActivity.ManageIpxeTemplateInventory

	errMsg := "Site Controller communication error"

	s.env.RegisterActivity(inventoryManager.DiscoverIpxeTemplateInventory)
	s.env.OnActivity(inventoryManager.DiscoverIpxeTemplateInventory, mock.Anything).Return(errors.New(errMsg))

	s.env.ExecuteWorkflow(DiscoverIpxeTemplateInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestInventoryIpxeTemplateTestSuite(t *testing.T) {
	suite.Run(t, new(InventoryIpxeTemplateTestSuite))
}
