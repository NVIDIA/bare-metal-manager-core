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

package ipxetemplate

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	cwm "github.com/NVIDIA/infra-controller/rest-api/workflow/internal/metrics"
	ipxeTemplateActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/ipxetemplate"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

type UpdateIpxeTemplateTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateIpxeTemplateTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateIpxeTemplateTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateIpxeTemplateTestSuite) Test_UpdateIpxeTemplateInventory_Success() {
	var templateManager ipxeTemplateActivity.ManageIpxeTemplate
	var metricsManager cwm.ManageInventoryMetrics

	siteID := uuid.New()
	inv := &cwssaws.IpxeTemplateInventory{Templates: []*cwssaws.IpxeTemplate{}}

	s.env.RegisterActivity(templateManager.UpdateIpxeTemplatesInDB)
	s.env.OnActivity(templateManager.UpdateIpxeTemplatesInDB, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	s.env.RegisterActivity(metricsManager.RecordLatency)
	s.env.OnActivity(metricsManager.RecordLatency, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	s.env.ExecuteWorkflow(UpdateIpxeTemplateInventory, siteID.String(), inv)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateIpxeTemplateTestSuite) Test_UpdateIpxeTemplateInventory_ActivityFails() {
	var templateManager ipxeTemplateActivity.ManageIpxeTemplate
	var metricsManager cwm.ManageInventoryMetrics

	siteID := uuid.New()
	inv := &cwssaws.IpxeTemplateInventory{Templates: []*cwssaws.IpxeTemplate{}}

	s.env.RegisterActivity(templateManager.UpdateIpxeTemplatesInDB)
	s.env.OnActivity(templateManager.UpdateIpxeTemplatesInDB, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("UpdateIpxeTemplatesInDB failure"))

	s.env.RegisterActivity(metricsManager.RecordLatency)
	s.env.OnActivity(metricsManager.RecordLatency, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	s.env.ExecuteWorkflow(UpdateIpxeTemplateInventory, siteID.String(), inv)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.NotNil(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("UpdateIpxeTemplatesInDB failure", applicationErr.Error())
}

func (s *UpdateIpxeTemplateTestSuite) Test_UpdateIpxeTemplateInventory_InvalidSiteID() {
	inv := &cwssaws.IpxeTemplateInventory{Templates: []*cwssaws.IpxeTemplate{}}

	s.env.ExecuteWorkflow(UpdateIpxeTemplateInventory, "not-a-valid-uuid", inv)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.NotNil(err)
}

func TestUpdateIpxeTemplateTestSuite(t *testing.T) {
	suite.Run(t, new(UpdateIpxeTemplateTestSuite))
}
