// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	ws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"

	osActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/operatingsystem"
)

type UpdateOsImageInventoryTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateOsImageInventoryTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateOsImageInventoryTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateOsImageInventoryTestSuite) Test_UpdateOsImageInventory_Success() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()
	osIDs := []uuid.UUID{uuid.New(), uuid.New()}

	osImageInventory := &ws.OsImageInventory{
		OsImages: []*ws.OsImage{
			{
				Attributes: &ws.OsImageAttributes{
					Id: &ws.UUID{Value: osIDs[0].String()},
				},
				Status: ws.OsImageStatus_ImageReady,
			},
			{
				Attributes: &ws.OsImageAttributes{
					Id: &ws.UUID{Value: osIDs[1].String()},
				},
				Status: ws.OsImageStatus_ImageFailed,
			},
		},
	}

	// Mock UpdateSSHKeyGroupsInDB activity
	s.env.RegisterActivity(osManager.UpdateOsImagesInDB)
	s.env.OnActivity(osManager.UpdateOsImagesInDB, mock.Anything, mock.Anything, mock.Anything).Return(osIDs, nil)
	s.env.OnActivity(osManager.UpdateOperatingSystemStatusInDB, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateOsImageInventory workflow
	s.env.ExecuteWorkflow(UpdateOsImageInventory, siteID.String(), osImageInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateOsImageInventoryTestSuite) Test_UpdateOsImageInventory_ActivityFails() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()
	osIDs := []uuid.UUID{uuid.New(), uuid.New()}

	osImageInventory := &ws.OsImageInventory{
		OsImages: []*ws.OsImage{
			{
				Attributes: &ws.OsImageAttributes{
					Id: &ws.UUID{Value: osIDs[0].String()},
				},
				Status: ws.OsImageStatus_ImageReady,
			},
			{
				Attributes: &ws.OsImageAttributes{
					Id: &ws.UUID{Value: osIDs[1].String()},
				},
				Status: ws.OsImageStatus_ImageFailed,
			},
		},
	}

	// Mock UpdateVpcsViaSiteAgent activity failure
	s.env.RegisterActivity(osManager.UpdateOsImagesInDB)
	s.env.OnActivity(osManager.UpdateOsImagesInDB, mock.Anything, mock.Anything, mock.Anything).Return(nil, errors.New("UpdateOsImageInventory Failure"))

	// execute UpdateVPCStatus workflow
	s.env.ExecuteWorkflow(UpdateOsImageInventory, siteID.String(), osImageInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("UpdateOsImageInventory Failure", applicationErr.Error())
}

func TestUpdateOsImageSuite(t *testing.T) {
	suite.Run(t, new(UpdateOsImageInventoryTestSuite))
}

type UpdateOperatingSystemInventoryTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *UpdateOperatingSystemInventoryTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *UpdateOperatingSystemInventoryTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *UpdateOperatingSystemInventoryTestSuite) Test_UpdateOperatingSystemInventory_Success() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()

	operatingSystemInventory := &ws.OperatingSystemInventory{
		OperatingSystems: []*ws.OperatingSystem{
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-1",
			},
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-2",
			},
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-3",
			},
		},
	}

	// Mock UpdateOperatingSystemsInDB activity
	s.env.RegisterActivity(osManager.UpdateOperatingSystemsInDB)
	s.env.OnActivity(osManager.UpdateOperatingSystemsInDB, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateOperatingSystemInventory workflow
	s.env.ExecuteWorkflow(UpdateOperatingSystemInventory, siteID.String(), operatingSystemInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *UpdateOperatingSystemInventoryTestSuite) Test_UpdateOperatingSystemInventory_ActivityFails() {
	var osManager osActivity.ManageOperatingSystem

	siteID := uuid.New()

	operatingSystemInventory := &ws.OperatingSystemInventory{
		OperatingSystems: []*ws.OperatingSystem{
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-1",
			},
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-2",
			},
			{
				Id:   &ws.OperatingSystemId{Value: uuid.NewString()},
				Name: "test-operating-system-3",
			},
		},
	}

	// Mock UpdateOperatingSystemsInDB activity failure
	s.env.RegisterActivity(osManager.UpdateOperatingSystemsInDB)
	s.env.OnActivity(osManager.UpdateOperatingSystemsInDB, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("UpdateOperatingSystemInventory Failure"))

	// execute UpdateOperatingSystemInventory workflow
	s.env.ExecuteWorkflow(UpdateOperatingSystemInventory, siteID.String(), operatingSystemInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal("UpdateOperatingSystemInventory Failure", applicationErr.Error())
}

func TestUpdateOperatingSystemInventorySuite(t *testing.T) {
	suite.Run(t, new(UpdateOperatingSystemInventoryTestSuite))
}
