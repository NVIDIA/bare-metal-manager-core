// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"

	mActivity "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/util"
)

type MachineWorkflowTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *MachineWorkflowTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *MachineWorkflowTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *MachineWorkflowTestSuite) Test_UpdateMachineInventory_Success() {
	var machineManager mActivity.ManageMachine

	request := &cwssaws.MaintenanceRequest{
		Operation: cwssaws.MaintenanceOperation_Enable,
		HostId:    &cwssaws.MachineId{Id: uuid.New().String()},
		Reference: util.GetStrPtr("Machine needs to taken offline to re-cable the network"),
	}

	// Mock UpdateVpcViaSiteAgent activity
	s.env.RegisterActivity(machineManager.SetMachineMaintenanceOnSite)
	s.env.OnActivity(machineManager.SetMachineMaintenanceOnSite, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateMachineInventory workflow
	s.env.ExecuteWorkflow(SetMachineMaintenance, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *MachineWorkflowTestSuite) Test_UpdateMachineInventory_ActivityFails() {
	var machineManager mActivity.ManageMachine

	request := &cwssaws.MaintenanceRequest{
		Operation: cwssaws.MaintenanceOperation_Enable,
		HostId:    &cwssaws.MachineId{Id: uuid.New().String()},
		Reference: util.GetStrPtr("Machine needs to taken offline to re-cable the network"),
	}

	errMsg := "Site Controller communication error"

	// Mock SetMachineMaintenanceOnSite activity failure
	s.env.RegisterActivity(machineManager.SetMachineMaintenanceOnSite)
	s.env.OnActivity(machineManager.SetMachineMaintenanceOnSite, mock.Anything, mock.Anything).Return(errors.New(errMsg))

	// Execute SetMachineMaintenanceOnSite workflow
	s.env.ExecuteWorkflow(SetMachineMaintenance, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *MachineWorkflowTestSuite) Test_CollectAndPublishMachineInventory_Success() {
	var machineInventoryManager mActivity.ManageMachineInventory

	// Mock SetMachineMaintenanceOnSite activity failure
	s.env.RegisterActivity(machineInventoryManager.CollectAndPublishMachineInventory)
	s.env.OnActivity(machineInventoryManager.CollectAndPublishMachineInventory, mock.Anything).Return(nil)

	// execute UpdateMachineInventory workflow
	s.env.ExecuteWorkflow(CollectAndPublishMachineInventory)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *MachineWorkflowTestSuite) Test_CollectAndPublishMachineInventory_ActivityFails() {
	var machineInventoryManager mActivity.ManageMachineInventory

	errMsg := "Site Controller communication error"

	// Mock SetMachineMaintenanceOnSite activity failure
	s.env.RegisterActivity(machineInventoryManager.CollectAndPublishMachineInventory)
	s.env.OnActivity(machineInventoryManager.CollectAndPublishMachineInventory, mock.Anything).Return(errors.New(errMsg))

	// Execute SetMachineMaintenanceOnSite workflow
	s.env.ExecuteWorkflow(CollectAndPublishMachineInventory)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *MachineWorkflowTestSuite) Test_UpdateMachineMetadata_Success() {
	var machineManager mActivity.ManageMachine

	request := &cwssaws.MachineMetadataUpdateRequest{
		MachineId: &cwssaws.MachineId{Id: uuid.New().String()},
		Metadata: &cwssaws.Metadata{
			Labels: []*cwssaws.Label{
				{
					Key:   "test-key",
					Value: util.GetStrPtr("test-value"),
				},
			},
		},
	}

	// Mock UpdateMachineMetadataOnSite activity
	s.env.RegisterActivity(machineManager.UpdateMachineMetadataOnSite)
	s.env.OnActivity(machineManager.UpdateMachineMetadataOnSite, mock.Anything, mock.Anything).Return(nil)

	// execute UpdateMachineMetadata workflow
	s.env.ExecuteWorkflow(UpdateMachineMetadata, request)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *MachineWorkflowTestSuite) Test_UpdateMachineMetadata_ActivityFails() {
	var machineManager mActivity.ManageMachine

	errMsg := "Site Controller communication error"

	request := &cwssaws.MachineMetadataUpdateRequest{
		MachineId: &cwssaws.MachineId{Id: uuid.New().String()},
		Metadata: &cwssaws.Metadata{
			Labels: []*cwssaws.Label{
				{
					Key:   "test-key",
					Value: util.GetStrPtr("test-value"),
				},
			},
		},
	}

	// Mock UpdateMachineMetadataOnSite activity failure
	s.env.RegisterActivity(machineManager.UpdateMachineMetadataOnSite)
	s.env.OnActivity(machineManager.UpdateMachineMetadataOnSite, mock.Anything, mock.Anything).Return(errors.New(errMsg))

	// Execute UpdateMachineMetadata workflow
	s.env.ExecuteWorkflow(UpdateMachineMetadata, request)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func (s *MachineWorkflowTestSuite) Test_CreateMachineHealthReportOverride_Success() {
	var machineManager mActivity.ManageMachine
	req := &cwssaws.InsertHealthReportOverrideRequest{
		MachineId: &cwssaws.MachineId{Id: uuid.New().String()},
		Override: &cwssaws.HealthReportOverride{
			Report: &cwssaws.HealthReport{
				Source: "request-online-repair",
				Alerts: []*cwssaws.HealthProbeAlert{
					{Id: "OnLineRepair", Message: `{"details":"d","issue_category":"OTHER","summary":"s"}`},
				},
			},
			Mode: cwssaws.OverrideMode_Merge,
		},
	}
	s.env.RegisterActivity(machineManager.CreateMachineHealthReportOverrideOnSite)
	s.env.OnActivity(machineManager.CreateMachineHealthReportOverrideOnSite, mock.Anything, mock.Anything).Return(nil)
	s.env.ExecuteWorkflow(CreateMachineHealthReportOverride, req)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func (s *MachineWorkflowTestSuite) Test_DeleteMachineHealthReportOverride_Success() {
	var machineManager mActivity.ManageMachine
	req := &cwssaws.RemoveHealthReportOverrideRequest{
		MachineId: &cwssaws.MachineId{Id: uuid.New().String()},
		Source:    "request-online-repair",
	}
	s.env.RegisterActivity(machineManager.DeleteMachineHealthReportOverrideOnSite)
	s.env.OnActivity(machineManager.DeleteMachineHealthReportOverrideOnSite, mock.Anything, mock.Anything).Return(nil)
	s.env.ExecuteWorkflow(DeleteMachineHealthReportOverride, req)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())
}

func TestMachineWorkflowSuite(t *testing.T) {
	suite.Run(t, new(MachineWorkflowTestSuite))
}

// GetDpuMachinesTestSuite defines Temporal test suite for the GetDpuMachines workflow
type GetDpuMachinesTestSuite struct {
	suite.Suite
	testsuite.WorkflowTestSuite

	env *testsuite.TestWorkflowEnvironment
}

func (s *GetDpuMachinesTestSuite) SetupTest() {
	s.env = s.NewTestWorkflowEnvironment()
}

func (s *GetDpuMachinesTestSuite) AfterTest(suiteName, testName string) {
	s.env.AssertExpectations(s.T())
}

func (s *GetDpuMachinesTestSuite) Test_GetDpuMachines_Success() {
	var machineManager mActivity.ManageMachine

	dpuMachineIDs := []string{"dpu-machine-1", "dpu-machine-2", "dpu-machine-3"}

	expectedResult := []*cwssaws.DpuMachine{
		{
			Machine: &cwssaws.Machine{
				Id: &cwssaws.MachineId{Id: "dpu-machine-1"},
			},
			DpuNetworkConfig: &cwssaws.ManagedHostNetworkConfigResponse{
				VniDevice:    "vxlan48",
				IsPrimaryDpu: true,
			},
		},
		{
			Machine: &cwssaws.Machine{
				Id: &cwssaws.MachineId{Id: "dpu-machine-2"},
			},
			DpuNetworkConfig: &cwssaws.ManagedHostNetworkConfigResponse{
				VniDevice:    "vxlan48",
				IsPrimaryDpu: false,
			},
		},
		{
			Machine: &cwssaws.Machine{
				Id: &cwssaws.MachineId{Id: "dpu-machine-3"},
			},
			DpuNetworkConfig: &cwssaws.ManagedHostNetworkConfigResponse{
				VniDevice:    "vxlan48",
				IsPrimaryDpu: false,
			},
		},
	}

	// Mock GetDpuMachinesByIDs activity success
	s.env.RegisterActivity(machineManager.GetDpuMachinesByIDs)
	s.env.OnActivity(machineManager.GetDpuMachinesByIDs, mock.Anything, mock.Anything).Return(expectedResult, nil)

	// Execute GetDpuMachines workflow
	s.env.ExecuteWorkflow(GetDpuMachines, dpuMachineIDs)
	s.True(s.env.IsWorkflowCompleted())
	s.NoError(s.env.GetWorkflowError())

	var result []*cwssaws.DpuMachine
	s.env.GetWorkflowResult(&result)

	s.Equal(len(expectedResult), len(result))
	for i, dpuMachine := range result {
		s.Equal(expectedResult[i].Machine.Id.Id, dpuMachine.Machine.Id.Id)
		s.Equal(expectedResult[i].DpuNetworkConfig.VniDevice, dpuMachine.DpuNetworkConfig.VniDevice)
		s.Equal(expectedResult[i].DpuNetworkConfig.IsPrimaryDpu, dpuMachine.DpuNetworkConfig.IsPrimaryDpu)
	}
}

func (s *GetDpuMachinesTestSuite) Test_GetDpuMachines_ActivityFails() {
	var machineManager mActivity.ManageMachine

	dpuMachineIDs := []string{"dpu-machine-1", "dpu-machine-2", "dpu-machine-3"}

	errMsg := "Site Controller communication error"

	// Mock GetDpuMachinesByIDs activity failure
	s.env.RegisterActivity(machineManager.GetDpuMachinesByIDs)
	s.env.OnActivity(machineManager.GetDpuMachinesByIDs, mock.Anything, mock.Anything).Return(nil, errors.New(errMsg))

	// Execute GetDpuMachines workflow
	s.env.ExecuteWorkflow(GetDpuMachines, dpuMachineIDs)
	s.True(s.env.IsWorkflowCompleted())
	err := s.env.GetWorkflowError()
	s.Error(err)

	var applicationErr *temporal.ApplicationError
	s.True(errors.As(err, &applicationErr))
	s.Equal(errMsg, applicationErr.Error())
}

func TestGetDpuMachinesTestSuite(t *testing.T) {
	suite.Run(t, new(GetDpuMachinesTestSuite))
}
