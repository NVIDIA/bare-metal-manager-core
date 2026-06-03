// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package machine

import (
	swa "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/workflow"
)

// RegisterSubscriber registers Machine CRUD workflows and activities with Temporal
func (api *API) RegisterSubscriber() error {
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: Registering CRUD workflows and activities")

	// Register workflows

	// Register SetMachineMaintenance workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.SetMachineMaintenance)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: Successfully registered SetMachineMaintenance workflow")

	// Register UpdateMachineMetadata workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.UpdateMachineMetadata)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: Successfully registered UpdateMachineMetadata workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CreateMachineHealthReportOverride)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: successfully registered the CreateMachineHealthReportOverride workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DeleteMachineHealthReportOverride)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: successfully registered the DeleteMachineHealthReportOverride Override workflow")

	// Register activities
	machineManager := swa.NewManageMachine(ManagerAccess.Data.EB.Managers.CoreGrpc.Client)

	// Register SetMachineMaintenanceOnSite activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(machineManager.SetMachineMaintenanceOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: Successfully registered SetMachineMaintenanceOnSite activity")

	// Register UpdateMachineMetadataOnSite activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(machineManager.UpdateMachineMetadataOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: Successfully registered UpdateMachineMetadataOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(machineManager.CreateMachineHealthReportOverrideOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: successfully registered the CreateMachineHealthReportOverrideOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(machineManager.DeleteMachineHealthReportOverrideOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("Machine: successfully registered the DeleteMachineHealthReportOverrideOnSite activity")

	return nil
}
