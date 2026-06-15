// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operatingsystem

import (
	swa "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

// RegisterSubscriber registers the OsImage and OperatingSystem CRUD
// workflows/activities with the Temporal client.
func (api *API) RegisterSubscriber() error {
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Registering CRUD workflows and activities")

	osManager := swa.NewManageOperatingSystem(ManagerAccess.Data.EB.Managers.CoreGrpc.Client)

	// ── OsImage workflows (cloud-managed image catalog pushed to site) ─────────────────
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CreateOsImage)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered CreateOsImage workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.UpdateOsImage)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered UpdateOsImage workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DeleteOsImage)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered DeleteOsImage workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.CreateOsImageOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered CreateOsImageOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.UpdateOsImageOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered UpdateOsImageOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.DeleteOsImageOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: Successfully registered DeleteOsImageOnSite activity")

	// ── OperatingSystem workflows (bi-directional: carbide-rest ↔ nico-core) ────────
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CreateOperatingSystem)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered the CreateOperatingSystem workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.UpdateOperatingSystem)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered the UpdateOperatingSystem workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DeleteOperatingSystem)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered the DeleteOperatingSystem workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.CreateOperatingSystemOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered CreateOperatingSystemOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.UpdateOperatingSystemOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered UpdateOperatingSystemOnSite activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(osManager.DeleteOperatingSystemOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("OperatingSystem: successfully registered DeleteOperatingSystemOnSite activity")

	return nil
}
