// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package flowgrpc

import (
	swa "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/activity"
	sww "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/workflow"
)

// RegisterSubscriber registers Flow rack and tray workflows and activities with Temporal
func (flowgrpc *API) RegisterSubscriber() error {
	// Check if Flow is enabled
	if !ManagerAccess.Conf.EB.FlowGrpc.Enabled {
		ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Flow gRPC is disabled, skipping workflow registration")
		return nil
	}

	// Register Rack workflows
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Registering rack workflows")

	// Register GetRack workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetRack workflow")

	// Register GetRacks workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetRacks)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetRacks workflow")

	// Register ValidateRackComponents workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.ValidateRackComponents)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered ValidateRackComponents workflow")

	// Register PowerOnRack workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.PowerOnRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerOnRack workflow")

	// Register PowerOffRack workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.PowerOffRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerOffRack workflow")

	// Register PowerResetRack workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.PowerResetRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerResetRack workflow")

	// Register BringUpRack workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.BringUpRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered BringUpRack workflow")

	// Register UpgradeFirmware workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.UpgradeFirmware)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered UpgradeFirmware workflow")

	// Register activities
	rackManager := swa.NewManageRack(ManagerAccess.Data.EB.Managers.FlowGrpc.Client)

	// Register GetRack activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.GetRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetRack activity")

	// Register GetRacks activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.GetRacks)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetRacks activity")

	// Register ValidateRackComponents activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.ValidateRackComponents)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered ValidateRackComponents activity")

	// Register PowerOnRack activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.PowerOnRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerOnRack activity")

	// Register PowerOffRack activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.PowerOffRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerOffRack activity")

	// Register PowerResetRack activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.PowerResetRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PowerResetRack activity")

	// Register BringUpRack activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.BringUpRack)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered BringUpRack activity")

	// Register UpgradeFirmware activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(rackManager.UpgradeFirmware)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered UpgradeFirmware activity")

	// Register Tray workflows

	// Register GetTray workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTray)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTray workflow")

	// Register GetTrays workflow
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTrays)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTrays workflow")

	// Register tray activities
	trayManager := swa.NewManageTray(ManagerAccess.Data.EB.Managers.FlowGrpc.Client)

	// Register GetTray activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(trayManager.GetTray)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTray activity")

	// Register GetTrays activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(trayManager.GetTrays)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTrays activity")

	// Register Task workflows
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTask)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTask workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CancelTask)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CancelTask workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTasks)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTasks workflow")

	// Register Task activities
	taskManager := swa.NewManageTask(ManagerAccess.Data.EB.Managers.FlowGrpc.Client)

	// Register GetTask activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(taskManager.GetTaskFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTaskFromFlow activity")

	// Register CancelTask activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(taskManager.CancelTaskOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CancelTaskOnFlow activity")

	// Register GetTasks activity
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(taskManager.GetTasksFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTasksFromFlow activity")

	// Register Operation Rule workflows
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CreateTaskRule)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CreateTaskRule workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTaskRule)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTaskRule workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetAllTaskRules)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRules workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.UpdateTaskRule)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered UpdateTaskRule workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.DeleteTaskRule)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered DeleteTaskRule workflow")

	// Register Operation Rule activities
	ruleManager := swa.NewManageRule(ManagerAccess.Data.EB.Managers.FlowGrpc.Client)

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(ruleManager.CreateTaskRuleOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CreateTaskRuleOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(ruleManager.GetTaskRuleFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTaskRuleFromFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(ruleManager.GetAllTaskRulesFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRulesFromFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(ruleManager.UpdateTaskRuleOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered UpdateTaskRuleOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(ruleManager.DeleteTaskRuleOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered DeleteTaskRuleOnFlow activity")

	// Register Run workflows
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CreateTaskRun)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CreateTaskRun workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetTaskRun)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTaskRun workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetAllTaskRuns)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRuns workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.GetAllTaskRunTargets)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRunTargets workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.PauseTaskRun)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PauseTaskRun workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.ResumeTaskRun)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered ResumeTaskRun workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.AdvanceTaskRunPhase)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered AdvanceTaskRunPhase workflow")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.CancelTaskRun)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CancelTaskRun workflow")

	// Register Run activities
	runManager := swa.NewManageTaskRun(ManagerAccess.Data.EB.Managers.FlowGrpc.Client)

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.CreateTaskRunOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CreateTaskRunOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.GetTaskRunFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetTaskRunFromFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.GetAllTaskRunsFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRunsFromFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.GetAllTaskRunTargetsFromFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered GetAllTaskRunTargetsFromFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.PauseTaskRunOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered PauseTaskRunOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.ResumeTaskRunOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered ResumeTaskRunOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.AdvanceTaskRunPhaseOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered AdvanceTaskRunPhaseOnFlow activity")

	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(runManager.CancelTaskRunOnFlow)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered CancelTaskRunOnFlow activity")

	// Register the generic Flow gRPC proxy alongside the per-method workflows
	// above. Registering it here, before any handler dispatches through it, is
	// what lets a later release switch handlers over safely: a workflow type is
	// known only to workers that registered it, the cloud API and each site's
	// agent ship as separate Helm releases, and a type no worker knows is still
	// accepted at submission, so the caller learns of it only as a timeout.
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Registering generic Flow gRPC proxy workflow and activity")
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterWorkflow(sww.InvokeFlowGRPC)
	flowProxyManager := swa.NewManageFlowProxy(
		ManagerAccess.Data.EB.Managers.FlowGrpc.Client,
		ManagerAccess.Conf.EB.Temporal.ClusterID,
	)
	ManagerAccess.Data.EB.Managers.Workflow.Temporal.Worker.RegisterActivity(flowProxyManager.InvokeFlowGRPCOnSite)
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Successfully registered InvokeFlowGRPC workflow and activity")

	// Register the tray subscribers here
	ManagerAccess.Data.EB.Log.Info().Msg("FlowGrpc: Registering tray workflows")

	return nil
}
