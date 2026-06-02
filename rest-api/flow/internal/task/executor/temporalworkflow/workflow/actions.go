// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/workflow"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/activity"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/common"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operationrules"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

// actionExecutionContext holds the context needed for action execution
type actionExecutionContext struct {
	workflowContext workflow.Context
	config          operationrules.ActionConfig
	target          common.Target
	allTargets      map[devicetypes.ComponentType]common.Target
	operationInfo   any
}

// actionExecutor defines the signature for action execution functions
type actionExecutor func(actx actionExecutionContext) error

// actionExecutorRegistry maps action names to their executor functions
var actionExecutorRegistry = map[string]actionExecutor{
	operationrules.ActionSleep:                     executeSleepAction,
	operationrules.ActionPowerControl:              executePowerControlAction,
	operationrules.ActionVerifyPowerStatus:         executeVerifyPowerStatusAction,
	operationrules.ActionVerifyReachability:        executeVerifyReachabilityAction,
	operationrules.ActionGetPowerStatus:            executeGetPowerStatusAction,
	operationrules.ActionFirmwareControl:           executeFirmwareControlAction,
	operationrules.ActionBringUpControl:            executeBringUpControlAction,
	operationrules.ActionWaitBringUp:               executeWaitBringUpAction,
	operationrules.ActionInjectExpectation:         executeInjectExpectationAction,
	operationrules.ActionVerifyFirmwareConsistency: executeVerifyFirmwareConsistencyAction,
}

// executeActionList executes a list of actions sequentially
func executeActionList(
	ctx workflow.Context,
	actions []operationrules.ActionConfig,
	target common.Target,
	allTargets map[devicetypes.ComponentType]common.Target,
	operationInfo any,
) error {
	for i, action := range actions {
		if err := executeAction(ctx, action, target, allTargets, operationInfo); err != nil {
			return fmt.Errorf("action %d (%s) failed: %w", i, action.Name, err)
		}
	}
	return nil
}

// executeAction executes a single action using the registry
func executeAction(
	ctx workflow.Context,
	config operationrules.ActionConfig,
	target common.Target,
	allTargets map[devicetypes.ComponentType]common.Target,
	operationInfo any,
) error {
	executor, ok := actionExecutorRegistry[config.Name]
	if !ok {
		return fmt.Errorf("unknown action: %s", config.Name)
	}

	actx := actionExecutionContext{
		workflowContext: ctx,
		config:          config,
		target:          target,
		allTargets:      allTargets,
		operationInfo:   operationInfo,
	}

	return executor(actx)
}

// executeSleepAction handles Sleep action
func executeSleepAction(actx actionExecutionContext) error {
	duration := parseDurationParam(
		actx.config.Parameters[operationrules.ParamDuration],
	)
	log.Debug().
		Dur("duration", duration).
		Msg("Sleeping")
	return workflow.Sleep(actx.workflowContext, duration)
}

// executePowerControlAction handles PowerControl action.
// When called from a non-power workflow (firmware, bring-up), ParamOperation
// must be set in the action config to specify the desired power operation.
// When called from the power workflow, operationInfo is passed through
// directly (Temporal handles deserialization at the activity boundary).
func executePowerControlAction(actx actionExecutionContext) error {
	if opParam, ok := actx.config.Parameters[operationrules.ParamOperation]; ok {
		opStr, _ := opParam.(string)
		op := operations.PowerOperationFromString(opStr)
		if op == operations.PowerOperationUnknown {
			return fmt.Errorf(
				"PowerControl action: unrecognized operation %q", opStr,
			)
		}
		info := operations.PowerControlTaskInfo{Operation: op}
		return executeGenericActivity(
			actx.workflowContext, activity.NamePowerControl, actx.target, info,
		)
	}

	return executeGenericActivity(
		actx.workflowContext, activity.NamePowerControl, actx.target, actx.operationInfo,
	)
}

// executeVerifyPowerStatusAction handles VerifyPowerStatus action
func executeVerifyPowerStatusAction(actx actionExecutionContext) error {
	expectedStatus := actx.config.Parameters[operationrules.ParamExpectedStatus].(string)
	return verifyPowerStatus(
		actx.workflowContext,
		actx.target,
		expectedStatus,
		actx.config.Timeout,
		actx.config.PollInterval,
	)
}

// executeVerifyReachabilityAction handles VerifyReachability action
func executeVerifyReachabilityAction(actx actionExecutionContext) error {
	var componentTypes []string
	switch v := actx.config.Parameters[operationrules.ParamComponentTypes].(type) {
	case []string:
		componentTypes = v
	case []any:
		componentTypes = make([]string, len(v))
		for i, item := range v {
			componentTypes[i] = item.(string)
		}
	}

	requireAll, _ := actx.config.Parameters[operationrules.ParamRequireAll].(bool)

	return verifyReachability(
		actx.workflowContext,
		actx.allTargets,
		componentTypes,
		actx.config.Timeout,
		actx.config.PollInterval,
		requireAll,
	)
}

// executeGetPowerStatusAction handles GetPowerStatus action
func executeGetPowerStatusAction(actx actionExecutionContext) error {
	return executeGenericActivity(
		actx.workflowContext,
		activity.NameGetPowerStatus,
		actx.target,
		nil,
	)
}

// executeFirmwareControlAction handles FirmwareControl action by starting a
// firmware update and polling for completion. Poll parameters are read from
// the action config (poll_interval, poll_timeout) with sensible defaults.
//
// operationInfo may arrive as *FirmwareControlTaskInfo (same-process call),
// FirmwareControlTaskInfo (value copy), or map[string]interface{} (after
// Temporal child-workflow JSON round-trip where the parameter type is `any`).
// We attempt recovery in that order; if none succeeds (e.g. BringUp context
// where operationInfo is BringUpTaskInfo), we fall back to a default upgrade
// with empty TargetVersion so the component manager auto-resolves.
func executeFirmwareControlAction(actx actionExecutionContext) error {
	ctx := actx.workflowContext
	target := actx.target

	var fwInfo operations.FirmwareControlTaskInfo
	switch v := actx.operationInfo.(type) {
	case *operations.FirmwareControlTaskInfo:
		fwInfo = *v
	case operations.FirmwareControlTaskInfo:
		fwInfo = v
	default:
		// After Temporal child-workflow serialization the concrete Go type is
		// lost and becomes map[string]interface{}. JSON round-trip recovers
		// the original FirmwareControlTaskInfo fields (including TargetVersion).
		if data, err := json.Marshal(actx.operationInfo); err == nil {
			_ = json.Unmarshal(data, &fwInfo)
		}
	}
	if fwInfo.Operation == operations.FirmwareOperationUnknown {
		fwInfo.Operation = operations.FirmwareOperationUpgrade
	}

	fwInfo.TargetVersion = extractComponentTargetVersion(fwInfo.TargetVersion, target.Type)

	if err := workflow.ExecuteActivity(
		ctx, activity.NameFirmwareControl, target, fwInfo,
	).Get(ctx, nil); err != nil {
		return fmt.Errorf("failed to start firmware update: %w", err)
	}

	// Determine poll parameters from action config
	pollInterval := 2 * time.Minute
	pollTimeout := 30 * time.Minute

	if v, ok := actx.config.Parameters[operationrules.ParamPollInterval]; ok {
		if d := parseDurationParam(v); d > 0 {
			pollInterval = d
		}
	}
	if v, ok := actx.config.Parameters[operationrules.ParamPollTimeout]; ok {
		if d := parseDurationParam(v); d > 0 {
			pollTimeout = d
		}
	}

	componentStr := devicetypes.ComponentTypeToString(target.Type)
	startTime := workflow.Now(ctx)
	deadline := startTime.Add(pollTimeout)

	log.Debug().
		Str("component_type", componentStr).
		Dur("poll_interval", pollInterval).
		Dur("poll_timeout", pollTimeout).
		Msg("Polling firmware update status")

	for {
		if workflow.Now(ctx).After(deadline) {
			return fmt.Errorf(
				"%s firmware update timed out after %v", componentStr, pollTimeout,
			)
		}

		var result activity.GetFirmwareStatusResult
		err := workflow.ExecuteActivity(
			ctx, activity.NameGetFirmwareStatus, target,
		).Get(ctx, &result)
		if err != nil {
			log.Warn().Err(err).
				Str("target", target.String()).
				Msg("Failed to get firmware update status, will retry")
		} else {
			allCompleted := true
			var failedComponents []string
			for componentID, status := range result.Statuses {
				if status.State == operations.FirmwareUpdateStateFailed {
					failedComponents = append(failedComponents, componentID)
				}
				if status.State != operations.FirmwareUpdateStateCompleted {
					allCompleted = false
				}
			}

			if len(failedComponents) > 0 {
				return fmt.Errorf(
					"firmware update failed for components: %v", failedComponents,
				)
			}

			if allCompleted {
				log.Info().
					Str("target", target.String()).
					Dur("duration", workflow.Now(ctx).Sub(startTime)).
					Msg("Firmware update completed")
				return nil
			}
		}

		if err := workflow.Sleep(ctx, pollInterval); err != nil {
			return fmt.Errorf("workflow sleep interrupted: %w", err)
		}
	}
}

// executeGenericActivity executes a Temporal activity identified by its assigned name.
func executeGenericActivity(
	ctx workflow.Context,
	name string,
	target common.Target,
	activityInfo any,
) error {
	var args []any
	args = append(args, target)
	if activityInfo != nil {
		args = append(args, activityInfo)
	}
	return workflow.ExecuteActivity(ctx, name, args...).Get(ctx, nil)
}

// verifyPowerStatus polls GetPowerStatus until expected status is reached
func verifyPowerStatus(
	ctx workflow.Context,
	target common.Target,
	expectedStatus string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	// Convert string to PowerStatus
	var expected operations.PowerStatus
	switch expectedStatus {
	case "on":
		expected = operations.PowerStatusOn
	case "off":
		expected = operations.PowerStatusOff
	default:
		return fmt.Errorf(
			"invalid expected_status '%s', must be 'on' or 'off'",
			expectedStatus,
		)
	}

	log.Debug().
		Str("component_type", devicetypes.ComponentTypeToString(target.Type)).
		Strs("component_ids", target.ComponentIDs).
		Str("expected_status", expectedStatus).
		Dur("timeout", timeout).
		Dur("poll_interval", pollInterval).
		Msg("Starting power status verification")

	deadline := workflow.Now(ctx).Add(timeout)
	attempt := 0

	for {
		attempt++

		// Call GetPowerStatus activity
		var statusMap map[string]operations.PowerStatus
		actErr := workflow.ExecuteActivity(
			ctx,
			activity.NameGetPowerStatus,
			target,
		).Get(ctx, &statusMap)

		if actErr == nil {
			allMatch := true
			mismatched := make(map[string]string, len(statusMap))
			for componentID, status := range statusMap {
				if status != expected {
					mismatched[componentID] = string(status)
					allMatch = false
				}
			}

			if allMatch {
				log.Info().
					Int("attempts", attempt).
					Int("component_count", len(statusMap)).
					Str("expected_status", string(expected)).
					Msg("All components reached expected power status")
				return nil
			}

			log.Info().
				Int("attempt", attempt).
				Str("expected_status", string(expected)).
				Int("mismatch_count", len(mismatched)).
				Interface("mismatched", mismatched).
				Msg("Power status mismatch, will retry")
		} else {
			log.Info().
				Err(actErr).
				Int("attempt", attempt).
				Str("expected_status", string(expected)).
				Msg("GetPowerStatus failed, will retry")
		}

		// Check timeout
		if workflow.Now(ctx).After(deadline) {
			return fmt.Errorf(
				"timeout after %v waiting for power status %s (attempts: %d)",
				timeout,
				expected,
				attempt,
			)
		}

		// Sleep before next poll (durable sleep in workflow)
		workflow.Sleep(ctx, pollInterval)
	}
}

// executeBringUpControlAction opens the power-on gate for the target components.
func executeBringUpControlAction(actx actionExecutionContext) error {
	return workflow.ExecuteActivity(
		actx.workflowContext, activity.NameBringUpControl, actx.target,
	).Get(actx.workflowContext, nil)
}

// executeWaitBringUpAction polls GetBringUpStatus until all components reach
// the MachineBringUpStateMachineCreated state. Uses config.Timeout and
// config.PollInterval.
func executeWaitBringUpAction(actx actionExecutionContext) error {
	ctx := actx.workflowContext
	target := actx.target

	timeout := actx.config.Timeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	pollInterval := actx.config.PollInterval
	if pollInterval == 0 {
		pollInterval = 30 * time.Second
	}

	log.Debug().
		Dur("timeout", timeout).
		Dur("poll_interval", pollInterval).
		Msg("Waiting for compute bring-up")

	deadline := workflow.Now(ctx).Add(timeout)

	for {
		if workflow.Now(ctx).After(deadline) {
			return fmt.Errorf(
				"timed out waiting for compute bring-up (timeout %v)", timeout,
			)
		}

		if err := workflow.Sleep(ctx, pollInterval); err != nil {
			return fmt.Errorf("workflow sleep interrupted: %w", err)
		}

		var result activity.GetBringUpStatusResult
		err := workflow.ExecuteActivity(
			ctx, activity.NameGetBringUpStatus, target,
		).Get(ctx, &result)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to get bring-up state, will retry")
			continue
		}

		allReady := true
		for componentID, state := range result.States {
			if !state.IsBroughtUp() {
				allReady = false
				log.Debug().
					Str("component_id", componentID).
					Str("state", state.String()).
					Msg("Compute not yet brought up")
			}
		}

		if allReady {
			log.Info().
				Int("count", len(result.States)).
				Msg("All compute components brought up")
			return nil
		}
	}
}

// verifyReachability polls GetPowerStatus for multiple component types until
// all are reachable. When requireAll is true, every individual component
// within a type must respond (not just the API call succeeding).
func verifyReachability(
	ctx workflow.Context,
	allTargets map[devicetypes.ComponentType]common.Target,
	componentTypes []string,
	timeout time.Duration,
	pollInterval time.Duration,
	requireAll bool,
) error {
	typesToCheck := make([]devicetypes.ComponentType, 0, len(componentTypes))
	for _, ctStr := range componentTypes {
		ct := devicetypes.ComponentTypeFromString(ctStr)
		if ct == devicetypes.ComponentTypeUnknown {
			return fmt.Errorf("invalid component type: %s", ctStr)
		}
		typesToCheck = append(typesToCheck, ct)
	}

	log.Debug().
		Strs("component_types", componentTypes).
		Bool("require_all", requireAll).
		Dur("timeout", timeout).
		Dur("poll_interval", pollInterval).
		Msg("Starting reachability verification")

	deadline := workflow.Now(ctx).Add(timeout)
	reachable := make(map[devicetypes.ComponentType]bool)

	for {
		for _, ct := range typesToCheck {
			if reachable[ct] {
				continue
			}

			target, ok := allTargets[ct]
			if !ok {
				log.Debug().
					Str("component_type", devicetypes.ComponentTypeToString(ct)).
					Msg("Component type not in target map, skipping")
				reachable[ct] = true
				continue
			}

			var statusMap map[string]operations.PowerStatus
			err := workflow.ExecuteActivity(
				ctx,
				activity.NameGetPowerStatus,
				target,
			).Get(ctx, &statusMap)

			if err != nil {
				log.Debug().
					Str("component_type", devicetypes.ComponentTypeToString(ct)).
					Err(err).
					Msg("Component type not yet reachable")
				continue
			}

			if requireAll && len(statusMap) < len(target.ComponentIDs) {
				log.Debug().
					Str("component_type", devicetypes.ComponentTypeToString(ct)).
					Int("responding", len(statusMap)).
					Int("expected", len(target.ComponentIDs)).
					Msg("Not all components responding yet")
				continue
			}

			log.Debug().
				Str("component_type", devicetypes.ComponentTypeToString(ct)).
				Msg("Component type is reachable")
			reachable[ct] = true
		}

		allReachable := true
		for _, ct := range typesToCheck {
			if !reachable[ct] {
				allReachable = false
				break
			}
		}

		if allReachable {
			log.Debug().
				Strs("component_types", componentTypes).
				Msg("All component types are reachable")
			return nil
		}

		if workflow.Now(ctx).After(deadline) {
			unreachable := []string{}
			for _, ct := range typesToCheck {
				if !reachable[ct] {
					unreachable = append(
						unreachable,
						devicetypes.ComponentTypeToString(ct),
					)
				}
			}
			return fmt.Errorf(
				"timeout after %v waiting for components to become reachable: %v",
				timeout,
				unreachable,
			)
		}

		workflow.Sleep(ctx, pollInterval)
	}
}

// executeInjectExpectationAction calls the InjectExpectation activity to register
// expected component configurations with their respective component manager services.
func executeInjectExpectationAction(actx actionExecutionContext) error {
	ctx := actx.workflowContext
	info := operations.InjectExpectationTaskInfo{}

	log.Debug().
		Str("component_type", devicetypes.ComponentTypeToString(actx.target.Type)).
		Int("component_count", len(actx.target.ComponentIDs)).
		Msg("Executing InjectExpectation action")

	return workflow.ExecuteActivity(
		ctx, activity.NameInjectExpectation, actx.target, info,
	).Get(ctx, nil)
}

// executeVerifyFirmwareConsistencyAction checks that all target components
// have the same firmware version. Fails if versions are heterogeneous.
func executeVerifyFirmwareConsistencyAction(actx actionExecutionContext) error {
	return workflow.ExecuteActivity(
		actx.workflowContext,
		activity.NameVerifyFirmwareConsistency,
		actx.target,
	).Get(actx.workflowContext, nil)
}

// knownComponentTypeKeys are the JSON keys recognised in a layered
// TargetVersion object. Used to distinguish the new per-component-type
// format from the legacy flat format.
var knownComponentTypeKeys = []string{"compute", "nvswitch", "powershelf"}

// extractComponentTargetVersion extracts the component-specific section from
// a layered TargetVersion JSON string. The expected top-level structure is:
//
//	{
//	  "compute":    {"bmc": "7.10.30", "uefi": "2.22.1"},
//	  "nvswitch":  "1.3.1",
//	  "powershelf": "r1.3.9"
//	}
//
// If the key for componentType is present, the corresponding value is
// returned. String scalars are unquoted so component managers receive the
// plain value (e.g. "1.3.1" → 1.3.1); object values are returned as raw
// JSON for component managers that parse multi-field version payloads.
// If the key is absent but the document contains another known
// component-type key (i.e. it IS the layered format), an empty string
// is returned so the component manager skips the firmware update. If the
// document does not look like the layered format (no known keys), the
// original string is returned as-is for backward compatibility with
// single-component updates.
func extractComponentTargetVersion(rawVersion string, componentType devicetypes.ComponentType) string {
	if rawVersion == "" {
		return ""
	}

	var layered map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawVersion), &layered); err != nil {
		return rawVersion
	}

	key := strings.ToLower(devicetypes.ComponentTypeToString(componentType))
	if section, ok := layered[key]; ok {
		if len(section) > 0 && section[0] == '"' {
			var s string
			if err := json.Unmarshal(section, &s); err == nil {
				return s
			}
		}
		return string(section)
	}

	for _, known := range knownComponentTypeKeys {
		if _, found := layered[known]; found {
			return ""
		}
	}

	return rawVersion
}
