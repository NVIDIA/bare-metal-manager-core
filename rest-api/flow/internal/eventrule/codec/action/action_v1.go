// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package action

import (
	"encoding/json"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec"
	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/operations"
	flowtypes "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/types"
)

const actionVersionV1 = 1

type actionV1 struct {
	Version   int               `json:"version"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Condition actionConditionV1 `json:"condition"`
	Spec      json.RawMessage   `json:"spec"`
}

type actionConditionV1 struct {
	Severities     []string `json:"severities,omitempty"`
	ComponentTypes []string `json:"componentTypes,omitempty"`
}

type submitTaskSpecV1 struct {
	Operation        operationV1 `json:"operation"`
	TargetStrategy   string      `json:"targetStrategy"`
	ConflictStrategy string      `json:"conflictStrategy"`
	Description      string      `json:"description,omitempty"`
}

type operationV1 struct {
	Type string          `json:"type"`
	Info json.RawMessage `json:"info"`
}

type sendAlertSpecV1 struct {
	Severity string `json:"severity"`
	Message  string `json:"message,omitempty"`
}

type noopSpecV1 struct {
	Reason string `json:"reason,omitempty"`
}

func marshalActionV1(action eventrule.Action) (json.RawMessage, error) {
	persisted := actionV1{
		Version: actionVersionV1,
		Name:    action.Name,
		Type:    string(action.Spec.Type()),
	}

	if action.Condition.Severities != nil {
		severities := make([]string, len(action.Condition.Severities))
		for i, severity := range action.Condition.Severities {
			severities[i] = string(severity)
		}

		persisted.Condition.Severities = severities
	}

	if action.Condition.ComponentTypes != nil {
		cts := make([]string, len(action.Condition.ComponentTypes))
		for i, componentType := range action.Condition.ComponentTypes {
			cts[i] = string(componentType)
		}

		persisted.Condition.ComponentTypes = cts
	}

	spec, err := marshalActionSpecV1(action.Spec)
	if err != nil {
		return nil, err
	}
	persisted.Spec = spec

	encoded, err := json.Marshal(persisted)
	if err != nil {
		return nil, fmt.Errorf("encode event policy action v1: %w", err)
	}

	return encoded, nil
}

func unmarshalActionV1(data json.RawMessage) (eventrule.Action, error) {
	var persisted actionV1
	if err := codec.DecodeStrict(data, &persisted); err != nil {
		return eventrule.Action{}, fmt.Errorf("decode event policy action v1: %w", err)
	}

	condition := eventrule.ActionCondition{}
	if persisted.Condition.Severities != nil {
		severities := make([]eventrule.Severity, len(persisted.Condition.Severities))
		for i, severity := range persisted.Condition.Severities {
			decodedSeverity, err := eventrule.ParseSeverity(severity)
			if err != nil {
				return eventrule.Action{}, fmt.Errorf(
					"condition severities[%d]: %w",
					i,
					err,
				)
			}

			severities[i] = decodedSeverity
		}

		condition.Severities = severities
	}

	if persisted.Condition.ComponentTypes != nil {
		cts := make([]flowtypes.ComponentType, len(persisted.Condition.ComponentTypes))
		for i, componentType := range persisted.Condition.ComponentTypes {
			decodedComponentType, err := flowtypes.ParseComponentType(componentType)
			if err != nil {
				return eventrule.Action{}, fmt.Errorf(
					"condition componentTypes[%d]: %w",
					i,
					err,
				)
			}

			cts[i] = decodedComponentType
		}

		condition.ComponentTypes = cts
	}

	spec, err := unmarshalActionSpecV1(eventrule.ActionType(persisted.Type), persisted.Spec)
	if err != nil {
		return eventrule.Action{}, err
	}

	return eventrule.Action{
		Name:      persisted.Name,
		Condition: condition,
		Spec:      spec,
	}, nil
}

func marshalActionSpecV1(spec eventrule.ActionSpec) (json.RawMessage, error) {
	switch typed := spec.(type) {
	case *eventrule.SubmitTask:
		operationInfo, err := typed.Operation.Marshal()
		if err != nil {
			return nil, fmt.Errorf("encode submit_task operation v1: %w", err)
		}

		return json.Marshal(submitTaskSpecV1{
			Operation: operationV1{
				Type: string(typed.Operation.Type()),
				Info: operationInfo,
			},
			TargetStrategy:   string(typed.TargetStrategy),
			ConflictStrategy: string(typed.ConflictStrategy),
			Description:      typed.Description,
		})
	case *eventrule.SendAlert:
		return json.Marshal(sendAlertSpecV1{
			Severity: string(typed.Severity),
			Message:  typed.Message,
		})
	case *eventrule.Noop:
		return json.Marshal(noopSpecV1{Reason: typed.Reason})
	default:
		return nil, fmt.Errorf("unsupported action spec %T", spec)
	}
}

func unmarshalActionSpecV1(
	actionType eventrule.ActionType,
	data json.RawMessage,
) (eventrule.ActionSpec, error) {
	switch actionType {
	case eventrule.ActionTypeSubmitTask:
		var persisted submitTaskSpecV1
		if err := codec.DecodeStrict(data, &persisted); err != nil {
			return nil, fmt.Errorf("decode submit_task action spec v1: %w", err)
		}
		operation, err := operations.New(
			taskcommon.TaskType(persisted.Operation.Type),
			persisted.Operation.Info,
		)
		if err != nil {
			return nil, fmt.Errorf("decode submit_task operation v1: %w", err)
		}

		return &eventrule.SubmitTask{
			Operation:        operation,
			TargetStrategy:   eventrule.TargetStrategy(persisted.TargetStrategy),
			ConflictStrategy: eventrule.ConflictStrategy(persisted.ConflictStrategy),
			Description:      persisted.Description,
		}, nil
	case eventrule.ActionTypeSendAlert:
		var persisted sendAlertSpecV1
		if err := codec.DecodeStrict(data, &persisted); err != nil {
			return nil, fmt.Errorf("decode send_alert action spec v1: %w", err)
		}

		severity, err := eventrule.ParseSeverity(persisted.Severity)
		if err != nil {
			return nil, fmt.Errorf("decode send_alert action spec v1 severity: %w", err)
		}
		return &eventrule.SendAlert{
			Severity: severity,
			Message:  persisted.Message,
		}, nil
	case eventrule.ActionTypeNoop:
		var persisted noopSpecV1
		if err := codec.DecodeStrict(data, &persisted); err != nil {
			return nil, fmt.Errorf("decode noop action spec v1: %w", err)
		}

		return &eventrule.Noop{Reason: persisted.Reason}, nil
	default:
		return nil, fmt.Errorf("unknown action type %q", actionType)
	}
}
