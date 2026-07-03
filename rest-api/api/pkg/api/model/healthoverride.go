// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"fmt"
	"time"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	MachineHealthReportModeMerge   = "Merge"
	MachineHealthReportModeReplace = "Replace"
)

var MachineHealthReportModes = []string{
	MachineHealthReportModeMerge,
	MachineHealthReportModeReplace,
}

var machineHealthReportModesAny = func() []interface{} {
	result := make([]interface{}, len(MachineHealthReportModes))
	for i, mode := range MachineHealthReportModes {
		result[i] = mode
	}
	return result
}()

type APIMachineHealthReportEntry struct {
	Source      string                         `json:"source"`
	TriggeredBy *string                        `json:"triggeredBy"`
	ObservedAt  *string                        `json:"observedAt"`
	Successes   []APIMachineHealthProbeSuccess `json:"successes"`
	Alerts      []APIMachineHealthProbeAlert   `json:"alerts"`
	Mode        string                         `json:"mode"`
}

func (amhre *APIMachineHealthReportEntry) FromProto(entry *cwssaws.HealthReportEntry) {
	amhre.Source = entry.GetReport().GetSource()
	amhre.TriggeredBy = cutil.GetPtr(entry.GetReport().GetTriggeredBy())
	amhre.ObservedAt = stringFromProtoTime(entry.GetReport().GetObservedAt())
	amhre.Successes = successesFromProto(entry.GetReport().GetSuccesses())
	amhre.Alerts = alertsFromProto(entry.GetReport().GetAlerts())
	amhre.Mode = machineHealthReportModeFromProto(entry.GetMode())
}

type APIMachineHealthReportEntryRequest struct {
	Source    string                         `json:"source"`
	Successes []APIMachineHealthProbeSuccess `json:"successes"`
	Alerts    []APIMachineHealthProbeAlert   `json:"alerts"`
	Mode      string                         `json:"mode"`
}

func (r *APIMachineHealthReportEntryRequest) Validate() error {
	err := validation.ValidateStruct(r,
		validation.Field(&r.Source, validation.Required.Error(validationErrorValueRequired)),
		validation.Field(&r.Mode,
			validation.Required.Error(validationErrorValueRequired),
			validation.In(machineHealthReportModesAny...).Error(fmt.Sprintf("must be one of %v", MachineHealthReportModes))),
	)

	if err != nil {
		return err
	}

	for i := range r.Successes {
		err = validation.ValidateStruct(&r.Successes[i],
			validation.Field(&r.Successes[i].ID, validation.Required.Error(validationErrorValueRequired)),
		)
		if err != nil {
			return validation.Errors{
				"successes": fmt.Errorf("invalid entry at index %d: %w", i, err),
			}
		}
	}
	for i := range r.Alerts {
		err = validation.ValidateStruct(&r.Alerts[i],
			validation.Field(&r.Alerts[i].ID, validation.Required.Error(validationErrorValueRequired)),
			validation.Field(&r.Alerts[i].Message, validation.Required.Error(validationErrorValueRequired)),
		)
		if err != nil {
			return validation.Errors{
				"alerts": fmt.Errorf("invalid entry at index %d: %w", i, err),
			}
		}
	}
	return nil
}

func (r *APIMachineHealthReportEntryRequest) ToProto(machineID string, userID string) *cwssaws.InsertMachineHealthReportRequest {
	request := &cwssaws.InsertMachineHealthReportRequest{
		MachineId: &cwssaws.MachineId{Id: machineID},
		HealthReportEntry: &cwssaws.HealthReportEntry{
			Report: &cwssaws.HealthReport{
				Source:      r.Source,
				TriggeredBy: &userID,
				ObservedAt:  timestamppb.New(time.Now()),
				Successes:   successesToProto(r.Successes),
				Alerts:      alertsToProto(r.Alerts),
			},
			Mode: healthReportModeToProto(r.Mode),
		},
	}

	return request
}

func NewMachineIDProto(machineID string) *cwssaws.MachineId {
	return &cwssaws.MachineId{Id: machineID}
}

func NewRemoveMachineHealthReportProto(machineID, source string) *cwssaws.RemoveMachineHealthReportRequest {
	return &cwssaws.RemoveMachineHealthReportRequest{
		MachineId: NewMachineIDProto(machineID),
		Source:    source,
	}
}

func healthReportModeToProto(mode string) cwssaws.HealthReportApplyMode {
	switch mode {
	case MachineHealthReportModeReplace:
		return cwssaws.HealthReportApplyMode_Replace
	default:
		return cwssaws.HealthReportApplyMode_Merge
	}
}

func machineHealthReportModeFromProto(mode cwssaws.HealthReportApplyMode) string {
	switch mode {
	case cwssaws.HealthReportApplyMode_Replace:
		return MachineHealthReportModeReplace
	default:
		return MachineHealthReportModeMerge
	}
}

func successesToProto(successes []APIMachineHealthProbeSuccess) []*cwssaws.HealthProbeSuccess {
	out := make([]*cwssaws.HealthProbeSuccess, 0, len(successes))
	for _, success := range successes {
		out = append(out, &cwssaws.HealthProbeSuccess{
			Id:     success.ID,
			Target: success.Target,
		})
	}
	return out
}

func alertsToProto(alerts []APIMachineHealthProbeAlert) []*cwssaws.HealthProbeAlert {
	out := make([]*cwssaws.HealthProbeAlert, 0, len(alerts))
	for _, alert := range alerts {
		out = append(out, &cwssaws.HealthProbeAlert{
			Id:              alert.ID,
			Target:          alert.Target,
			InAlertSince:    stringToProtoTime(alert.InAlertSince),
			Message:         alert.Message,
			TenantMessage:   alert.TenantMessage,
			Classifications: alert.Classifications,
		})
	}
	return out
}

func machineHealthReportEntryFromProto(entry *cwssaws.HealthReportEntry) APIMachineHealthReportEntry {
	apiEntry := APIMachineHealthReportEntry{
		Mode: machineHealthReportModeFromProto(entry.GetMode()),
	}
	report := entry.GetReport()
	if report == nil {
		return apiEntry
	}
	apiEntry.Source = report.GetSource()
	apiEntry.TriggeredBy = report.TriggeredBy
	apiEntry.ObservedAt = stringFromProtoTime(report.GetObservedAt())
	apiEntry.Successes = successesFromProto(report.GetSuccesses())
	apiEntry.Alerts = alertsFromProto(report.GetAlerts())
	return apiEntry
}

func successesFromProto(successes []*cwssaws.HealthProbeSuccess) []APIMachineHealthProbeSuccess {
	out := make([]APIMachineHealthProbeSuccess, 0, len(successes))
	for _, success := range successes {
		out = append(out, APIMachineHealthProbeSuccess{
			ID:     success.GetId(),
			Target: success.Target,
		})
	}
	return out
}

func alertsFromProto(alerts []*cwssaws.HealthProbeAlert) []APIMachineHealthProbeAlert {
	out := make([]APIMachineHealthProbeAlert, 0, len(alerts))
	for _, alert := range alerts {
		out = append(out, APIMachineHealthProbeAlert{
			ID:              alert.GetId(),
			Target:          alert.Target,
			InAlertSince:    stringFromProtoTime(alert.GetInAlertSince()),
			Message:         alert.GetMessage(),
			TenantMessage:   alert.TenantMessage,
			Classifications: alert.GetClassifications(),
		})
	}
	return out
}

func validateOptionalRFC3339(value *string, field string) error {
	if value == nil {
		return nil
	}
	if *value == "" {
		return fmt.Errorf("%s must be RFC3339 timestamp", field)
	}
	if _, err := time.Parse(time.RFC3339Nano, *value); err != nil {
		return fmt.Errorf("%s must be RFC3339 timestamp: %w", field, err)
	}
	return nil
}

func stringToProtoTime(value *string) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *value)
	if err != nil {
		return nil
	}
	return timestamppb.New(t)
}

func stringFromProtoTime(t *timestamppb.Timestamp) *string {
	if t == nil {
		return nil
	}
	out := t.AsTime().Format(time.RFC3339Nano)
	return &out
}
