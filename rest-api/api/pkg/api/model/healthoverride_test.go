// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func healthOverrideStrPtr(s string) *string { return &s }

func TestAPIMachineHealthReportEntryRequestValidateAndToProto(t *testing.T) {
	inAlertSince := "2026-06-24T11:00:00Z"
	req := APIMachineHealthReportEntryRequest{
		Source: "overrides.sre",
		Mode:   MachineHealthReportModeReplace,
		Successes: []APIMachineHealthProbeSuccess{
			{ID: "probe.ok", Target: healthOverrideStrPtr("host")},
		},
		Alerts: []APIMachineHealthProbeAlert{
			{
				ID:              "probe.alert",
				Target:          healthOverrideStrPtr("gpu0"),
				InAlertSince:    &inAlertSince,
				Message:         "forced unhealthy",
				TenantMessage:   healthOverrideStrPtr("maintenance"),
				Classifications: []string{"maintenance"},
			},
		},
	}
	require.NoError(t, req.Validate())

	protoReq := req.ToProto("machine-1", "operator")
	assert.Equal(t, "machine-1", protoReq.GetMachineId().GetId())
	entry := protoReq.GetHealthReportEntry()
	require.NotNil(t, entry)
	assert.Equal(t, cwssaws.HealthReportApplyMode_Replace, entry.GetMode())
	report := entry.GetReport()
	require.NotNil(t, report)
	assert.Equal(t, "overrides.sre", report.GetSource())
	assert.Equal(t, "operator", report.GetTriggeredBy())
	assert.WithinDuration(t, time.Now(), report.GetObservedAt().AsTime(), time.Minute)
	require.Len(t, report.GetSuccesses(), 1)
	assert.Equal(t, "probe.ok", report.GetSuccesses()[0].GetId())
	require.Len(t, report.GetAlerts(), 1)
	assert.Equal(t, "probe.alert", report.GetAlerts()[0].GetId())
	assert.Equal(t, inAlertSince, report.GetAlerts()[0].GetInAlertSince().AsTime().Format(time.RFC3339))

	assert.Error(t, (&APIMachineHealthReportEntryRequest{Mode: MachineHealthReportModeMerge}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: "merge"}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: MachineHealthReportModeMerge, Successes: []APIMachineHealthProbeSuccess{{}}}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: MachineHealthReportModeMerge, Alerts: []APIMachineHealthProbeAlert{{ID: "alert"}}}).Validate())
}
