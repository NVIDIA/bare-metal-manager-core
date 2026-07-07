// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

func TestAPIMachineHealthReportEntryRequestValidateAndToProto(t *testing.T) {
	inAlertSince := "2026-06-24T11:00:00Z"
	req := APIMachineHealthReportEntryRequest{
		Source: "overrides.sre",
		Mode:   MachineHealthReportModeReplace,
		Successes: []APIMachineHealthProbeSuccess{
			{ID: "probe.ok", Target: cutil.GetPtr("host")},
		},
		Alerts: []APIMachineHealthProbeAlert{
			{
				ID:              "probe.alert",
				Target:          cutil.GetPtr("gpu0"),
				InAlertSince:    &inAlertSince,
				Message:         "forced unhealthy",
				TenantMessage:   cutil.GetPtr("maintenance"),
				Classifications: []string{"maintenance"},
			},
		},
	}
	require.NoError(t, req.Validate())

	user := &cdbm.User{ID: uuid.New()}
	protoReq := req.ToProto("machine-1", user)
	assert.Equal(t, "machine-1", protoReq.GetMachineId().GetId())
	entry := protoReq.GetHealthReportEntry()
	require.NotNil(t, entry)
	assert.Equal(t, cwssaws.HealthReportApplyMode_Replace, entry.GetMode())
	report := entry.GetReport()
	require.NotNil(t, report)
	assert.Equal(t, "overrides.sre", report.GetSource())
	assert.Equal(t, user.ID.String(), report.GetTriggeredBy())
	assert.WithinDuration(t, time.Now(), report.GetObservedAt().AsTime(), time.Minute)
	require.Len(t, report.GetSuccesses(), 1)
	assert.Equal(t, "probe.ok", report.GetSuccesses()[0].GetId())
	require.Len(t, report.GetAlerts(), 1)
	assert.Equal(t, "probe.alert", report.GetAlerts()[0].GetId())
	assert.Equal(t, inAlertSince, report.GetAlerts()[0].GetInAlertSince().AsTime().Format(time.RFC3339))

	assert.Error(t, (&APIMachineHealthReportEntryRequest{Mode: MachineHealthReportModeMerge}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: MachineHealthReportMode("merge")}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: MachineHealthReportModeMerge, Successes: []APIMachineHealthProbeSuccess{{}}}).Validate())
	assert.Error(t, (&APIMachineHealthReportEntryRequest{Source: "source", Mode: MachineHealthReportModeMerge, Alerts: []APIMachineHealthProbeAlert{{ID: "alert"}}}).Validate())
}
