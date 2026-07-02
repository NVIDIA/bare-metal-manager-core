// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"testing"

	"github.com/stretchr/testify/require"

	operationrun "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun"
)

func TestSafetyGateTrippedMessageIncludesRateThreshold(t *testing.T) {
	got := safetyGateTrippedMessage(
		&operationrun.FailureRateGate{
			Scope:                   operationrun.SafetyGateScopeCumulativeRun,
			FailureThresholdPercent: 25,
		},
		safetyGateStats{
			failed: 2,
			total:  5,
		},
	)

	require.Equal(
		t,
		"failure_rate safety gate tripped for cumulative_run: 2/5 targets failed (40%, threshold 25%)",
		got,
	)
}
