// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package operationrun

import (
	"testing"

	"github.com/stretchr/testify/require"

	taskcommon "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/common"
)

func TestOperationRunStatusIsTerminalIncludesCompletedWithFailures(t *testing.T) {
	require.True(t, OperationRunStatusCompletedWithFailures.IsTerminal())
}

func TestOperationRunTargetStatusFromTaskStatus(t *testing.T) {
	tests := []struct {
		name   string
		status taskcommon.TaskStatus
		want   OperationRunTargetStatus
	}{
		{
			name:   "completed",
			status: taskcommon.TaskStatusCompleted,
			want:   OperationRunTargetStatusCompleted,
		},
		{
			name:   "failed",
			status: taskcommon.TaskStatusFailed,
			want:   OperationRunTargetStatusFailed,
		},
		{
			name:   "terminated",
			status: taskcommon.TaskStatusTerminated,
			want:   OperationRunTargetStatusTerminated,
		},
		{
			name:   "non-terminal",
			status: taskcommon.TaskStatusRunning,
			want:   OperationRunTargetStatusSubmitted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(
				t,
				tt.want,
				OperationRunTargetStatusFromTaskStatus(tt.status),
			)
		})
	}
}
