// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInventoryIntervalFromSchedule(t *testing.T) {
	tests := []struct {
		name     string
		schedule string
		want     time.Duration
		wantErr  bool
	}{
		{
			name:     "every minute descriptor, the co-located Site setting",
			schedule: "@every 1m",
			want:     time.Minute,
		},
		{
			name:     "every three minutes descriptor, the chart default",
			schedule: "@every 3m",
			want:     3 * time.Minute,
		},
		{
			name:     "sub-minute descriptor",
			schedule: "@every 30s",
			want:     30 * time.Second,
		},
		{
			name:     "five field expression",
			schedule: "*/5 * * * *",
			want:     5 * time.Minute,
		},
		{
			name:     "hourly descriptor",
			schedule: "@hourly",
			want:     time.Hour,
		},
		{
			// Uneven gaps alternate between 8 and 16 hours. Reporting the shorter one would
			// have Cloud call fresh data stale, so the longer gap is the answer.
			name:     "uneven gaps report the longest",
			schedule: "0 9,17 * * *",
			want:     16 * time.Hour,
		},
		{
			name:     "daily expression",
			schedule: "0 0 * * *",
			want:     24 * time.Hour,
		},
		{
			name:     "weekly expression",
			schedule: "0 9 * * 1",
			want:     7 * 24 * time.Hour,
		},
		{
			name:     "unparseable schedule",
			schedule: "not-a-schedule",
			wantErr:  true,
		},
		{
			name:     "empty schedule",
			schedule: "",
			wantErr:  true,
		},
		{
			// Six fields include seconds, which Temporal does not accept, so neither do we.
			name:     "six field expression is rejected",
			schedule: "0 */5 * * * *",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InventoryIntervalFromSchedule(tt.schedule)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Zero(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
