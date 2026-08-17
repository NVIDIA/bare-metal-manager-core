// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDedupe_Clone(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var nilDedupe *Dedupe
		require.Nil(t, nilDedupe.Clone())
	})

	t.Run("configured policy", func(t *testing.T) {
		dedupe := &Dedupe{Window: time.Minute}
		cloned := dedupe.Clone()
		require.Equal(t, dedupe, cloned)
		require.NotSame(t, dedupe, cloned)
	})
}

func TestDedupe_WithinWindow(t *testing.T) {
	firstClaimedAt := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		dedupe     *Dedupe
		observedAt time.Time
		want       bool
	}{
		"nil policy": {
			observedAt: firstClaimedAt,
		},
		"at first claim": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt,
			want:       true,
		},
		"immediately before first claim": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(-time.Nanosecond),
		},
		"far before first claim": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(-24 * time.Hour),
		},
		"inside window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(time.Minute - time.Nanosecond),
			want:       true,
		},
		"at window boundary": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(time.Minute),
		},
		"outside window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: firstClaimedAt.Add(time.Minute + time.Nanosecond),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(
				t,
				test.want,
				test.dedupe.WithinWindow(firstClaimedAt, test.observedAt),
			)
		})
	}
}
