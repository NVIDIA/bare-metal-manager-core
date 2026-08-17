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
	createdAt := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := map[string]struct {
		dedupe     *Dedupe
		observedAt time.Time
		want       bool
	}{
		"nil policy": {
			observedAt: createdAt,
		},
		"at creation": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt,
			want:       true,
		},
		"immediately before creation": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(-time.Nanosecond),
		},
		"far before creation": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(-24 * time.Hour),
		},
		"inside window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(time.Minute - time.Nanosecond),
			want:       true,
		},
		"at window boundary": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(time.Minute),
		},
		"outside window": {
			dedupe:     &Dedupe{Window: time.Minute},
			observedAt: createdAt.Add(time.Minute + time.Nanosecond),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(
				t,
				test.want,
				test.dedupe.WithinWindow(createdAt, test.observedAt),
			)
		})
	}
}
