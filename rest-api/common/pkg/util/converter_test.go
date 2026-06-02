// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntPtrToUint32Ptr(t *testing.T) {
	t.Run("nil in yields nil out", func(t *testing.T) {
		assert.Nil(t, IntPtrToUint32Ptr(nil))
	})

	cases := []struct {
		name string
		in   int
		want uint32
	}{
		{"zero", 0, 0},
		{"typical", 42, 42},
		{"max uint32", math.MaxUint32, math.MaxUint32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IntPtrToUint32Ptr(&tc.in)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}
}

func TestUint32PtrToIntPtr(t *testing.T) {
	t.Run("nil in yields nil out", func(t *testing.T) {
		assert.Nil(t, Uint32PtrToIntPtr(nil))
	})

	cases := []struct {
		name string
		in   uint32
		want int
	}{
		{"zero", 0, 0},
		{"typical", 42, 42},
		{"max uint32 fits in int on 64-bit", math.MaxUint32, math.MaxUint32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Uint32PtrToIntPtr(&tc.in)
			require.NotNil(t, got)
			assert.Equal(t, tc.want, *got)
		})
	}
}
