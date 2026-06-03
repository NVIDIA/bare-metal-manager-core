// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/operations"
)

// TestExtractOverrideAssignmentCheck covers every branch of the
// extractOverrideAssignmentCheck helper. The helper bridges the parent /
// sub-action boundary inside the rule engine: a parent task carries its
// OverrideAssignmentCheck flag through to dynamically synthesised
// PowerControl, FirmwareControl, and BringUp sub-actions. The helper is
// intentionally type-agnostic — the workflow runtime hands it either a
// concrete TaskInfo, a pointer to one, or a JSON-deserialised
// map[string]any from a child-workflow boundary — so all of those shapes
// must extract the flag, and an unrecognised or nil input must fall back
// to false to keep the safety gate engaged by default.
func TestExtractOverrideAssignmentCheck(t *testing.T) {
	t.Run("nil returns false", func(t *testing.T) {
		assert.False(t, extractOverrideAssignmentCheck(nil))
	})

	t.Run("nil typed pointers return false", func(t *testing.T) {
		var pc *operations.PowerControlTaskInfo
		var fw *operations.FirmwareControlTaskInfo
		var bu *operations.BringUpTaskInfo
		assert.False(t, extractOverrideAssignmentCheck(pc))
		assert.False(t, extractOverrideAssignmentCheck(fw))
		assert.False(t, extractOverrideAssignmentCheck(bu))
	})

	t.Run("PowerControlTaskInfo pointer", func(t *testing.T) {
		info := &operations.PowerControlTaskInfo{OverrideAssignmentCheck: true}
		assert.True(t, extractOverrideAssignmentCheck(info))
		info.OverrideAssignmentCheck = false
		assert.False(t, extractOverrideAssignmentCheck(info))
	})

	t.Run("PowerControlTaskInfo value", func(t *testing.T) {
		info := operations.PowerControlTaskInfo{OverrideAssignmentCheck: true}
		assert.True(t, extractOverrideAssignmentCheck(info))
	})

	t.Run("FirmwareControlTaskInfo pointer and value", func(t *testing.T) {
		assert.True(t, extractOverrideAssignmentCheck(&operations.FirmwareControlTaskInfo{
			OverrideAssignmentCheck: true,
		}))
		assert.True(t, extractOverrideAssignmentCheck(operations.FirmwareControlTaskInfo{
			OverrideAssignmentCheck: true,
		}))
	})

	t.Run("BringUpTaskInfo pointer and value", func(t *testing.T) {
		assert.True(t, extractOverrideAssignmentCheck(&operations.BringUpTaskInfo{
			OverrideAssignmentCheck: true,
		}))
		assert.True(t, extractOverrideAssignmentCheck(operations.BringUpTaskInfo{
			OverrideAssignmentCheck: true,
		}))
	})

	t.Run("map shape from child-workflow JSON round-trip", func(t *testing.T) {
		// Temporal serialises child-workflow arguments through JSON; on
		// receipt the typed TaskInfo struct degrades to a map[string]any
		// keyed by JSON tag. The helper must still recover the flag.
		assert.True(t, extractOverrideAssignmentCheck(map[string]any{
			"override_assignment_check": true,
		}))
		assert.False(t, extractOverrideAssignmentCheck(map[string]any{
			"override_assignment_check": false,
		}))
		assert.False(t, extractOverrideAssignmentCheck(map[string]any{
			"some_other_key": "value",
		}))
	})

	t.Run("unrecognised struct falls through JSON probe", func(t *testing.T) {
		// Anonymous struct with the matching JSON tag should still
		// be readable via the marshal/unmarshal fallback.
		type customInfo struct {
			OverrideAssignmentCheck bool `json:"override_assignment_check"`
		}
		assert.True(t, extractOverrideAssignmentCheck(customInfo{OverrideAssignmentCheck: true}))
	})

	t.Run("non-marshalable value returns false", func(t *testing.T) {
		// A channel is not JSON-marshalable; the helper must return
		// false rather than panic.
		assert.False(t, extractOverrideAssignmentCheck(make(chan int)))
	})
}
