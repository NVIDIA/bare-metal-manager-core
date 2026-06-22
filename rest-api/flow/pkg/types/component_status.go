// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// ComponentOperationStatus is Flow's view of a component's operability. It is
// derived from a source-specific state machine (today: Core's per-type
// controller state, mapped in internal/nicoapi) and recomputed on every
// inventory sync. Only the type lives here; mappers belong with the
// source whose raw values they decode.
type ComponentOperationStatus struct {
	Phase             Phase           `json:"phase"`
	Reason            string          `json:"reason,omitempty"`
	BlockedOperations []OperationType `json:"blocked_operations,omitempty"`
}

// IsReady returns true when the component is in Ready phase with no
// blocked operations of interest. It is a convenience for callers that
// only need a boolean go/no-go.
func (s ComponentOperationStatus) IsReady() bool {
	return s.Phase == PhaseReady && len(s.BlockedOperations) == 0
}

// Blocks reports whether op is in BlockedOperations.
func (s ComponentOperationStatus) Blocks(op OperationType) bool {
	for _, b := range s.BlockedOperations {
		if b == op {
			return true
		}
	}
	return false
}

// Equal reports whether two ComponentOperationStatus values are identical. Needed
// because BlockedOperations is a slice and ComponentOperationStatus is therefore
// not comparable with ==.
func (s ComponentOperationStatus) Equal(other ComponentOperationStatus) bool {
	if s.Phase != other.Phase || s.Reason != other.Reason {
		return false
	}
	if len(s.BlockedOperations) != len(other.BlockedOperations) {
		return false
	}
	for i := range s.BlockedOperations {
		if s.BlockedOperations[i] != other.BlockedOperations[i] {
			return false
		}
	}
	return true
}
