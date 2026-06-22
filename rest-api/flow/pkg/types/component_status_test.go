// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComponentOperationStatus_IsReady(t *testing.T) {
	assert.True(t, ComponentOperationStatus{Phase: PhaseReady}.IsReady())
	assert.False(t, ComponentOperationStatus{Phase: PhaseInUse}.IsReady())
	assert.False(t, ComponentOperationStatus{
		Phase:             PhaseReady,
		BlockedOperations: []OperationType{OperationTypePowerControl},
	}.IsReady())
}

func TestComponentOperationStatus_Blocks(t *testing.T) {
	s := ComponentOperationStatus{BlockedOperations: []OperationType{OperationTypeFirmwareControl}}
	assert.True(t, s.Blocks(OperationTypeFirmwareControl))
	assert.False(t, s.Blocks(OperationTypePowerControl))
}

func TestComponentOperationStatus_Equal(t *testing.T) {
	base := ComponentOperationStatus{
		Phase:             PhaseInUse,
		Reason:            "Assigned/Provisioning",
		BlockedOperations: []OperationType{OperationTypePowerControl, OperationTypeFirmwareControl},
	}
	same := ComponentOperationStatus{
		Phase:             PhaseInUse,
		Reason:            "Assigned/Provisioning",
		BlockedOperations: []OperationType{OperationTypePowerControl, OperationTypeFirmwareControl},
	}
	diffPhase := ComponentOperationStatus{Phase: PhaseReady, Reason: base.Reason, BlockedOperations: base.BlockedOperations}
	diffReason := ComponentOperationStatus{Phase: base.Phase, Reason: "other", BlockedOperations: base.BlockedOperations}
	diffOpsLen := ComponentOperationStatus{Phase: base.Phase, Reason: base.Reason, BlockedOperations: []OperationType{OperationTypePowerControl}}
	diffOpsOrder := ComponentOperationStatus{Phase: base.Phase, Reason: base.Reason, BlockedOperations: []OperationType{OperationTypeFirmwareControl, OperationTypePowerControl}}

	assert.True(t, base.Equal(same))
	assert.False(t, base.Equal(diffPhase))
	assert.False(t, base.Equal(diffReason))
	assert.False(t, base.Equal(diffOpsLen))
	assert.False(t, base.Equal(diffOpsOrder))
}
