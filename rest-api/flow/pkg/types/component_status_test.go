// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComponentStatus_IsReady(t *testing.T) {
	assert.True(t, ComponentStatus{Phase: PhaseReady}.IsReady())
	assert.False(t, ComponentStatus{Phase: PhaseInUse}.IsReady())
	assert.False(t, ComponentStatus{
		Phase:             PhaseReady,
		BlockedOperations: []OperationType{OperationTypePowerControl},
	}.IsReady())
}

func TestComponentStatus_Blocks(t *testing.T) {
	s := ComponentStatus{BlockedOperations: []OperationType{OperationTypeFirmwareControl}}
	assert.True(t, s.Blocks(OperationTypeFirmwareControl))
	assert.False(t, s.Blocks(OperationTypePowerControl))
}

func TestComponentStatus_Equal(t *testing.T) {
	base := ComponentStatus{
		Phase:             PhaseInUse,
		Reason:            "Assigned/Provisioning",
		BlockedOperations: []OperationType{OperationTypePowerControl, OperationTypeFirmwareControl},
	}
	same := ComponentStatus{
		Phase:             PhaseInUse,
		Reason:            "Assigned/Provisioning",
		BlockedOperations: []OperationType{OperationTypePowerControl, OperationTypeFirmwareControl},
	}
	diffPhase := ComponentStatus{Phase: PhaseReady, Reason: base.Reason, BlockedOperations: base.BlockedOperations}
	diffReason := ComponentStatus{Phase: base.Phase, Reason: "other", BlockedOperations: base.BlockedOperations}
	diffOpsLen := ComponentStatus{Phase: base.Phase, Reason: base.Reason, BlockedOperations: []OperationType{OperationTypePowerControl}}
	diffOpsOrder := ComponentStatus{Phase: base.Phase, Reason: base.Reason, BlockedOperations: []OperationType{OperationTypeFirmwareControl, OperationTypePowerControl}}

	assert.True(t, base.Equal(same))
	assert.False(t, base.Equal(diffPhase))
	assert.False(t, base.Equal(diffReason))
	assert.False(t, base.Equal(diffOpsLen))
	assert.False(t, base.Equal(diffOpsOrder))
}
