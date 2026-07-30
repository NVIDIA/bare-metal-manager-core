// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestBindingValidateRequiresEventType(t *testing.T) {
	binding := Binding{
		ID:     uuid.New(),
		RuleID: uuid.New(),
		Scope:  Scope{Type: ScopeTypeSite},
	}

	require.ErrorContains(t, binding.Validate(), "event rule binding event type")

	binding.EventType = "test.event"
	require.NoError(t, binding.Validate())
}
