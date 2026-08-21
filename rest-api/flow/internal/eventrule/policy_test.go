// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package eventrule

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicy_Clone(t *testing.T) {
	policy := Policy{Actions: []Action{{Name: "noop", Spec: &Noop{Reason: "test"}}}}
	cloned := policy.Clone()
	require.Equal(t, policy, cloned)
	require.NotSame(t, policy.Actions[0].Spec, cloned.Actions[0].Spec)
}
