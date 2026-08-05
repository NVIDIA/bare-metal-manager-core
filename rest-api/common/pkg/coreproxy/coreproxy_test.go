// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package coreproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTimeoutLadder(t *testing.T) {
	require.Less(t, ActivityStartToCloseTimeout, WorkflowExecutionTimeout)
}
