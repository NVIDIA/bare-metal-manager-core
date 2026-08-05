// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package flowproxy

import (
	"testing"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestTimeoutLadder(t *testing.T) {
	require.Less(t, ActivityStartToCloseTimeout, WorkflowExecutionTimeout)

	// The caller must outlast the workflow so a terminal workflow result is
	// observed rather than reported as a client-side timeout.
	require.Less(t, WorkflowExecutionTimeout, cutil.WorkflowContextTimeout)
}
