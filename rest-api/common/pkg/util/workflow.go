// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import "time"

const (
	// InventoryReceiptInterval is the interval between 2 subsequent inventory receipts
	InventoryReceiptInterval = 3 * time.Minute
	// WorkflowExecutionTimeout is the timeout for a workflow execution
	WorkflowExecutionTimeout = time.Minute * 1
	// WorkflowContextTimeout is the timeout for a workflow context
	WorkflowContextTimeout = time.Second * 50
	// WorkflowContextNewAfterTimeout is the timeout for a new workflow context
	WorkflowContextNewAfterTimeout = time.Second * 5
)
