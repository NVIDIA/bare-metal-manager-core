// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import "time"

const (
	// DefaultInventoryReceiptInterval is the assumed interval between 2 subsequent inventory
	// receipts for a Site that has not reported its own collection interval. Prefer
	// Site.IsTimeWithinStaleInventoryThreshold, which follows the reported interval where there
	// is one.
	DefaultInventoryReceiptInterval = 3 * time.Minute
	// StaleInventoryBuffer keeps the staleness check from sitting exactly on the collection
	// interval, where clock skew between the Site and Cloud decides the outcome.
	StaleInventoryBuffer = 10 * time.Second
	// WorkflowExecutionTimeout is the timeout for a workflow execution
	WorkflowExecutionTimeout = time.Minute * 1
	// WorkflowContextTimeout is the timeout for a workflow context
	WorkflowContextTimeout = time.Second * 50
	// WorkflowContextNewAfterTimeout is the timeout for a new workflow context
	WorkflowContextNewAfterTimeout = time.Second * 5
)
