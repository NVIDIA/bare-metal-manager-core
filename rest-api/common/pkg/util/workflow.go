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
	// interval, where clock skew between the Site and REST layer decides the outcome.
	StaleInventoryBuffer = 10 * time.Second
	// MaxInventoryReceiptInterval is the slowest inventory collection the system supports. REST
	// layer waits out the reported interval before acting on an object, so a slower Site would
	// hold off deletions and status updates long enough to destabilize it. The Site Agent rejects
	// a schedule past this at config load rather than run in that state.
	MaxInventoryReceiptInterval = 5 * time.Minute
	// WorkflowExecutionTimeout is the timeout for a workflow execution
	WorkflowExecutionTimeout = time.Minute * 1
	// WorkflowContextTimeout is the timeout for a workflow context
	WorkflowContextTimeout = time.Second * 50
	// WorkflowContextNewAfterTimeout is the timeout for a new workflow context
	WorkflowContextNewAfterTimeout = time.Second * 5
)
