// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// EventActionExecution is the bun model for the event_action_executions table.
type EventActionExecution struct {
	bun.BaseModel `bun:"table:event_action_executions,alias:eae"`

	ID             uuid.UUID  `bun:"id,pk,type:uuid,default:gen_random_uuid()"`
	EventID        uuid.UUID  `bun:"event_id,type:uuid,notnull"`
	RuleID         uuid.UUID  `bun:"rule_id,type:uuid,notnull"`
	ActionID       string     `bun:"action_id,notnull"`
	CorrelationKey string     `bun:"correlation_key,notnull"`
	Status         string     `bun:"status,notnull"`
	Reason         string     `bun:"reason,notnull"`
	Observations   int        `bun:"observations,notnull"`
	Attempts       int        `bun:"attempts,notnull"`
	StatusMessage  string     `bun:"status_message,notnull"`
	FirstClaimedAt time.Time  `bun:"first_claimed_at,notnull"`
	UpdatedAt      time.Time  `bun:"updated_at,notnull"`
	NextAttemptAt  *time.Time `bun:"next_attempt_at"`
}
