// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// DriftType represents the type of drift detected for a component.
type DriftType string

const (
	// DriftTypeMissingInExpected means the component exists in the source system
	// but is NOT in the local DB (component table).
	DriftTypeMissingInExpected DriftType = "missing_in_expected"

	// DriftTypeMissingInActual means the component exists in the local DB
	// but was NOT found in the source system.
	DriftTypeMissingInActual DriftType = "missing_in_actual"

	// DriftTypeMismatch means the component exists in both the local DB
	// and the source system, but some validation fields have different values.
	DriftTypeMismatch DriftType = "mismatch"
)

// FieldDiff represents a single field difference between expected and actual values.
type FieldDiff struct {
	FieldName     string `json:"field_name"`
	ExpectedValue string `json:"expected_value"`
	ActualValue   string `json:"actual_value"`
}

// ComponentDrift stores validation drift detected by the inventory loop.
// Each row represents one drift record between expected (component table)
// and actual (source system) data.
type ComponentDrift struct {
	bun.BaseModel `bun:"table:component_drift,alias:cd"`

	ID          uuid.UUID   `bun:"id,pk,type:uuid,default:gen_random_uuid()"`
	ComponentID *uuid.UUID  `bun:"component_id,type:uuid"` // NULL for missing_in_expected
	ExternalID  *string     `bun:"external_id"`            // Component ID from the component manager service; NULL for missing_in_actual
	DriftType   DriftType   `bun:"drift_type,type:varchar(32),notnull"`
	Diffs       []FieldDiff `bun:"diffs,type:jsonb,notnull,default:'[]'"`
	CheckedAt   time.Time   `bun:"checked_at,notnull,default:current_timestamp"`
}

// ReplaceAllDrifts replaces all component_drift rows with the given set.
// This is called once per inventory loop cycle to overwrite stale data.
func ReplaceAllDrifts(ctx context.Context, idb bun.IDB, drifts []ComponentDrift) error {
	// Delete all existing drift records
	if _, err := idb.NewDelete().Model((*ComponentDrift)(nil)).Where("TRUE").Exec(ctx); err != nil {
		return err
	}

	// Insert new drift records (if any)
	if len(drifts) > 0 {
		if _, err := idb.NewInsert().Model(&drifts).Exec(ctx); err != nil {
			return err
		}
	}

	return nil
}

// GetDriftsByComponentIDs retrieves drift records for the given component UUIDs.
func GetDriftsByComponentIDs(ctx context.Context, idb bun.IDB, componentIDs []uuid.UUID) ([]ComponentDrift, error) {
	var drifts []ComponentDrift
	err := idb.NewSelect().
		Model(&drifts).
		Where("component_id IN (?)", bun.In(componentIDs)).
		Scan(ctx)
	return drifts, err
}

// GetAllDrifts retrieves all drift records.
func GetAllDrifts(ctx context.Context, idb bun.IDB) ([]ComponentDrift, error) {
	var drifts []ComponentDrift
	err := idb.NewSelect().Model(&drifts).Scan(ctx)
	return drifts, err
}
