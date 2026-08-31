// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	eventrulecodec "github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/codec"
	"github.com/google/uuid"
)

// GetByID returns one persisted rule.
func (s *Store) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*eventrule.Rule, error) {
	var record dbmodel.EventRule
	err := s.pg.DB.NewSelect().
		Model(&record).
		Where("er.id = ?", id).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}
	if err != nil {
		return nil, err
	}

	return converterdao.EventRuleFrom(&record)
}

// List returns persisted rules matching the filter in stable ID order.
func (s *Store) List(
	ctx context.Context,
	filter eventrule.RuleFilter,
) ([]*eventrule.Rule, error) {
	if !filter.IncludesOrigin(eventrule.RuleOriginPersisted) {
		return nil, nil
	}

	var records []dbmodel.EventRule
	query := s.pg.DB.NewSelect().Model(&records)
	if filter.EventType != nil {
		query = query.Where("er.event_type = ?", string(*filter.EventType))
	}
	if filter.Enabled != nil {
		query = query.Where("er.enabled = ?", *filter.Enabled)
	}

	if err := query.OrderExpr("er.id ASC").Scan(ctx); err != nil {
		return nil, err
	}

	rules := make([]*eventrule.Rule, len(records))
	for i := range records {
		rule, err := converterdao.EventRuleFrom(&records[i])
		if err != nil {
			return nil, err
		}

		rules[i] = rule
	}

	return rules, nil
}

// Create stores a new persisted rule using database-owned timestamps.
func (s *Store) Create(
	ctx context.Context,
	rule *eventrule.Rule,
) (*eventrule.Rule, error) {
	if rule == nil {
		return nil, fmt.Errorf("event rule is nil")
	}

	record, err := converterdao.EventRuleTo(rule)
	if err != nil {
		return nil, err
	}

	err = s.pg.DB.NewInsert().
		Model(record).
		Column("id", "name", "description", "enabled", "event_type", "policy").
		Returning("*").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return converterdao.EventRuleFrom(record)
}

// UpdateMetadata updates one persisted rule's descriptive fields.
func (s *Store) UpdateMetadata(
	ctx context.Context,
	id uuid.UUID,
	metadata eventrule.RuleMetadata,
) error {
	if err := metadata.Validate(); err != nil {
		return err
	}

	return s.updateRule(
		ctx,
		id,
		"name = ?, description = ?",
		metadata.Name,
		metadata.Description,
	)
}

// ReplaceActions replaces all actions belonging to one persisted rule.
func (s *Store) ReplaceActions(
	ctx context.Context,
	id uuid.UUID,
	actions []eventrule.Action,
) error {
	if err := eventrule.ValidateActions(actions); err != nil {
		return err
	}

	policy, err := eventrulecodec.MarshalPolicy(eventrule.Policy{
		Actions: eventrule.CloneActions(actions),
	})
	if err != nil {
		return err
	}

	return s.updateRule(ctx, id, "policy = ?", policy)
}

// Delete atomically deletes a persisted rule and its cascading bindings.
func (s *Store) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := s.pg.DB.NewDelete().
		Model((*dbmodel.EventRule)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return err
	}

	if err := requireRuleMutation(result, id); err != nil {
		return err
	}

	return nil
}

// SetEnabled changes one persisted rule's enabled state.
func (s *Store) SetEnabled(
	ctx context.Context,
	id uuid.UUID,
	enabled bool,
) error {
	return s.updateRule(ctx, id, "enabled = ?", enabled)
}

func (s *Store) updateRule(
	ctx context.Context,
	id uuid.UUID,
	assignment string,
	args ...any,
) error {
	now, err := s.timestamp(ctx, s.pg.DB)
	if err != nil {
		return err
	}

	query := s.pg.DB.NewUpdate().
		Model((*dbmodel.EventRule)(nil)).
		Set(assignment, args...).
		Set("updated_at = ?", now).
		Where("id = ?", id)

	result, err := query.Exec(ctx)
	if err != nil {
		return err
	}

	if err := requireRuleMutation(result, id); err != nil {
		return err
	}

	return nil
}

func requireRuleMutation(result sql.Result, id uuid.UUID) error {
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return fmt.Errorf("%w: %s", eventrule.ErrRuleNotFound, id)
	}

	return nil
}
