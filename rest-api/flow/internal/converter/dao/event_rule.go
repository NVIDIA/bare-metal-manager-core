// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"fmt"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/policycodec"
	"github.com/google/uuid"
)

// EventRuleTo converts a domain rule to a database model.
func EventRuleTo(rule *eventrule.Rule) (*dbmodel.EventRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, err
	}

	if rule.Origin != eventrule.RuleOriginPersisted {
		return nil, fmt.Errorf(
			"persisted event rule origin must be %q",
			eventrule.RuleOriginPersisted,
		)
	}

	policy, err := policycodec.Marshal(rule.Policy)
	if err != nil {
		return nil, err
	}

	return &dbmodel.EventRule{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		Enabled:     rule.Enabled,
		EventType:   string(rule.EventType),
		Policy:      policy,
		CreatedAt:   rule.CreatedAt,
		UpdatedAt:   rule.UpdatedAt,
	}, nil
}

// EventRuleFrom converts a database model to a domain rule.
func EventRuleFrom(dbRule *dbmodel.EventRule) (*eventrule.Rule, error) {
	if dbRule == nil {
		return nil, nil
	}

	policy, err := policycodec.Unmarshal(dbRule.Policy)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: decode policy: %w",
			eventrule.ErrInvalidPersistedRule,
			err,
		)
	}

	rule := &eventrule.Rule{
		ID:          dbRule.ID,
		Origin:      eventrule.RuleOriginPersisted,
		Name:        dbRule.Name,
		Description: dbRule.Description,
		Enabled:     dbRule.Enabled,
		EventType:   eventrule.Type(dbRule.EventType),
		Policy:      policy,
		CreatedAt:   dbRule.CreatedAt,
		UpdatedAt:   dbRule.UpdatedAt,
	}

	if err := rule.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", eventrule.ErrInvalidPersistedRule, err)
	}

	return rule, nil
}

// EventRuleBindingTo converts a domain binding to a database model.
func EventRuleBindingTo(
	binding eventrule.Binding,
	createdAt time.Time,
	updatedAt time.Time,
) (*dbmodel.EventRuleBinding, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}

	var scopeID *uuid.UUID
	if binding.Scope.HasID() {
		id := binding.Scope.ID
		scopeID = &id
	}

	return &dbmodel.EventRuleBinding{
		ID:        binding.ID,
		RuleID:    binding.RuleID,
		EventType: string(binding.EventType),
		ScopeType: string(binding.Scope.Type),
		ScopeID:   scopeID,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

// EventRuleBindingFrom converts a database model to a domain binding.
func EventRuleBindingFrom(
	dbBinding *dbmodel.EventRuleBinding,
) (*eventrule.Binding, error) {
	if dbBinding == nil {
		return nil, nil
	}

	var scopeID uuid.UUID
	if dbBinding.ScopeID != nil {
		scopeID = *dbBinding.ScopeID
	}

	binding := &eventrule.Binding{
		ID:        dbBinding.ID,
		RuleID:    dbBinding.RuleID,
		EventType: eventrule.Type(dbBinding.EventType),
		Scope: eventrule.Scope{
			Type: eventrule.ScopeType(dbBinding.ScopeType),
			ID:   scopeID,
		},
	}

	if err := binding.Validate(); err != nil {
		return nil, fmt.Errorf("decode persisted event rule binding: %w", err)
	}

	return binding, nil
}
