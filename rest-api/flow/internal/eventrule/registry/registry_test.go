// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestNewRejectsInvalidAndDuplicateRules(t *testing.T) {
	valid := testRule(uuid.New(), "test.event")
	duplicateID := testRule(valid.ID, "other.event")
	duplicateType := testRule(uuid.New(), valid.EventType)
	persisted := testRule(uuid.New(), "persisted.event")
	persisted.Origin = eventrule.RuleOriginPersisted
	invalid := testRule(uuid.New(), "invalid.event")
	invalid.Actions = nil

	tests := map[string]struct {
		rules   []*eventrule.Rule
		wantErr string
	}{
		"invalid origin":       {rules: []*eventrule.Rule{persisted}, wantErr: "origin must be"},
		"invalid policy":       {rules: []*eventrule.Rule{invalid}, wantErr: "actions are required"},
		"duplicate id":         {rules: []*eventrule.Rule{valid, duplicateID}, wantErr: "duplicate id"},
		"duplicate event type": {rules: []*eventrule.Rule{valid, duplicateType}, wantErr: "duplicate event type"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := New(test.rules...)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

func TestRegistryLookup(t *testing.T) {
	rule := testRule(uuid.New(), "test.event")
	registry, err := New(rule)
	require.NoError(t, err)

	rule.Actions[0].ID = "changed-after-registration"

	byID, err := registry.GetByID(context.Background(), rule.ID)
	require.NoError(t, err)
	require.Equal(t, rule.ID, byID.ID)
	require.Equal(t, "noop", byID.Actions[0].ID)
	byID.Actions[0].ID = "changed"

	byType, err := registry.GetByEventType(context.Background(), rule.EventType)
	require.NoError(t, err)
	require.Equal(t, rule.ID, byType.ID)
	require.Equal(t, "noop", byType.Actions[0].ID)
}

func TestGetByEventTypeDetectsInconsistentRegistry(t *testing.T) {
	eventType := eventrule.Type("test.event")
	registry := &Registry{
		byID:        make(map[uuid.UUID]eventrule.Rule),
		byEventType: map[eventrule.Type]uuid.UUID{eventType: uuid.New()},
	}

	_, err := registry.GetByEventType(context.Background(), eventType)
	require.ErrorContains(t, err, "registry is inconsistent")
	require.False(t, errors.Is(err, eventrule.ErrRuleNotFound))
}

func testRule(id uuid.UUID, eventType eventrule.Type) *eventrule.Rule {
	return &eventrule.Rule{
		ID:        id,
		Origin:    eventrule.RuleOriginBuiltIn,
		Name:      "test",
		Enabled:   true,
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
}
