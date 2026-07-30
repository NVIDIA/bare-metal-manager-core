// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package dao

import (
	"testing"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEventRuleRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	rule := &eventrule.Rule{
		ID:          uuid.New(),
		Origin:      eventrule.RuleOriginPersisted,
		Name:        "test",
		Description: "description",
		Enabled:     true,
		EventType:   "test.event",
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}

	dbRule, err := EventRuleTo(rule)
	require.NoError(t, err)
	roundTripped, err := EventRuleFrom(dbRule)
	require.NoError(t, err)
	require.Equal(t, rule, roundTripped)
}

func TestEventRuleBindingRoundTrip(t *testing.T) {
	scopes := map[string]eventrule.Scope{
		"site": {Type: eventrule.ScopeTypeSite},
		"rack": {Type: eventrule.ScopeTypeRack, ID: uuid.New()},
	}
	for name, scope := range scopes {
		t.Run(name, func(t *testing.T) {
			binding := eventrule.Binding{
				ID:        uuid.New(),
				RuleID:    uuid.New(),
				EventType: "test.event",
				Scope:     scope,
			}
			now := time.Now().UTC()
			dbBinding, err := EventRuleBindingTo(binding, now, now)
			require.NoError(t, err)
			roundTripped, err := EventRuleBindingFrom(dbBinding)
			require.NoError(t, err)
			require.Equal(t, &binding, roundTripped)
		})
	}
}

func TestEventRuleBindingFromRejectsInvalidModel(t *testing.T) {
	dbBinding := &dbmodel.EventRuleBinding{
		ID:        uuid.New(),
		RuleID:    uuid.New(),
		EventType: "test.event",
		ScopeType: string(eventrule.ScopeTypeRack),
	}
	_, err := EventRuleBindingFrom(dbBinding)
	require.ErrorContains(t, err, "rack scope requires an id")
}
