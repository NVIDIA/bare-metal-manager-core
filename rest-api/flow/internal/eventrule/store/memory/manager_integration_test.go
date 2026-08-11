// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"testing"

	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/manager"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/registry"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerIntegration(t *testing.T) {
	ctx := context.Background()
	eventType := eventrule.Type("test.event")
	builtIn := integrationRule(uuid.New(), eventrule.RuleOriginBuiltIn, eventType)
	builtIns, err := registry.New(builtIn)
	require.NoError(t, err)
	store := New()
	ruleManager, err := manager.New(builtIns, store, store)
	require.NoError(t, err)

	site, err := ruleManager.Create(ctx, integrationCreate(eventType, "site"))
	require.NoError(t, err)
	_, err = ruleManager.Bind(ctx, site.ID, eventrule.Scope{Type: eventrule.ScopeTypeSite})
	require.NoError(t, err)

	effective, err := ruleManager.GetEffective(ctx, eventType, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, builtIn.ID, effective.ID)

	require.NoError(t, ruleManager.SetEnabled(ctx, site.ID, true))
	effective, err = ruleManager.GetEffective(ctx, eventType, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, site.ID, effective.ID)

	rackID := uuid.New()
	rack, err := ruleManager.Create(ctx, integrationCreate(eventType, "rack"))
	require.NoError(t, err)
	_, err = ruleManager.Bind(ctx, rack.ID, eventrule.Scope{
		Type: eventrule.ScopeTypeRack,
		ID:   rackID,
	})
	require.NoError(t, err)
	require.NoError(t, ruleManager.SetEnabled(ctx, rack.ID, true))

	effective, err = ruleManager.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, rack.ID, effective.ID)

	require.NoError(t, ruleManager.SetEnabled(ctx, rack.ID, false))
	effective, err = ruleManager.GetEffective(ctx, eventType, rackID)
	require.NoError(t, err)
	assert.Equal(t, site.ID, effective.ID)
}

func integrationCreate(eventType eventrule.Type, name string) eventrule.RuleCreate {
	return eventrule.RuleCreate{
		Metadata:  eventrule.RuleMetadata{Name: name},
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
}

func integrationRule(
	id uuid.UUID,
	origin eventrule.RuleOrigin,
	eventType eventrule.Type,
) *eventrule.Rule {
	return &eventrule.Rule{
		ID:        id,
		Origin:    origin,
		Name:      "built-in",
		Enabled:   true,
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
}
