// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package processor

import (
	"context"
	"testing"

	converterdao "github.com/NVIDIA/infra-controller/rest-api/flow/internal/converter/dao"
	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/manager"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/registry"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/memory"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/deviceinfo"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/common/location"
	"github.com/NVIDIA/infra-controller/rest-api/flow/pkg/inventoryobjects/rack"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestProcessorPreparationIntegration(t *testing.T) {
	ctx := context.Background()
	eventType := eventrule.Type("test.event")
	rackID := uuid.New()
	builtIn := processorRule(uuid.New(), eventrule.RuleOriginBuiltIn, eventType)
	builtIns, err := registry.New(builtIn)
	require.NoError(t, err)
	store := memory.New()
	persisted := &malformedRuleStore{Store: store}
	ruleManager, err := manager.New(builtIns, persisted, store)
	require.NoError(t, err)

	rackRule, err := ruleManager.Create(ctx, processorCreate(eventType, "rack"))
	require.NoError(t, err)
	_, err = ruleManager.Bind(ctx, rackRule.ID, eventrule.Scope{
		Type: eventrule.ScopeTypeRack,
		ID:   rackID,
	})
	require.NoError(t, err)

	processor := newTestProcessor(
		t,
		&processorInventory{
			rack: rack.New(deviceinfo.DeviceInfo{ID: rackID}, location.Location{}),
		},
		ruleManager,
	)
	envelope := eventrule.Envelope{
		ID:       uuid.New(),
		Type:     eventType,
		Resource: eventrule.Resource{Kind: eventrule.ResourceKindRack, ID: rackID},
	}

	prepared, err := processor.prepare(ctx, envelope)
	require.NoError(t, err)
	require.Equal(t, rackID, prepared.Resource.RackID)
	require.Equal(t, builtIn.ID, prepared.Rule.ID)

	require.NoError(t, ruleManager.SetEnabled(ctx, rackRule.ID, true))
	prepared, err = processor.prepare(ctx, envelope)
	require.NoError(t, err)
	require.Equal(t, rackRule.ID, prepared.Rule.ID)

	persisted.malformedID = rackRule.ID
	_, err = processor.prepare(ctx, envelope)
	require.ErrorIs(t, err, ErrTerminal)
	require.ErrorIs(t, err, eventrule.ErrInvalidPersistedRule)
}

type malformedRuleStore struct {
	*memory.Store
	malformedID uuid.UUID
}

func (s *malformedRuleStore) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*eventrule.Rule, error) {
	if id == s.malformedID {
		return converterdao.EventRuleFrom(&dbmodel.EventRule{
			ID:        id,
			Name:      "malformed",
			EventType: "test.event",
			Policy:    []byte(`{"version": 999}`),
		})
	}
	return s.Store.GetByID(ctx, id)
}

func processorCreate(eventType eventrule.Type, name string) eventrule.RuleCreate {
	return eventrule.RuleCreate{
		Metadata:  eventrule.RuleMetadata{Name: name},
		EventType: eventType,
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	}
}

func processorRule(
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
