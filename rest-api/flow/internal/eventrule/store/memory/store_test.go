// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"testing"
	"time"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStoreContract(t *testing.T) {
	storetest.RunRuleBindingContract(t, func() (eventrule.RuleStore, eventrule.BindingStore) {
		store := New()
		return store, store
	})
	storetest.RunExecutionContract(t, func(now *time.Time) eventrule.ExecutionStore {
		return NewWithClock(func() time.Time { return *now })
	})
}

func TestBindingScansIgnoreUnrelatedInvalidRecords(t *testing.T) {
	ctx := context.Background()
	store := New()
	invalidID := uuid.New()
	store.bindings[invalidID] = dbmodel.EventRuleBinding{
		ID:        invalidID,
		RuleID:    uuid.New(),
		EventType: "invalid",
		ScopeType: "invalid",
	}

	rule, err := store.Create(ctx, &eventrule.Rule{
		ID:        uuid.New(),
		Origin:    eventrule.RuleOriginPersisted,
		Name:      "test",
		EventType: "test.event",
		Policy: eventrule.Policy{Actions: []eventrule.Action{
			eventrule.NewAction("noop", eventrule.ActionCondition{}, eventrule.Noop{}),
		}},
	})
	require.NoError(t, err)

	scope := eventrule.Scope{Type: eventrule.ScopeTypeRack, ID: uuid.New()}
	binding := eventrule.Binding{
		ID:        uuid.New(),
		RuleID:    rule.ID,
		EventType: rule.EventType,
		Scope:     scope,
	}
	require.NoError(t, store.Bind(ctx, binding))

	found, err := store.GetForScope(ctx, rule.EventType, scope)
	require.NoError(t, err)
	require.Equal(t, &binding, found)
	require.NoError(t, store.Delete(ctx, rule.ID))
}

func TestStore_CreateExecutionRejectsDanglingIndexes(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*Store, eventrule.ExecutionIdentity){
		"delivery": func(store *Store, identity eventrule.ExecutionIdentity) {
			store.executionsByDelivery[identity.DeliveryKey()] = uuid.New()
		},
		"semantic": func(store *Store, identity eventrule.ExecutionIdentity) {
			store.executionsBySemantic[identity.SemanticKey()] = []uuid.UUID{uuid.New()}
		},
	}

	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			store := NewWithClock(func() time.Time { return now })
			identity := eventrule.ExecutionIdentity{
				EventID:        uuid.New(),
				RuleID:         uuid.New(),
				ActionID:       "action",
				CorrelationKey: "incident-1",
			}
			dedupe := &eventrule.Dedupe{Window: time.Minute}
			corrupt(store, identity)

			execution, err := store.CreateExecution(
				context.Background(),
				identity,
				dedupe,
			)
			require.ErrorIs(t, err, eventrule.ErrExecutionNotFound)
			require.Nil(t, execution)
		})
	}
}
