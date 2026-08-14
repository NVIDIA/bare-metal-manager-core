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
	storetest.RunExecutionContract(t, func() eventrule.ExecutionStore {
		return New()
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

func TestStore_ClaimRejectsDanglingIndexes(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*Store, eventrule.ExecutionClaim){
		"delivery": func(store *Store, claim eventrule.ExecutionClaim) {
			store.executionsByDelivery[claim.DeliveryKey()] = uuid.New()
		},
		"semantic": func(store *Store, claim eventrule.ExecutionClaim) {
			store.executionsBySemantic[claim.SemanticKey()] = []uuid.UUID{uuid.New()}
		},
	}

	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			store := New()
			claim := eventrule.ExecutionClaim{
				EventID:        uuid.New(),
				RuleID:         uuid.New(),
				ActionID:       "action",
				CorrelationKey: "incident-1",
				Dedupe:         &eventrule.Dedupe{Window: time.Minute},
				Now:            now,
			}
			corrupt(store, claim)

			execution, err := store.Claim(context.Background(), claim)
			require.ErrorIs(t, err, eventrule.ErrExecutionNotFound)
			require.Nil(t, execution)
		})
	}
}
