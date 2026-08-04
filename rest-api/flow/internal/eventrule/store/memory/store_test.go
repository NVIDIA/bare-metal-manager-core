// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"testing"

	dbmodel "github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/eventrule/store/storetest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStoreContract(t *testing.T) {
	storetest.RunContract(t, func() (eventrule.RuleStore, eventrule.BindingStore) {
		store := New()
		return store, store
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
