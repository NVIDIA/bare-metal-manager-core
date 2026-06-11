// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/uptrace/bun"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
)

// runInventoryOne is a single iteration of the inventory sync job. Order:
//
//  1. syncExpectedFromCore mirrors Core's expected inventory into Flow's
//     rack / component tables (the "expected" half of the package — see
//     expected_mirror*.go). Gated by expectedSyncEnabled; when false the
//     step is skipped entirely and Flow's existing ingestion path is the
//     sole writer to rack / component.
//  2. runActualSync reconciles each component type against Core's runtime
//     view and returns one combined drift set (the "actual" half — see
//     actual_sync*.go).
//  3. The drift set replaces the whole component_drift table atomically so
//     stale rows from previous runs can't linger. The replace is skipped
//     when any actual-sync RPC failed: component_drift is a full-table
//     replace with no per-type discriminator, so writing a partial view
//     would wipe the drifts of the types whose RPC failed. The existing
//     table is left intact until a fully successful cycle refreshes it.
//
// Errors are handled inside each step: any per-type RPC failure is logged
// and that type's drifts are skipped, but the rest of the cycle continues.
// A persistence failure is also logged rather than propagated — the
// scheduler retries on the next trigger.
func runInventoryOne(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
	expectedSyncEnabled bool,
) {
	if expectedSyncEnabled {
		syncExpectedFromCore(ctx, pool, nicoClient)
	} else {
		log.Debug().Msgf("Expected-inventory mirror: skipped this cycle (gate %s is off)", envExpectedSyncEnabled)
	}

	drifts, allRPCOK := runActualSync(ctx, pool, nicoClient)
	if !allRPCOK {
		log.Warn().Int("drifts_this_cycle", len(drifts)).
			Msg("Drift detection: one or more actual-sync RPCs failed; preserving existing component_drift table this cycle instead of overwriting it with a partial view")
		return
	}

	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return model.ReplaceAllDrifts(ctx, tx, drifts)
	}); err != nil {
		log.Error().Msgf("Unable to persist drift records: %v", err)
	} else {
		log.Info().Msgf("Drift detection complete: %d drift(s) detected", len(drifts))
	}
}
