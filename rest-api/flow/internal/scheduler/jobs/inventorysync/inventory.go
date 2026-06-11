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
//     expected_mirror*.go).
//  2. runActualSync reconciles each component type against Core's runtime
//     view and returns one combined drift set (the "actual" half — see
//     actual_sync*.go).
//  3. The drift set replaces the whole component_drift table atomically so
//     stale rows from previous runs can't linger.
//
// Errors are handled inside each step: any per-type RPC failure is logged
// and that type's drifts are skipped, but the rest of the cycle continues.
// A persistence failure is also logged rather than propagated — the
// scheduler retries on the next trigger.
func runInventoryOne(
	ctx context.Context,
	pool *cdb.Session,
	nicoClient nicoapi.Client,
) {
	syncExpectedFromCore(ctx, pool, nicoClient)

	drifts := runActualSync(ctx, pool, nicoClient)

	if err := pool.RunInTx(ctx, func(ctx context.Context, tx bun.Tx) error {
		return model.ReplaceAllDrifts(ctx, tx, drifts)
	}); err != nil {
		log.Error().Msgf("Unable to persist drift records: %v", err)
	} else {
		log.Info().Msgf("Drift detection complete: %d drift(s) detected", len(drifts))
	}
}
