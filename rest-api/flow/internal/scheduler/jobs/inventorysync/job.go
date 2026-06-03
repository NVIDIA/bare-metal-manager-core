// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package inventorysync

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/config"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/scheduler/types"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providerapi"
	nicoprovider "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/providers/nico" //nolint
)

// Job implements scheduler.Job for the inventory sync task.
type Job struct {
	dbConf     *cdb.Config
	nicoClient nicoapi.Client
	pool       *cdb.Session
}

// New constructs an inventory sync Job using clients sourced from the provider
// registry. Returns nil, nil if inventory is disabled or the NICo provider
// is not registered.
func New(
	ctx context.Context,
	dbConf *cdb.Config,
	providers *providerapi.ProviderRegistry,
	cfg config.Config,
) (*Job, error) {
	if cfg.DisableInventory {
		log.Info().Msg("Inventory disabled by configuration")
		return nil, nil
	}

	if dbConf == nil {
		return nil, fmt.Errorf("database configuration is nil")
	}

	nicoProvider, err := providerapi.GetTyped[*nicoprovider.Provider](
		providers, nicoprovider.ProviderName,
	)
	if err != nil {
		log.Warn().
			Err(err).
			Msg("NICo provider not available; inventory sync disabled")
		return nil, nil
	}

	pool, err := cdb.NewSessionFromConfig(ctx, *dbConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pool: %w", err)
	}

	// TODO(follow-up PR): several cleanups are deferred to keep this PR focused:
	//  - Resource lifecycle: pool is never explicitly closed. Jobs should
	//    implement a Close() method so the scheduler can release resources on
	//    shutdown. The same applies to the leak-detection job.
	//  - Store abstraction: raw DB access (pool, dbConf) should be hidden behind
	//    a store interface so jobs depend on a domain-level contract rather than
	//    the database session directly.
	//  - Provider encapsulation: the NICo client is wired here by reaching into
	//    the component-manager provider registry. This logic should move into
	//    the component manager so jobs receive ready-to-use domain clients
	//    instead of low-level provider handles.

	return &Job{
		dbConf:     dbConf,
		nicoClient: nicoProvider.Client(),
		pool:       pool,
	}, nil
}

// Name returns the job name.
func (j *Job) Name() string { return "inventory-sync" }

// Run executes one iteration of the inventory sync.
// No error is returned because runInventoryOne handles all errors internally:
// each sync step logs failures and continues, and the final drift persistence
// error is also logged rather than propagated. A failed iteration is not
// fatal — the scheduler will simply retry on the next trigger fire.
func (j *Job) Run(ctx context.Context, _ types.Event) error {
	runInventoryOne(ctx, j.pool, j.nicoClient)
	return nil
}
