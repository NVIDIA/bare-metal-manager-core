// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package leakdetection

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/nicoapi"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler/types"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/providerapi"
	nicoprovider "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/componentmanager/providers/nico" //nolint
	taskmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/manager"
)

// Job implements scheduler.Job for the leak detection task.
type Job struct {
	nicoClient nicoapi.Client
	taskMgr    taskmanager.Manager
	pool       *cdb.Session
}

// New constructs a leak detection Job using the NICo provider from the
// registry. Returns nil, nil if leak detection is disabled or the NICo
// provider is not registered (e.g. non-production environment).
func New(
	ctx context.Context,
	dbConf *cdb.Config,
	taskMgr taskmanager.Manager,
	providers *providerapi.ProviderRegistry,
	cfg config.Config,
) (*Job, error) {
	if cfg.DisableLeakDetection {
		log.Info().Msg("Leak detection disabled by configuration")
		return nil, nil
	}

	if dbConf == nil {
		return nil, fmt.Errorf("database configuration is nil")
	}

	nicoProvider, err := providerapi.GetTyped[*nicoprovider.Provider](
		providers, nicoprovider.ProviderName,
	)
	if err != nil {
		log.Error().Err(err).
			Msg("NICo provider not available; leak detection disabled")
		return nil, nil
	}

	pool, err := cdb.NewSessionFromConfig(ctx, *dbConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create database pool: %w", err)
	}

	return &Job{
		nicoClient: nicoProvider.Client(),
		taskMgr:    taskMgr,
		pool:       pool,
	}, nil
}

// Name returns the job name.
func (j *Job) Name() string { return "leak-detection" }

// Run executes one iteration of leak detection.
func (j *Job) Run(ctx context.Context, _ types.Event) error {
	runLeakDetectionOne(ctx, j.nicoClient, j.taskMgr, j.pool)
	return nil
}
