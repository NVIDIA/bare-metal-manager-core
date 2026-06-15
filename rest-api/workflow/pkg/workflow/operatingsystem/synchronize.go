/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package operatingsystem

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	temporalEnums "go.temporal.io/api/enums/v1"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	osActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/operatingsystem"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

const (
	SyncOperationCreate = "Create"
	SyncOperationUpdate = "Update"
	SyncOperationDelete = "Delete"
)

// CreateOrUpdateOperatingSystemByID is a Temporal workflow that creates or updates an Operating System by ID via Site Agent
func CreateOrUpdateOperatingSystemByID(ctx workflow.Context, siteIDs []uuid.UUID, operatingSystemID uuid.UUID) error {
	logger := log.With().Str("Workflow", "CreateOrUpdateOperatingSystemByID").
		Int("Site ID Count", len(siteIDs)).Str("OperatingSystemID", operatingSystemID.String()).Logger()

	logger.Info().Msg("starting workflow")

	retryPolicy := &temporal.RetryPolicy{
		InitialInterval:    2 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    2 * time.Minute,
		MaximumAttempts:    15,
	}
	options := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy:         retryPolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var osManager osActivity.ManageOperatingSystem

	for _, siteID := range siteIDs {
		err := workflow.ExecuteActivity(ctx, osManager.CreateOrUpdateOperatingSystemViaSiteAgent, siteID, operatingSystemID).Get(ctx, nil)
		if err != nil {
			logger.Error().Err(err).Str("Site ID", siteID.String()).Msg("failed to execute activity: CreateOrUpdateOperatingSystemViaSiteAgent")
			return err
		}
	}

	logger.Info().Msg("completing workflow")

	return nil
}

// ExecuteCreateOrUpdateOperatingSystemByIDWorkflow triggers the CreateOrUpdateOperatingSystemByID workflow
func ExecuteCreateOrUpdateOperatingSystemByIDWorkflow(ctx context.Context, tc client.Client, siteIDs []uuid.UUID, operatingSystemID uuid.UUID) (*string, error) {
	// Get SHA1 hash of siteIDs in hex format
	siteIDStrings := make([]string, len(siteIDs))
	for i, siteID := range siteIDs {
		siteIDStrings[i] = siteID.String()
	}
	sort.Strings(siteIDStrings)

	siteIDStringsHash := sha1.New()
	siteIDStringsHash.Write([]byte(strings.Join(siteIDStrings, "-")))
	siteIDStringsHashHex := hex.EncodeToString(siteIDStringsHash.Sum(nil))

	workflowOptions := client.StartWorkflowOptions{
		ID:                    "operating-system-create-or-update-by-id-" + operatingSystemID.String() + "-" + siteIDStringsHashHex,
		TaskQueue:             queue.CloudTaskQueue,
		WorkflowIDReusePolicy: temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
	}

	we, err := tc.ExecuteWorkflow(ctx, workflowOptions, CreateOrUpdateOperatingSystemByID, siteIDs, operatingSystemID)
	if err != nil {
		log.Error().Err(err).Msg("failed to execute CreateOrUpdateOperatingSystemByID workflow")
		return nil, err
	}

	wid := we.GetID()

	return &wid, nil
}
