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

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	osActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/operatingsystem"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

// DeleteOperatingSystemByID is a Temporal workflow to delete an Operating System by ID asynchronously through system worker
func DeleteOperatingSystemByID(ctx workflow.Context, siteIDs []uuid.UUID, operatingSystemID uuid.UUID) error {
	logger := log.With().Str("Workflow", "DeleteOperatingSystemByID").
		Int("Site ID Count", len(siteIDs)).Str("OperatingSystemID", operatingSystemID.String()).Logger()

	logger.Info().Msg("Starting workflow")

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
		err := workflow.ExecuteActivity(ctx, osManager.DeleteOperatingSystemViaSiteAgent, siteID, operatingSystemID).Get(ctx, nil)
		if err != nil {
			logger.Error().Err(err).Str("Site ID", siteID.String()).Msg("Failed to execute activity: DeleteOperatingSystemViaSiteAgent")
			return err
		}
	}

	logger.Info().Msg("Completing workflow")

	return nil
}

// ExecuteDeleteOperatingSystemByIDWorkflow is a helper function to trigger execution of DeleteOperatingSystemByID workflow
func ExecuteDeleteOperatingSystemByIDWorkflow(ctx context.Context, tc client.Client, siteIDs []uuid.UUID, operatingSystemID uuid.UUID) (*string, error) {
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
		ID:        "operating-system-delete-by-id-" + operatingSystemID.String() + "-" + siteIDStringsHashHex,
		TaskQueue: queue.CloudTaskQueue,
	}

	we, err := tc.ExecuteWorkflow(ctx, workflowOptions, DeleteOperatingSystemByID, siteIDs, operatingSystemID)
	if err != nil {
		log.Error().Err(err).Msg("failed to execute workflow: DeleteOperatingSystemByID")
		return nil, err
	}

	wid := we.GetID()

	return &wid, nil
}
