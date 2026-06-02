// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package vpc

import (
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	vpcActivity "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// DeleteVpc is a Temporal workflow to delete an existing VPC via Site Agent
func DeleteVpcByID(ctx workflow.Context, vpcID uuid.UUID) error {
	logger := log.With().Str("Workflow", "VPC").Str("Action", "Delete").Str("VPC ID", vpcID.String()).Logger()

	logger.Info().Msg("starting workflow")

	// RetryPolicy specifies how to automatically handle retries if an Activity fails.
	retrypolicy := &temporal.RetryPolicy{
		InitialInterval:    2 * time.Second,
		BackoffCoefficient: 2.0,
		MaximumInterval:    2 * time.Minute,
		MaximumAttempts:    10,
	}
	options := workflow.ActivityOptions{
		// Timeout options specify when to automatically timeout Activity functions.
		StartToCloseTimeout: 3 * time.Minute,
		// Optionally provide a customized RetryPolicy.
		RetryPolicy: retrypolicy,
	}

	ctx = workflow.WithActivityOptions(ctx, options)

	var vpcManager vpcActivity.ManageVPC

	request := &cwssaws.VpcDeletionRequest{
		Id: &cwssaws.VpcId{Value: vpcID.String()},
	}

	err := workflow.ExecuteActivity(ctx, vpcManager.DeleteVpcOnSite, request).Get(ctx, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("failed to execute activity: DeleteVpcOnSite")
		return err
	}

	logger.Info().Msg("completing workflow")

	return nil
}
