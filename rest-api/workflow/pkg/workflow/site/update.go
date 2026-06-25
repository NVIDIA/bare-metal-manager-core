// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package site

import (
	"time"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	temporallog "go.temporal.io/sdk/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	siteActivity "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/activity/site"
)

// UpdateSiteConfigInventory applies the Site Config inventory reported by the
// Site Agent. Today that inventory carries the Site fabric prefixes, from which
// the workflow creates the matching Site-level IP Blocks.
func UpdateSiteConfigInventory(ctx workflow.Context, siteIDStr string, buildInfo *cwssaws.BuildInfo) error {
	logger := temporallog.With(workflow.GetLogger(ctx), "Workflow", "UpdateSiteConfigInventory", "SiteID", siteIDStr)
	logger.Info("starting workflow")

	siteID, err := uuid.Parse(siteIDStr)
	if err != nil {
		logger.Error("invalid Site ID", "Error", err)
		return err
	}

	options := workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    1 * time.Minute,
			MaximumAttempts:    3,
		},
	}
	ctx = workflow.WithActivityOptions(ctx, options)

	var manageSite siteActivity.ManageSite
	siteFabricPrefixes := buildInfo.GetRuntimeConfig().GetSiteFabricPrefixes()

	err = workflow.ExecuteActivity(ctx, manageSite.UpdateIPBlocksInDBFromFabricPrefixes, siteID, siteFabricPrefixes).Get(ctx, nil)
	if err != nil {
		logger.Error("failed to execute UpdateIPBlocksInDBFromFabricPrefixes activity", "Error", err)
		return err
	}

	logger.Info("completing workflow")
	return nil
}
