// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package workflow

import (
	"time"

	"github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/activity"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GetTenantIdentityActivityOptions are the activity options for identity workflows.
func GetTenantIdentityActivityOptions() workflow.ActivityOptions {
	return workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    1 * time.Second,
			BackoffCoefficient: 2.0,
			MaximumInterval:    10 * time.Second,
			MaximumAttempts:    2,
		},
	}
}

// CreateOrUpdateTenantIdentityConfiguration is a workflow to create or update Tenant Identity Config using the CreateOrUpdateTenantIdentityConfigurationOnSite activity
func CreateOrUpdateTenantIdentityConfiguration(ctx workflow.Context, request *cwssaws.SetTenantIdentityConfigRequest) (*cwssaws.TenantIdentityConfigResponse, error) {
	logger := log.With().Str("Workflow", "CreateOrUpdateTenantIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.TenantIdentityConfigResponse
	if err := workflow.ExecuteActivity(ctx, manager.CreateOrUpdateTenantIdentityConfigurationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "CreateOrUpdateTenantIdentityConfigurationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetTenantIdentityConfiguration is a workflow to get Tenant Identity Config using the GetTenantIdentityConfigurationFromSite activity
func GetTenantIdentityConfiguration(ctx workflow.Context, request *cwssaws.GetTenantIdentityConfigRequest) (*cwssaws.TenantIdentityConfigResponse, error) {
	logger := log.With().Str("Workflow", "GetTenantIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.TenantIdentityConfigResponse
	if err := workflow.ExecuteActivity(ctx, manager.GetTenantIdentityConfigurationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetTenantIdentityConfigurationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// DeleteTenantIdentityConfiguration is a workflow to delete Tenant Identity Config using the DeleteTenantIdentityConfigurationOnSite activity
func DeleteTenantIdentityConfiguration(ctx workflow.Context, request *cwssaws.GetTenantIdentityConfigRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "DeleteTenantIdentityConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response emptypb.Empty
	if err := workflow.ExecuteActivity(ctx, manager.DeleteTenantIdentityConfigurationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteTenantIdentityConfigurationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// CreateOrUpdateTenantIdentityTokenDelegation is a workflow to create or update Token Delegation using the CreateOrUpdateTenantIdentityTokenDelegationOnSite activity
func CreateOrUpdateTenantIdentityTokenDelegation(ctx workflow.Context, request *cwssaws.TokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Workflow", "CreateOrUpdateTenantIdentityTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.TokenDelegationResponse
	if err := workflow.ExecuteActivity(ctx, manager.CreateOrUpdateTenantIdentityTokenDelegationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "CreateOrUpdateTenantIdentityTokenDelegationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetTenantIdentityTokenDelegation is a workflow to get Token Delegation using the GetTenantIdentityTokenDelegationFromSite activity
func GetTenantIdentityTokenDelegation(ctx workflow.Context, request *cwssaws.GetTokenDelegationRequest) (*cwssaws.TokenDelegationResponse, error) {
	logger := log.With().Str("Workflow", "GetTenantIdentityTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.TokenDelegationResponse
	if err := workflow.ExecuteActivity(ctx, manager.GetTenantIdentityTokenDelegationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetTenantIdentityTokenDelegationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// DeleteTenantIdentityTokenDelegation is a workflow to delete Token Delegation using the DeleteTenantIdentityTokenDelegationOnSite activity
func DeleteTenantIdentityTokenDelegation(ctx workflow.Context, request *cwssaws.GetTokenDelegationRequest) (*emptypb.Empty, error) {
	logger := log.With().Str("Workflow", "DeleteTenantIdentityTokenDelegation").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response emptypb.Empty
	if err := workflow.ExecuteActivity(ctx, manager.DeleteTenantIdentityTokenDelegationOnSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "DeleteTenantIdentityTokenDelegationOnSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetJWKS is a workflow to get JWKS using the GetJWKSFromSite activity
func GetJWKS(ctx workflow.Context, request *cwssaws.JwksRequest) (*cwssaws.Jwks, error) {
	logger := log.With().Str("Workflow", "GetJWKS").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.Jwks
	if err := workflow.ExecuteActivity(ctx, manager.GetJWKSFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetJWKSFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}

// GetOpenIDConfiguration is a workflow to get OpenID Configuration using the GetOpenIDConfigurationFromSite activity
func GetOpenIDConfiguration(ctx workflow.Context, request *cwssaws.OpenIdConfigRequest) (*cwssaws.OpenIdConfiguration, error) {
	logger := log.With().Str("Workflow", "GetOpenIDConfiguration").Logger()
	logger.Info().Msg("Starting workflow")

	ctx = workflow.WithActivityOptions(ctx, GetTenantIdentityActivityOptions())

	var manager activity.ManageTenantIdentity
	var response cwssaws.OpenIdConfiguration
	if err := workflow.ExecuteActivity(ctx, manager.GetOpenIDConfigurationFromSite, request).Get(ctx, &response); err != nil {
		logger.Error().Err(err).Str("Activity", "GetOpenIDConfigurationFromSite").Msg("Failed to execute activity from workflow")
		return nil, err
	}

	logger.Info().Msg("Completing workflow")
	return &response, nil
}
