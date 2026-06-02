// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.temporal.io/sdk/temporal"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
)

// ManageTenant is activity to manage a Tenant on Site
type ManageTenant struct {
	coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
}

// CreateTenantOnSite creates a Tenant by calling Site Controller gRPC API
func (mt *ManageTenant) CreateTenantOnSite(ctx context.Context, request *cwssaws.CreateTenantRequest) error {
	logger := log.With().Str("Activity", "CreateTenantOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty Tenant request")
	} else if request.OrganizationId == "" {
		err = errors.New("received Tenant creation request without Organization ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mt.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.CreateTenant(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create Tenant using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return err
}

// UpdateTenantOnSite creates a Tenant by calling Site Controller gRPC API
func (mt *ManageTenant) UpdateTenantOnSite(ctx context.Context, request *cwssaws.UpdateTenantRequest) error {
	logger := log.With().Str("Activity", "UpdateTenantOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty Tenant request")
	} else if request.OrganizationId == "" {
		err = errors.New("received Tenant update request without Organization ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mt.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.UpdateTenant(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to update Tenant using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return err
}

// NewManageTenant returns a new ManageTenant activity
func NewManageTenant(coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient) ManageTenant {
	return ManageTenant{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
	}
}

// ManageTenantInventory is an activity wrapper for VPC inventory collection and publishing
type ManageTenantInventory struct {
	config ManageInventoryConfig
}

// ManageTenantInventory is an activity to collect Tenant inventory and publish to Cloud
func (mti *ManageTenantInventory) DiscoverTenantInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverTenantInventory").Logger()
	logger.Info().Msg("Starting activity")
	inventoryImpl := manageInventoryImpl[string, *cwssaws.Tenant, *cwssaws.TenantInventory]{
		itemType:               "Tenant",
		config:                 mti.config,
		internalFindIDs:        tenantFindIDs,
		internalFindByIDs:      tenantFindByIDs,
		internalPagedInventory: tenantPagedInventory,
	}
	return inventoryImpl.CollectAndPublishInventory(ctx, &logger)
}

// NewManageTenantInventory returns a ManageInventory implementation for VPC activity
func NewManageTenantInventory(config ManageInventoryConfig) ManageTenantInventory {
	return ManageTenantInventory{
		config: config,
	}
}

func tenantFindIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient) ([]string, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	idList, err := grpcServiceClient.FindTenantOrganizationIds(ctx, &cwssaws.TenantSearchFilter{})
	if err != nil {
		return nil, err
	}
	return idList.GetTenantOrganizationIds(), nil
}

func tenantFindByIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient, ids []string) ([]*cwssaws.Tenant, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	list, err := grpcServiceClient.FindTenantsByOrganizationIds(ctx, &cwssaws.TenantByOrganizationIdsRequest{
		OrganizationIds: ids,
	})
	if err != nil {
		return nil, err
	}
	return list.GetTenants(), nil
}

func tenantPagedInventory(allItemIDs []string, pagedItems []*cwssaws.Tenant, input *pagedInventoryInput) *cwssaws.TenantInventory {
	// Create an inventory page with the subset of Tenants
	inventory := &cwssaws.TenantInventory{
		Tenants: pagedItems,
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
		},
		InventoryStatus: input.status,
		StatusMsg:       input.statusMessage,
		InventoryPage:   input.buildPage(),
	}
	if inventory.InventoryPage != nil {
		inventory.InventoryPage.ItemIds = allItemIDs
	}
	return inventory
}
