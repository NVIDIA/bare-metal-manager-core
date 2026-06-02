// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"time"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/timestamppb"

	gcodes "google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// ManageOperatingSystem is an activity wrapper for Operating System management
type ManageOperatingSystem struct {
	coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
}

// NewManageOperatingSystem returns a new ManageOperatingSystem client
func NewManageOperatingSystem(coreGrpcClient *cClient.CoreGrpcAtomicClient) ManageOperatingSystem {
	return ManageOperatingSystem{
		coreGrpcAtomicClient: coreGrpcClient,
	}
}

// Function to create OsImage with NICo
func (mos *ManageOperatingSystem) CreateOsImageOnSite(ctx context.Context, request *cwssaws.OsImageAttributes) error {
	logger := log.With().Str("Activity", "CreateOsImageOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty create OS Image request")
	} else if request.SourceUrl == "" {
		err = errors.New("received create OS Image request missing SourceUrl")
	} else if request.Digest == "" {
		err = errors.New("received create OS Image request missing Digest")
	} else if request.TenantOrganizationId == "" {
		err = errors.New("received create OS Image request missing TenantOrganizationId")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mos.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.CreateOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create OS Image using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// Function to update OsImage with NICo
func (mos *ManageOperatingSystem) UpdateOsImageOnSite(ctx context.Context, request *cwssaws.OsImageAttributes) error {
	logger := log.With().Str("Activity", "UpdateOsImageOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty update OS Image request")
	} else if request.SourceUrl == "" {
		err = errors.New("received update OS Image request missing SourceUrl")
	} else if request.Digest == "" {
		err = errors.New("received update OS Image request missing Digest")
	} else if request.TenantOrganizationId == "" {
		err = errors.New("received update OS Image request without TenantOrganizationId")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mos.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.UpdateOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to update OS Image using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// Function to delete OsImage on NICo
func (mos *ManageOperatingSystem) DeleteOsImageOnSite(ctx context.Context, request *cwssaws.DeleteOsImageRequest) error {
	logger := log.With().Str("Activity", "DeleteOsImageOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty delete OS Image request")
	} else if request.Id == nil {
		err = errors.New("reveived delete OS Image request without ID")
	} else if request.TenantOrganizationId == "" {
		err = errors.New("received delete OS Image request without TenantOrganizationId")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mos.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.DeleteOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete OS Image using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// ManageOsImageInventory is an activity wrapper for OS Image inventory collection and publishing
type ManageOsImageInventory struct {
	config ManageInventoryConfig
}

// NewManageOsImageInventory returns a ManageInventory implementation for OS Image
func NewManageOsImageInventory(config ManageInventoryConfig) ManageOsImageInventory {
	return ManageOsImageInventory{
		config: config,
	}
}

// DiscoverOsImageInventory is an activity to collect OS Image inventory and publish to Temporal queue
func (moii *ManageOsImageInventory) DiscoverOsImageInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverOsImageInventory").Logger()
	logger.Info().Msg("Starting activity")

	inventoryImpl := manageInventoryImpl[*cwssaws.UUID, *cwssaws.OsImage, *cwssaws.OsImageInventory]{
		itemType:               "OsImage",
		config:                 moii.config,
		internalFindIDs:        osImageFindIDs,
		internalFindByIDs:      osImageFindByIDs,
		internalPagedInventory: osImagePagedInventory,
		internalFindFallback:   osImageFindFallback,
	}
	return inventoryImpl.CollectAndPublishInventory(ctx, &logger)
}

func osImageFindIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient) ([]*cwssaws.UUID, error) {
	return nil, gstatus.Error(gcodes.Unimplemented, "")
}

func osImageFindByIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient, ids []*cwssaws.UUID) ([]*cwssaws.OsImage, error) {
	return nil, gstatus.Error(gcodes.Unimplemented, "")
}

func osImagePagedInventory(allItemIDs []*cwssaws.UUID, pagedItems []*cwssaws.OsImage, input *pagedInventoryInput) *cwssaws.OsImageInventory {
	itemIDs := []string{}
	for _, id := range allItemIDs {
		itemIDs = append(itemIDs, id.GetValue())
	}

	// Create an inventory page with the subset of OS Images
	inventory := &cwssaws.OsImageInventory{
		OsImages: pagedItems,
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
		},
		InventoryStatus: input.status,
		StatusMsg:       input.statusMessage,
		InventoryPage:   input.buildPage(),
	}
	if inventory.InventoryPage != nil {
		inventory.InventoryPage.ItemIds = itemIDs
	}
	return inventory
}

func osImageFindFallback(ctx context.Context, grpcClient *cClient.CoreGrpcClient) ([]*cwssaws.UUID, []*cwssaws.OsImage, error) {
	request := &cwssaws.ListOsImageRequest{}
	items, err := grpcClient.GrpcServiceClient().ListOsImage(ctx, request)
	if err != nil {
		return nil, nil, err
	}
	var ids []*cwssaws.UUID
	for _, it := range items.GetImages() {
		ids = append(ids, it.GetAttributes().Id)
	}
	return ids, items.GetImages(), nil
}
