// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"time"

	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	cclient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type ManageDpuExtensionServiceInventory struct {
	config ManageInventoryConfig
}

// DiscoverDpuExtensionServiceInventory is an activity to discover DPU Extension Services on Site and publish to Temporal queue
func (msi *ManageDpuExtensionServiceInventory) DiscoverDpuExtensionServiceInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverDpuExtensionServiceInventory").Logger()

	logger.Info().Msg("Starting activity")

	inventoryImpl := manageInventoryImpl[string, *cwssaws.DpuExtensionService, *cwssaws.DpuExtensionServiceInventory]{
		itemType:               "DpuExtensionService",
		config:                 msi.config,
		internalFindIDs:        dpuExtensionServiceFindIDs,
		internalFindByIDs:      dpuExtensionServiceFindByIDs,
		internalPagedInventory: dpuExtensionServicePagedInventory,
	}

	return inventoryImpl.CollectAndPublishInventory(ctx, &logger)
}

// NewManageDpuExtensionServiceInventory returns a ManageInventory implementation for DPU Extension Service activity
func NewManageDpuExtensionServiceInventory(config ManageInventoryConfig) ManageDpuExtensionServiceInventory {
	return ManageDpuExtensionServiceInventory{
		config: config,
	}
}

func dpuExtensionServiceFindIDs(ctx context.Context, grpcClient *cclient.CoreGrpcClient) ([]string, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	result, err := grpcServiceClient.FindDpuExtensionServiceIds(ctx, &cwssaws.DpuExtensionServiceSearchFilter{})
	if err != nil {
		return nil, err
	}

	return result.ServiceIds, nil
}

func dpuExtensionServiceFindByIDs(ctx context.Context, grpcClient *cclient.CoreGrpcClient, ids []string) ([]*cwssaws.DpuExtensionService, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	result, err := grpcServiceClient.FindDpuExtensionServicesByIds(ctx, &cwssaws.DpuExtensionServicesByIdsRequest{
		ServiceIds: ids,
	})
	if err != nil {
		return nil, err
	}
	return result.Services, nil
}

func dpuExtensionServicePagedInventory(allItemIDs []string, pagedItems []*cwssaws.DpuExtensionService, input *pagedInventoryInput) *cwssaws.DpuExtensionServiceInventory {
	itemIDs := []string{}
	for _, id := range allItemIDs {
		itemIDs = append(itemIDs, id)
	}

	inventory := &cwssaws.DpuExtensionServiceInventory{
		DpuExtensionServices: pagedItems,
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

// ManageDpuExtensionService is an activity wrapper for DPU Extension Service management
type ManageDpuExtensionService struct {
	coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient
}

// CreateDpuExtensionServiceOnSite is an activity to create a new DPU Extension Service on Site
func (mdes *ManageDpuExtensionService) CreateDpuExtensionServiceOnSite(ctx context.Context, request *cwssaws.CreateDpuExtensionServiceRequest) (*cwssaws.DpuExtensionService, error) {
	logger := log.With().Str("Activity", "CreateDpuExtensionServiceOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty create DPU Extension Service request")
	} else if request.ServiceId == nil || *request.ServiceId == "" {
		err = errors.New("received create DPU Extension Service request without ID")
	} else if request.ServiceName == "" {
		err = errors.New("received create DPU Extension Service request without name")
	} else if request.TenantOrganizationId == "" {
		err = errors.New("received create DPU Extension Service request without tenant organization ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mdes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	createdDpuExtensionService, err := grpcServiceClient.CreateDpuExtensionService(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create DPU Extension Service using Core gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return createdDpuExtensionService, nil
}

// UpdateDpuExtensionServiceOnSite is an activity to update a DPU Extension Service on Site
func (mdes *ManageDpuExtensionService) UpdateDpuExtensionServiceOnSite(ctx context.Context, request *cwssaws.UpdateDpuExtensionServiceRequest) (*cwssaws.DpuExtensionService, error) {
	logger := log.With().Str("Activity", "UpdateDpuExtensionServiceOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty update DPU Extension Service request")
	} else if request.ServiceId == "" {
		err = errors.New("received update DPU Extension Service request without ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mdes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	updatedDpuExtensionService, err := grpcServiceClient.UpdateDpuExtensionService(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to update DPU Extension Service using Core gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return updatedDpuExtensionService, nil
}

// DeleteDpuExtensionServiceOnSite is an activity to delete a DPU Extension Service on Site
func (mdes *ManageDpuExtensionService) DeleteDpuExtensionServiceOnSite(ctx context.Context, request *cwssaws.DeleteDpuExtensionServiceRequest) error {
	logger := log.With().Str("Activity", "DeleteDpuExtensionServiceOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty delete DPU Extension Service request")
	} else if request.ServiceId == "" {
		err = errors.New("received delete DPU Extension Service request without ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mdes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.DeleteDpuExtensionService(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete DPU Extension Service using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// GetDpuExtensionServiceVersionsInfoOnSite is an activity to get detailed information for various versions of a DPU Extension Service on Site
func (mdes *ManageDpuExtensionService) GetDpuExtensionServiceVersionsInfoOnSite(ctx context.Context, request *cwssaws.GetDpuExtensionServiceVersionsInfoRequest) (*cwssaws.DpuExtensionServiceVersionInfoList, error) {
	logger := log.With().Str("Activity", "GetDpuExtensionServiceVersionsInfoOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty get DPU Extension Service versions info request")
	} else if request.ServiceId == "" {
		err = errors.New("received get DPU Extension Service versions info request without ID")
	}

	if err != nil {
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mdes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	versionInfos, err := grpcServiceClient.GetDpuExtensionServiceVersionsInfo(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to get DPU Extension Service versions info using Core gRPC API")
		return nil, swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return versionInfos, nil
}

// NewManageDpuExtensionService returns a new ManageDpuExtensionService activity
func NewManageDpuExtensionService(coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient) ManageDpuExtensionService {
	return ManageDpuExtensionService{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
	}
}
