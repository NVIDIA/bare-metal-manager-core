// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"fmt"
	"time"

	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/rs/zerolog/log"
	tClient "go.temporal.io/sdk/client"
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

// Function to create OsImage with NICo Core
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

	// Call Site Controller gRPC endpoint
	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}

	forgeClient := coreGrpcClient.GrpcServiceClient()

	_, err = forgeClient.CreateOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create OS Image using Site Controller API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// Function to update OsImage with NICo Core
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

	// Call Site Controller gRPC endpoint
	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	forgeClient := coreGrpcClient.GrpcServiceClient()

	_, err = forgeClient.UpdateOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to update OS Image using Site Controller API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// Function to delete OsImage on NICo Core
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

	// Call Site Controller gRPC endpoint
	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	forgeClient := coreGrpcClient.GrpcServiceClient()

	_, err = forgeClient.DeleteOsImage(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete OS Image using Site Controller API")
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

func osImageFindIDs(ctx context.Context, coreGrpcClient *cClient.CoreGrpcClient) ([]*cwssaws.UUID, error) {
	return nil, gstatus.Error(gcodes.Unimplemented, "")
}

func osImageFindByIDs(ctx context.Context, coreGrpcClient *cClient.CoreGrpcClient, ids []*cwssaws.UUID) ([]*cwssaws.OsImage, error) {
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

func osImageFindFallback(ctx context.Context, coreGrpcClient *cClient.CoreGrpcClient) ([]*cwssaws.UUID, []*cwssaws.OsImage, error) {
	request := &cwssaws.ListOsImageRequest{}

	forgeClient := coreGrpcClient.GrpcServiceClient()

	items, err := forgeClient.ListOsImage(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	var ids []*cwssaws.UUID
	for _, it := range items.GetImages() {
		ids = append(ids, it.GetAttributes().Id)
	}

	return ids, items.GetImages(), nil
}

// ManageOperatingSystemInventory is an activity wrapper for Operating System inventory collection and publishing
type ManageOperatingSystemInventory struct {
	config ManageInventoryConfig
}

// DiscoverOperatingSystemInventory collects Operating System inventory from nico-core and publishes
// it to the cloud Temporal queue for reconciliation with the operating_system table.
func (m *ManageOperatingSystemInventory) DiscoverOperatingSystemInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverOperatingSystemInventory").Logger()
	logger.Info().Msg("Starting activity")

	workflowOptions := tClient.StartWorkflowOptions{
		ID:        fmt.Sprintf("update-operating-system-inventory-%s", m.config.SiteID.String()),
		TaskQueue: m.config.TemporalPublishQueue,
	}
	workflowName := "UpdateOperatingSystemInventory"

	coreGrpcClient := m.config.CoreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	forgeClient := coreGrpcClient.GrpcServiceClient()

	publishError := func(msg string, cause error) error {
		inv := &cwssaws.OperatingSystemInventory{
			InventoryStatus: cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       cause.Error(),
			Timestamp:       timestamppb.Now(),
		}
		if _, execErr := m.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, m.config.SiteID, inv); execErr != nil {
			logger.Error().Err(execErr).Msg("Failed to publish inventory error to Cloud")
			return execErr
		}
		return cause
	}

	// Step 1: fetch all active OS definition IDs from nico-core.
	idList, err := forgeClient.FindOperatingSystemIds(ctx, &cwssaws.OperatingSystemSearchFilter{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve OS definition IDs from nico-core")
		return publishError("Failed to retrieve OS definition IDs from nico-core", err)
	}

	// Step 2: fetch full definitions for all returned IDs.
	var osDefs []*cwssaws.OperatingSystem
	if len(idList.GetIds()) > 0 {
		osList, ferr := forgeClient.FindOperatingSystemsByIds(ctx, &cwssaws.OperatingSystemsByIdsRequest{
			Ids: idList.GetIds(),
		})
		if ferr != nil {
			logger.Warn().Err(ferr).Msg("Failed to retrieve OS definitions by IDs from nico-core")
			return publishError("Failed to retrieve OS definitions by IDs from nico-core", ferr)
		}
		osDefs = osList.GetOperatingSystems()
	}

	inventory := &cwssaws.OperatingSystemInventory{
		InventoryStatus:  cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS,
		StatusMsg:        "Successfully retrieved from nico-core",
		Timestamp:        timestamppb.Now(),
		OperatingSystems: osDefs,
	}

	if _, err = m.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, m.config.SiteID, inventory); err != nil {
		logger.Error().Err(err).Msg("Failed to publish OS definition inventory to Cloud")
		return err
	}

	logger.Info().Msgf("Published %d Operating Systems to Cloud", len(osDefs))
	logger.Info().Msg("Completed activity")
	return nil
}

// NewManageOperatingSystemInventory returns a ManageOperatingSystemInventory activity
func NewManageOperatingSystemInventory(config ManageInventoryConfig) ManageOperatingSystemInventory {
	return ManageOperatingSystemInventory{config: config}
}

// CreateOperatingSystemOnSite creates an Operating System in nico-core via gRPC.
// request.Id must be pre-set to the carbide-rest primary key so both sides share the same UUID.
func (mos *ManageOperatingSystem) CreateOperatingSystemOnSite(ctx context.Context, request *cwssaws.CreateOperatingSystemRequest) (string, error) {
	logger := log.With().Str("Activity", "CreateOperatingSystemOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty create OS definition request")
		return "", temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.Name == "" {
		err := errors.New("received create OS definition request missing Name")
		return "", temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return "", cClient.ErrCoreGrpcClientNotConnected
	}

	if _, err := coreGrpcClient.GrpcServiceClient().CreateOperatingSystem(ctx, request); err != nil {
		logger.Warn().Err(err).Msg("Failed to create Operating System in nico-core")
		return "", swe.WrapErr(err)
	}

	idStr := request.GetId().GetValue()
	logger.Info().Str("ID", idStr).Msg("Completed activity")
	return idStr, nil
}

// UpdateOperatingSystemOnSite updates an existing Operating System in nico-core via gRPC
func (mos *ManageOperatingSystem) UpdateOperatingSystemOnSite(ctx context.Context, request *cwssaws.UpdateOperatingSystemRequest) error {
	logger := log.With().Str("Activity", "UpdateOperatingSystemOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty update OS definition request")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetId().GetValue() == "" {
		err := errors.New("received update OS definition request missing ID")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}

	_, err := coreGrpcClient.GrpcServiceClient().UpdateOperatingSystem(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to update Operating System in nico-core")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return nil
}

// DeleteOperatingSystemOnSite deletes an Operating System from nico-core via gRPC
func (mos *ManageOperatingSystem) DeleteOperatingSystemOnSite(ctx context.Context, request *cwssaws.DeleteOperatingSystemRequest) error {
	logger := log.With().Str("Activity", "DeleteOperatingSystemOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil {
		err := errors.New("received empty delete OS definition request")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}
	if request.GetId().GetValue() == "" {
		err := errors.New("received delete OS definition request missing ID")
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	coreGrpcClient := mos.coreGrpcAtomicClient.GetClient()
	if coreGrpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}

	_, err := coreGrpcClient.GrpcServiceClient().DeleteOperatingSystem(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete Operating System from nico-core")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return nil
}
