// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"go.temporal.io/sdk/client"
	tClient "go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	cclient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"
)

// ManageExpectedPowerShelfInventory is an activity wrapper for Expected Power Shelf inventory collection and publishing
type ManageExpectedPowerShelfInventory struct {
	siteID                uuid.UUID
	coreGrpcAtomicClient  *cclient.CoreGrpcAtomicClient
	temporalPublishClient tClient.Client
	temporalPublishQueue  string
	cloudPageSize         int
}

type linkedExpectedPowerShelfInfo struct {
	expectedPowerShelf       *corev1.ExpectedPowerShelf
	linkedExpectedPowerShelf *corev1.LinkedExpectedPowerShelf
}

// DiscoverExpectedPowerShelfInventory is an activity to collect Expected Power Shelf inventory and publish to Temporal queue
func (mepsi *ManageExpectedPowerShelfInventory) DiscoverExpectedPowerShelfInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverExpectedPowerShelfInventory").Logger()
	logger.Info().Msg("Starting activity")

	// Define workflow options
	workflowOptions := tClient.StartWorkflowOptions{
		ID:        "update-expectedpowershelf-inventory-" + mepsi.siteID.String(),
		TaskQueue: mepsi.temporalPublishQueue,
	}

	// Get Site Controller gRPC client
	grpcClient := mepsi.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	// Call GetAllExpectedPowerShelves to get full list of ExpectedPowerShelves on Site
	epsList, err := grpcServiceClient.GetAllExpectedPowerShelves(ctx, &emptypb.Empty{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve ExpectedPowerShelves using Core gRPC API")

		// Error encountered before we've published anything, report inventory collection error to Cloud
		inventory := &corev1.ExpectedPowerShelfInventory{
			Timestamp: &timestamppb.Timestamp{
				Seconds: time.Now().Unix(),
			},
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       err.Error(),
		}

		_, serr := mepsi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedPowerShelfInventory", mepsi.siteID, inventory)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedPowerShelf inventory error to Cloud")
			return serr
		}
		return err
	}

	// Call GetAllExpectedPowerShelvesLinked to get linked Power Shelf IDs
	linkedList, lerr := grpcServiceClient.GetAllExpectedPowerShelvesLinked(ctx, &emptypb.Empty{})
	if lerr != nil {
		logger.Warn().Err(lerr).Msg("Failed to retrieve linked Power Shelf IDs using Core gRPC API")

		// Fatal error - report inventory collection error to Cloud
		inventory := &corev1.ExpectedPowerShelfInventory{
			Timestamp: &timestamppb.Timestamp{
				Seconds: time.Now().Unix(),
			},
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       lerr.Error(),
		}

		_, serr := mepsi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedPowerShelfInventory", mepsi.siteID, inventory)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedPowerShelf inventory error to Cloud")
			return serr
		}
		return lerr
	}

	// LinkedExpectedPowerShelf data is missing ExpectedPowerShelf ID so we build an intermediate map using MAC address
	linkedPowerShelvesByKey := make(map[string]*corev1.LinkedExpectedPowerShelf)
	for _, linked := range linkedList.ExpectedPowerShelves {
		linkedPowerShelvesByKey[linked.BmcMacAddress] = linked
	}

	// Build list of ExpectedPowerShelf paired with LinkedExpectedPowerShelf
	linkedExpectedPowerShelvesInfo := []linkedExpectedPowerShelfInfo{}
	allExpectedPowerShelfIDs := []string{}
	for _, eps := range epsList.ExpectedPowerShelves {
		// Discard records without ID
		if eps.ExpectedPowerShelfId == nil || eps.ExpectedPowerShelfId.Value == "" {
			logger.Warn().Str("MAC", eps.BmcMacAddress).Str("Serial", eps.ShelfSerialNumber).Msg("Discarding ExpectedPowerShelf without ID")
			continue
		}
		allExpectedPowerShelfIDs = append(allExpectedPowerShelfIDs, eps.ExpectedPowerShelfId.Value)
		// Find matching LinkedPowerShelf record by MAC address if it exists
		linked := linkedPowerShelvesByKey[eps.BmcMacAddress]
		linkedExpectedPowerShelvesInfo = append(linkedExpectedPowerShelvesInfo, linkedExpectedPowerShelfInfo{
			expectedPowerShelf:       eps,
			linkedExpectedPowerShelf: linked,
		})
	}
	totalCount := len(linkedExpectedPowerShelvesInfo)

	logger.Info().Int("ExpectedPowerShelf Count", totalCount).Msg("Built ExpectedPowerShelf list")

	if totalCount == 0 {
		inventoryPage := getPagedExpectedPowerShelfInventory([]linkedExpectedPowerShelfInfo{}, allExpectedPowerShelfIDs, totalCount, 1, mepsi.cloudPageSize, corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS, "No ExpectedPowerShelves reported by Site Controller")

		_, serr := mepsi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedPowerShelfInventory", mepsi.siteID, inventoryPage)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedPowerShelf inventory to Cloud")
			return serr
		}
		return nil
	}

	// Calculate total pages needed for Cloud
	totalCloudPages := totalCount / mepsi.cloudPageSize
	if totalCount%mepsi.cloudPageSize > 0 {
		totalCloudPages++
	}

	// Publish ExpectedPowerShelf inventory to Cloud in separate chunks
	for cloudPage := 1; cloudPage <= totalCloudPages; cloudPage++ {
		startIndex := (cloudPage - 1) * mepsi.cloudPageSize
		endIndex := startIndex + mepsi.cloudPageSize
		if endIndex > totalCount {
			endIndex = totalCount
		}

		pagedWorkflowOptions := client.StartWorkflowOptions{
			ID:        fmt.Sprintf("%v-%v", workflowOptions.ID, cloudPage),
			TaskQueue: workflowOptions.TaskQueue,
		}

		// Create an inventory page with the subset of ExpectedPowerShelves
		// Slice the list directly for this page
		pagedInfo := linkedExpectedPowerShelvesInfo[startIndex:endIndex]
		inventoryPage := getPagedExpectedPowerShelfInventory(
			pagedInfo,
			allExpectedPowerShelfIDs,
			totalCount,
			cloudPage,
			mepsi.cloudPageSize,
			corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			"Successfully retrieved ExpectedPowerShelves from Site Controller",
		)

		logger.Info().Msgf("Publishing ExpectedPowerShelf inventory page %d to Cloud", cloudPage)

		_, serr := mepsi.temporalPublishClient.ExecuteWorkflow(context.Background(), pagedWorkflowOptions, "UpdateExpectedPowerShelfInventory", mepsi.siteID, inventoryPage)
		if serr != nil {
			logger.Error().Err(serr).Int("Cloud Page", cloudPage).Msg("Failed to publish ExpectedPowerShelf inventory to Cloud")
			return serr
		}
	}

	return nil
}

// getPagedExpectedPowerShelfInventory returns a subset of ExpectedPowerShelfInventory for a given page
func getPagedExpectedPowerShelfInventory(
	pagedInfo []linkedExpectedPowerShelfInfo,
	allExpectedPowerShelfIDs []string,
	totalCount int,
	page int,
	pageSize int,
	status corev1.InventoryStatus,
	statusMessage string,
) *corev1.ExpectedPowerShelfInventory {
	totalPages := totalCount / pageSize
	if totalCount%pageSize > 0 {
		totalPages++
	}

	// Build lists for this page from the sliced info list
	pagedExpectedPowerShelves := make([]*corev1.ExpectedPowerShelf, 0, len(pagedInfo))
	pagedLinkedPowerShelves := make([]*corev1.LinkedExpectedPowerShelf, 0, len(pagedInfo))

	for _, info := range pagedInfo {
		pagedExpectedPowerShelves = append(pagedExpectedPowerShelves, info.expectedPowerShelf)
		// Only add LinkedExpectedPowerShelf if it exists (it may be nil if no match was found)
		if info.linkedExpectedPowerShelf != nil {
			pagedLinkedPowerShelves = append(pagedLinkedPowerShelves, info.linkedExpectedPowerShelf)
		}
	}

	// Create an inventory page with the subset of ExpectedPowerShelves and matching LinkedPowerShelves
	inventoryPage := &corev1.ExpectedPowerShelfInventory{
		ExpectedPowerShelves: pagedExpectedPowerShelves,
		LinkedPowerShelves:   pagedLinkedPowerShelves,
		Timestamp: &timestamppb.Timestamp{
			Seconds: time.Now().Unix(),
		},
		InventoryStatus: status,
		StatusMsg:       statusMessage,
		InventoryPage: &corev1.InventoryPage{
			TotalPages:  int32(totalPages),
			CurrentPage: int32(page),
			PageSize:    int32(pageSize),
			TotalItems:  int32(totalCount),
			ItemIds:     allExpectedPowerShelfIDs,
		},
	}

	return inventoryPage
}

// NewManageExpectedPowerShelfInventory returns a ManageInventory implementation for Expected Power Shelf activity
func NewManageExpectedPowerShelfInventory(siteID uuid.UUID, coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient, temporalPublishClient tClient.Client, temporalPublishQueue string, cloudPageSize int) ManageExpectedPowerShelfInventory {
	return ManageExpectedPowerShelfInventory{
		siteID:                siteID,
		coreGrpcAtomicClient:  coreGrpcAtomicClient,
		temporalPublishClient: temporalPublishClient,
		temporalPublishQueue:  temporalPublishQueue,
		cloudPageSize:         cloudPageSize,
	}
}

// ManageExpectedPowerShelf is an activity wrapper for Expected Power Shelf management
type ManageExpectedPowerShelf struct {
	coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient
	flowGrpcAtomicClient *cclient.FlowGrpcAtomicClient
}

// NewManageExpectedPowerShelf returns a new ManageExpectedPowerShelf client
func NewManageExpectedPowerShelf(coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient, flowGrpcAtomicClient *cclient.FlowGrpcAtomicClient) ManageExpectedPowerShelf {
	return ManageExpectedPowerShelf{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// CreateExpectedPowerShelfOnSite creates Expected Power Shelf with NICo
func (meps *ManageExpectedPowerShelf) CreateExpectedPowerShelfOnSite(ctx context.Context, request *corev1.ExpectedPowerShelf) error {
	logger := log.With().Str("Activity", "CreateExpectedPowerShelfOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty create Expected Power Shelf request")
	} else if request.GetExpectedPowerShelfId().GetValue() == "" {
		err = errors.New("received create Expected Power Shelf request without required id field")
	} else if request.GetBmcMacAddress() == "" || request.GetShelfSerialNumber() == "" {
		err = errors.New("received create Expected Power Shelf request with missing MAC or serial")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := meps.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	// Call Core gRPC endpoint
	start := time.Now()
	_, err = grpcServiceClient.AddExpectedPowerShelf(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to create Expected Power Shelf using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// UpdateExpectedPowerShelfOnSite updates Expected Power Shelf on NICo
func (meps *ManageExpectedPowerShelf) UpdateExpectedPowerShelfOnSite(ctx context.Context, request *corev1.ExpectedPowerShelf) error {
	logger := log.With().Str("Activity", "UpdateExpectedPowerShelfOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty update Expected Power Shelf request")
	} else if request.GetExpectedPowerShelfId().GetValue() == "" {
		err = errors.New("received update Expected Power Shelf request without required id field")
	} else if request.GetBmcMacAddress() == "" || request.GetShelfSerialNumber() == "" {
		err = errors.New("received update Expected Power Shelf request with missing MAC or serial")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := meps.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.UpdateExpectedPowerShelf(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to update Expected Power Shelf using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// CreateExpectedPowerShelfOnFlow creates an Expected Power Shelf as a component in Flow via AddComponent
func (meps *ManageExpectedPowerShelf) CreateExpectedPowerShelfOnFlow(ctx context.Context, request *corev1.ExpectedPowerShelf) error {
	logger := log.With().Str("Activity", "CreateExpectedPowerShelfOnFlow").Logger()

	logger.Info().Msg("Starting activity")

	// Validate request
	if request == nil {
		return temporal.NewNonRetryableApplicationError("received empty create Expected Power Shelf request for Flow", swe.ErrTypeInvalidRequest, errors.New("nil request"))
	}

	// If Flow client is not configured, skip gracefully
	if meps.flowGrpcAtomicClient == nil {
		logger.Warn().Msg("Flow client not configured, skipping Flow component creation")
		return nil
	}

	grpcClient := meps.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		logger.Warn().Msg("Flow client not connected, skipping Flow component creation")
		return nil
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	component := expectedPowerShelfToFlowComponent(request)
	_, err := grpcServiceClient.AddComponent(ctx, &flowv1.AddComponentRequest{Component: component})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create Expected Power Shelf component on Flow")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return nil
}

// expectedPowerShelfToFlowComponent converts a NICo ExpectedPowerShelf proto to an Flow Component proto
func expectedPowerShelfToFlowComponent(eps *corev1.ExpectedPowerShelf) *flowv1.Component {
	component := &flowv1.Component{
		Type: flowv1.ComponentType_COMPONENT_TYPE_POWERSHELF,
		Info: &flowv1.DeviceInfo{
			Id:           &flowv1.UUID{Id: eps.GetExpectedPowerShelfId().GetValue()},
			SerialNumber: eps.GetShelfSerialNumber(),
		},
		Bmcs: []*flowv1.BMCInfo{
			{
				Type:       flowv1.BMCType_BMC_TYPE_HOST,
				MacAddress: eps.GetBmcMacAddress(),
			},
		},
		ComponentId: eps.GetExpectedPowerShelfId().GetValue(),
	}

	// DeviceInfo fields
	if name := eps.GetName(); name != "" {
		component.Info.Name = name
	}
	if manufacturer := eps.GetManufacturer(); manufacturer != "" {
		component.Info.Manufacturer = manufacturer
	}
	if eps.Model != nil {
		component.Info.Model = eps.Model
	}
	if eps.Description != nil {
		component.Info.Description = eps.Description
	}

	// Rack position
	if eps.SlotId != nil || eps.TrayIdx != nil || eps.HostId != nil {
		pos := &flowv1.RackPosition{}
		if eps.SlotId != nil {
			pos.SlotId = *eps.SlotId
		}
		if eps.TrayIdx != nil {
			pos.TrayIdx = *eps.TrayIdx
		}
		if eps.HostId != nil {
			pos.HostId = *eps.HostId
		}
		component.Position = pos
	}

	if eps.GetBmcIpAddress() != "" {
		ipAddr := eps.GetBmcIpAddress()
		component.Bmcs[0].IpAddress = &ipAddr
	}

	if rackID := eps.GetRackId().GetId(); rackID != "" {
		component.RackId = &flowv1.UUID{Id: rackID}
	}

	return component
}

// DeleteExpectedPowerShelfOnSite deletes Expected Power Shelf on NICo
func (meps *ManageExpectedPowerShelf) DeleteExpectedPowerShelfOnSite(ctx context.Context, request *corev1.ExpectedPowerShelfRequest) error {
	logger := log.With().Str("Activity", "DeleteExpectedPowerShelfOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty delete Expected Power Shelf request")
	} else if request.GetExpectedPowerShelfId().GetValue() == "" {
		err = errors.New("received delete Expected Power Shelf request without required id field")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := meps.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.DeleteExpectedPowerShelf(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to delete Expected Power Shelf using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}
