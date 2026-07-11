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

// ManageExpectedSwitchInventory is an activity wrapper for Expected Switch inventory collection and publishing
type ManageExpectedSwitchInventory struct {
	siteID                uuid.UUID
	coreGrpcAtomicClient  *cclient.CoreGrpcAtomicClient
	temporalPublishClient tClient.Client
	temporalPublishQueue  string
	cloudPageSize         int
}

type linkedExpectedSwitchInfo struct {
	expectedSwitch       *corev1.ExpectedSwitch
	linkedExpectedSwitch *corev1.LinkedExpectedSwitch
}

// DiscoverExpectedSwitchInventory is an activity to collect Expected Switch inventory and publish to Temporal queue
func (mesi *ManageExpectedSwitchInventory) DiscoverExpectedSwitchInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverExpectedSwitchInventory").Logger()
	logger.Info().Msg("Starting activity")

	// Define workflow options
	workflowOptions := tClient.StartWorkflowOptions{
		ID:        "update-expectedswitch-inventory-" + mesi.siteID.String(),
		TaskQueue: mesi.temporalPublishQueue,
	}

	// Get Site Controller gRPC client
	grpcClient := mesi.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	// Call GetAllExpectedSwitches to get full list of ExpectedSwitches on Site
	esList, err := grpcServiceClient.GetAllExpectedSwitches(ctx, &emptypb.Empty{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve ExpectedSwitches using Core gRPC API")

		// Error encountered before we've published anything, report inventory collection error to Cloud
		inventory := &corev1.ExpectedSwitchInventory{
			Timestamp: &timestamppb.Timestamp{
				Seconds: time.Now().Unix(),
			},
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       err.Error(),
		}

		_, serr := mesi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedSwitchInventory", mesi.siteID, inventory)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedSwitch inventory error to Cloud")
			return serr
		}
		return err
	}

	// Call GetAllExpectedSwitchesLinked to get linked Switch IDs
	linkedList, lerr := grpcServiceClient.GetAllExpectedSwitchesLinked(ctx, &emptypb.Empty{})
	if lerr != nil {
		logger.Warn().Err(lerr).Msg("Failed to retrieve linked Switch IDs using Core gRPC API")

		// Fatal error - report inventory collection error to Cloud
		inventory := &corev1.ExpectedSwitchInventory{
			Timestamp: &timestamppb.Timestamp{
				Seconds: time.Now().Unix(),
			},
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       lerr.Error(),
		}

		_, serr := mesi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedSwitchInventory", mesi.siteID, inventory)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedSwitch inventory error to Cloud")
			return serr
		}
		return lerr
	}

	// LinkedExpectedSwitch data is missing ExpectedSwitch ID so we build an intermediate map using MAC address
	linkedSwitchesByKey := make(map[string]*corev1.LinkedExpectedSwitch)
	for _, linked := range linkedList.ExpectedSwitches {
		linkedSwitchesByKey[linked.BmcMacAddress] = linked
	}

	// Build list of ExpectedSwitch paired with LinkedExpectedSwitch
	linkedExpectedSwitchesInfo := []linkedExpectedSwitchInfo{}
	allExpectedSwitchIDs := []string{}
	for _, es := range esList.ExpectedSwitches {
		// Discard records without ID
		if es.ExpectedSwitchId == nil || es.ExpectedSwitchId.Value == "" {
			logger.Warn().Str("MAC", es.BmcMacAddress).Str("Serial", es.SwitchSerialNumber).Msg("Discarding ExpectedSwitch without ID")
			continue
		}
		allExpectedSwitchIDs = append(allExpectedSwitchIDs, es.ExpectedSwitchId.Value)
		// Find matching LinkedSwitch record by MAC address if it exists
		linked := linkedSwitchesByKey[es.BmcMacAddress]
		linkedExpectedSwitchesInfo = append(linkedExpectedSwitchesInfo, linkedExpectedSwitchInfo{
			expectedSwitch:       es,
			linkedExpectedSwitch: linked,
		})
	}
	totalCount := len(linkedExpectedSwitchesInfo)

	logger.Info().Int("ExpectedSwitch Count", totalCount).Msg("Built ExpectedSwitch list")

	if totalCount == 0 {
		inventoryPage := getPagedExpectedSwitchInventory([]linkedExpectedSwitchInfo{}, allExpectedSwitchIDs, totalCount, 1, mesi.cloudPageSize, corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS, "No ExpectedSwitches reported by Site Controller")

		_, serr := mesi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateExpectedSwitchInventory", mesi.siteID, inventoryPage)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish ExpectedSwitch inventory to Cloud")
			return serr
		}
		return nil
	}

	// Calculate total pages needed for Cloud
	totalCloudPages := totalCount / mesi.cloudPageSize
	if totalCount%mesi.cloudPageSize > 0 {
		totalCloudPages++
	}

	// Publish ExpectedSwitch inventory to Cloud in separate chunks
	for cloudPage := 1; cloudPage <= totalCloudPages; cloudPage++ {
		startIndex := (cloudPage - 1) * mesi.cloudPageSize
		endIndex := startIndex + mesi.cloudPageSize
		if endIndex > totalCount {
			endIndex = totalCount
		}

		pagedWorkflowOptions := client.StartWorkflowOptions{
			ID:        fmt.Sprintf("%v-%v", workflowOptions.ID, cloudPage),
			TaskQueue: workflowOptions.TaskQueue,
		}

		// Create an inventory page with the subset of ExpectedSwitches
		// Slice the list directly for this page
		pagedInfo := linkedExpectedSwitchesInfo[startIndex:endIndex]
		inventoryPage := getPagedExpectedSwitchInventory(
			pagedInfo,
			allExpectedSwitchIDs,
			totalCount,
			cloudPage,
			mesi.cloudPageSize,
			corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS,
			"Successfully retrieved ExpectedSwitches from Site Controller",
		)

		logger.Info().Msgf("Publishing ExpectedSwitch inventory page %d to Cloud", cloudPage)

		_, serr := mesi.temporalPublishClient.ExecuteWorkflow(context.Background(), pagedWorkflowOptions, "UpdateExpectedSwitchInventory", mesi.siteID, inventoryPage)
		if serr != nil {
			logger.Error().Err(serr).Int("Cloud Page", cloudPage).Msg("Failed to publish ExpectedSwitch inventory to Cloud")
			return serr
		}
	}

	return nil
}

// getPagedExpectedSwitchInventory returns a subset of ExpectedSwitchInventory for a given page
func getPagedExpectedSwitchInventory(
	pagedInfo []linkedExpectedSwitchInfo,
	allExpectedSwitchIDs []string,
	totalCount int,
	page int,
	pageSize int,
	status corev1.InventoryStatus,
	statusMessage string,
) *corev1.ExpectedSwitchInventory {
	totalPages := totalCount / pageSize
	if totalCount%pageSize > 0 {
		totalPages++
	}

	// Build lists for this page from the sliced info list
	pagedExpectedSwitches := make([]*corev1.ExpectedSwitch, 0, len(pagedInfo))
	pagedLinkedSwitches := make([]*corev1.LinkedExpectedSwitch, 0, len(pagedInfo))

	for _, info := range pagedInfo {
		pagedExpectedSwitches = append(pagedExpectedSwitches, info.expectedSwitch)
		// Only add LinkedExpectedSwitch if it exists (it may be nil if no match was found)
		if info.linkedExpectedSwitch != nil {
			pagedLinkedSwitches = append(pagedLinkedSwitches, info.linkedExpectedSwitch)
		}
	}

	// Create an inventory page with the subset of ExpectedSwitches and matching LinkedSwitches
	inventoryPage := &corev1.ExpectedSwitchInventory{
		ExpectedSwitches: pagedExpectedSwitches,
		LinkedSwitches:   pagedLinkedSwitches,
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
			ItemIds:     allExpectedSwitchIDs,
		},
	}

	return inventoryPage
}

// NewManageExpectedSwitchInventory returns a ManageInventory implementation for Expected Switch activity
func NewManageExpectedSwitchInventory(siteID uuid.UUID, coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient, temporalPublishClient tClient.Client, temporalPublishQueue string, cloudPageSize int) ManageExpectedSwitchInventory {
	return ManageExpectedSwitchInventory{
		siteID:                siteID,
		coreGrpcAtomicClient:  coreGrpcAtomicClient,
		temporalPublishClient: temporalPublishClient,
		temporalPublishQueue:  temporalPublishQueue,
		cloudPageSize:         cloudPageSize,
	}
}

// ManageExpectedSwitch is an activity wrapper for Expected Switch management
type ManageExpectedSwitch struct {
	coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient
	flowGrpcAtomicClient *cclient.FlowGrpcAtomicClient
}

// NewManageExpectedSwitch returns a new ManageExpectedSwitch client
func NewManageExpectedSwitch(coreGrpcAtomicClient *cclient.CoreGrpcAtomicClient, flowGrpcAtomicClient *cclient.FlowGrpcAtomicClient) ManageExpectedSwitch {
	return ManageExpectedSwitch{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
		flowGrpcAtomicClient: flowGrpcAtomicClient,
	}
}

// CreateExpectedSwitchOnSite creates Expected Switch with NICo
func (mes *ManageExpectedSwitch) CreateExpectedSwitchOnSite(ctx context.Context, request *corev1.ExpectedSwitch) error {
	logger := log.With().Str("Activity", "CreateExpectedSwitchOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty create Expected Switch request")
	} else if request.GetExpectedSwitchId().GetValue() == "" {
		err = errors.New("received create Expected Switch request without required id field")
	} else if request.GetBmcMacAddress() == "" || request.GetSwitchSerialNumber() == "" {
		err = errors.New("received create Expected Switch request with missing MAC or serial")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	// Call Core gRPC endpoint
	start := time.Now()
	_, err = grpcServiceClient.AddExpectedSwitch(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to create Expected Switch using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// UpdateExpectedSwitchOnSite updates Expected Switch on NICo
func (mes *ManageExpectedSwitch) UpdateExpectedSwitchOnSite(ctx context.Context, request *corev1.ExpectedSwitch) error {
	logger := log.With().Str("Activity", "UpdateExpectedSwitchOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty update Expected Switch request")
	} else if request.GetExpectedSwitchId().GetValue() == "" {
		err = errors.New("received update Expected Switch request without required id field")
	} else if request.GetBmcMacAddress() == "" || request.GetSwitchSerialNumber() == "" {
		err = errors.New("received update Expected Switch request with missing MAC or serial")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.UpdateExpectedSwitch(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to update Expected Switch using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// CreateExpectedSwitchOnFlow creates an Expected Switch as a component in Flow via AddComponent
func (mes *ManageExpectedSwitch) CreateExpectedSwitchOnFlow(ctx context.Context, request *corev1.ExpectedSwitch) error {
	logger := log.With().Str("Activity", "CreateExpectedSwitchOnFlow").Logger()

	logger.Info().Msg("Starting activity")

	// Validate request
	if request == nil {
		return temporal.NewNonRetryableApplicationError("received empty create Expected Switch request for Flow", swe.ErrTypeInvalidRequest, errors.New("nil request"))
	}

	// If Flow client is not configured, skip gracefully
	if mes.flowGrpcAtomicClient == nil {
		logger.Warn().Msg("Flow client not configured, skipping Flow component creation")
		return nil
	}

	grpcClient := mes.flowGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		logger.Warn().Msg("Flow client not connected, skipping Flow component creation")
		return nil
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	component := expectedSwitchToFlowComponent(request)
	_, err := grpcServiceClient.AddComponent(ctx, &flowv1.AddComponentRequest{Component: component})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create Expected Switch component on Flow")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")
	return nil
}

// expectedSwitchToFlowComponent converts a NICo ExpectedSwitch proto to an Flow Component proto
func expectedSwitchToFlowComponent(es *corev1.ExpectedSwitch) *flowv1.Component {
	component := &flowv1.Component{
		Type: flowv1.ComponentType_COMPONENT_TYPE_NVSWITCH,
		Info: &flowv1.DeviceInfo{
			Id:           &flowv1.UUID{Id: es.GetExpectedSwitchId().GetValue()},
			SerialNumber: es.GetSwitchSerialNumber(),
		},
		Bmcs: []*flowv1.BMCInfo{
			{
				Type:       flowv1.BMCType_BMC_TYPE_HOST,
				MacAddress: es.GetBmcMacAddress(),
			},
		},
		ComponentId: es.GetExpectedSwitchId().GetValue(),
	}

	// DeviceInfo fields
	if name := es.GetName(); name != "" {
		component.Info.Name = name
	}
	if manufacturer := es.GetManufacturer(); manufacturer != "" {
		component.Info.Manufacturer = manufacturer
	}
	if es.Model != nil {
		component.Info.Model = es.Model
	}
	if es.Description != nil {
		component.Info.Description = es.Description
	}

	// Rack position
	if es.SlotId != nil || es.TrayIdx != nil || es.HostId != nil {
		pos := &flowv1.RackPosition{}
		if es.SlotId != nil {
			pos.SlotId = *es.SlotId
		}
		if es.TrayIdx != nil {
			pos.TrayIdx = *es.TrayIdx
		}
		if es.HostId != nil {
			pos.HostId = *es.HostId
		}
		component.Position = pos
	}

	if rackID := es.GetRackId().GetId(); rackID != "" {
		component.RackId = &flowv1.UUID{Id: rackID}
	}

	return component
}

// DeleteExpectedSwitchOnSite deletes Expected Switch on NICo
func (mes *ManageExpectedSwitch) DeleteExpectedSwitchOnSite(ctx context.Context, request *corev1.ExpectedSwitchRequest) error {
	logger := log.With().Str("Activity", "DeleteExpectedSwitchOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty delete Expected Switch request")
	} else if request.GetExpectedSwitchId().GetValue() == "" {
		err = errors.New("received delete Expected Switch request without required id field")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint
	grpcClient := mes.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cclient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.DeleteExpectedSwitch(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to delete Expected Switch using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}
