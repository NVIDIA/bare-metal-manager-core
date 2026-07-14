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
	"google.golang.org/protobuf/types/known/timestamppb"

	cClient "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/grpc/client"

	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"

	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
)

// ManageMachine is an activity wrapper for Machine management tasks that allows injecting DB access
type ManageMachine struct {
	coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
}

// SetMachineMaintenanceOnSite is an activity to set Machine maintenance mode using Core gRPC API
func (mm *ManageMachine) SetMachineMaintenanceOnSite(ctx context.Context, request *corev1.MaintenanceRequest) error {
	logger := log.With().Str("Activity", "SetMachineMaintenanceActivity").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty Machine maintenance request")
	} else if request.HostId == nil || request.HostId.Id == "" {
		err = errors.New("received Machine maintenance request without Machine ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC endpoint to set SetMaintenance request
	grpcClient := mm.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.SetMaintenance(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to set Maintenance mode for Machine using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return err
}

// UpdateMachineMetadataOnSite is an activity to update Machine metadata using Core gRPC API
func (mm *ManageMachine) UpdateMachineMetadataOnSite(ctx context.Context, request *corev1.MachineMetadataUpdateRequest) error {
	logger := log.With().Str("Activity", "UpdateMachineMetadataOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty Machine metadata update request")
	} else if request.MachineId == nil || request.MachineId.Id == "" {
		err = errors.New("received Machine metadata update request without Machine ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC endpoint to update Machine metadata
	grpcClient := mm.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err = grpcServiceClient.UpdateMachineMetadata(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to update Machine metadata using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return err
}

// CreateMachineHealthReportOnSite applies a health report on the Site controller.
func (mm *ManageMachine) CreateMachineHealthReportOnSite(ctx context.Context, request *corev1.InsertMachineHealthReportRequest) error {
	logger := log.With().Str("Activity", "CreateMachineHealthReportOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil || request.MachineId == nil || request.MachineId.Id == "" || request.HealthReportEntry == nil || request.HealthReportEntry.Report == nil {
		return temporal.NewNonRetryableApplicationError("invalid InsertMachineHealthReportRequest request", swe.ErrTypeInvalidRequest, errors.New("missing machine id or health report entry"))
	}

	grpcClient := mm.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err := grpcServiceClient.InsertMachineHealthReport(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to insert Machine health report using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// DeleteMachineHealthReportOnSite removes a health report override on the Site controller.
func (mm *ManageMachine) DeleteMachineHealthReportOnSite(ctx context.Context, request *corev1.RemoveMachineHealthReportRequest) error {
	logger := log.With().Str("Activity", "DeleteMachineHealthReportOnSite").Logger()
	logger.Info().Msg("Starting activity")

	if request == nil || request.MachineId == nil || request.MachineId.Id == "" || request.Source == "" {
		return temporal.NewNonRetryableApplicationError("invalid RemoveMachineHealthReportRequest request", swe.ErrTypeInvalidRequest, errors.New("missing machine id or source"))
	}

	grpcClient := mm.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	start := time.Now()
	_, err := grpcServiceClient.RemoveMachineHealthReport(ctx, request)
	duration := time.Since(start)
	if err != nil {
		logger.Warn().Err(err).Dur("grpc_duration", duration).Msg("Failed to remove Machine health report using Core gRPC API")
		return swe.WrapErr(err)
	}
	logger.Info().Dur("grpc_duration", duration).Msg("Completed activity")

	return nil
}

// GetDpuMachinesByIDs is an activity to retrieve DPU Machines by IDs with network configuration
func (mm *ManageMachine) GetDpuMachinesByIDs(ctx context.Context, dpuMachineIDs []string) ([]*corev1.DpuMachine, error) {
	logger := log.With().Str("Activity", "GetDpuMachinesByIDs").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if len(dpuMachineIDs) == 0 {
		err = errors.New("received GetDpuMachinesByIDs request without DPU Machine IDs")
		return nil, temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API endpoint to get DPU Machines by IDs
	grpcClient := mm.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return nil, cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	// Convert string IDs to MachineId objects
	machineIDs := make([]*corev1.MachineId, 0, len(dpuMachineIDs))
	for _, id := range dpuMachineIDs {
		machineIDs = append(machineIDs, &corev1.MachineId{Id: id})
	}

	request := &corev1.MachinesByIdsRequest{
		MachineIds: machineIDs,
	}

	machineList, err := grpcServiceClient.FindMachinesByIds(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve DPU Machines by IDs using Core gRPC API")
		return nil, swe.WrapErr(err)
	}

	// For each DPU machine, fetch the network configuration
	dpuMachines := make([]*corev1.DpuMachine, 0, len(machineList.Machines))
	for _, machine := range machineList.Machines {
		if machine.MachineType == corev1.MachineType_DPU {
			networkConfigReq := &corev1.ManagedHostNetworkConfigRequest{
				DpuMachineId: machine.Id,
			}
			networkConfig, nerr := grpcServiceClient.GetManagedHostNetworkConfig(ctx, networkConfigReq)
			if nerr != nil {
				logger.Warn().Err(nerr).Str("DPU Machine ID", machine.Id.Id).Msg("Failed to retrieve network config for DPU machine, continuing without it")
				// Don't fail the entire request if network config is unavailable
			}

			logger.Debug().Str("DPU Machine ID", machine.Id.Id).Msg("Retrieved network config for DPU machine")
			dpuMachines = append(dpuMachines, &corev1.DpuMachine{
				Machine:          machine,
				DpuNetworkConfig: networkConfig,
			})
		}
	}

	logger.Info().Int("DPU Machine Count", len(dpuMachines)).Msg("Completed activity")

	return dpuMachines, nil
}

// NewManageMachine returns a new ManageMachine activity
func NewManageMachine(coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient) ManageMachine {
	return ManageMachine{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
	}
}

// ManageMachineInventory is an activity wrapper for Machine inventory collection and publishing
type ManageMachineInventory struct {
	siteID                uuid.UUID
	coreGrpcAtomicClient  *cClient.CoreGrpcAtomicClient
	temporalPublishClient tClient.Client
	temporalPublishQueue  string
	sitePageSize          int
	cloudPageSize         int
}

// CollectAndPublishMachineInventory is an activity to collect Machine inventory and publish to Temporal queue
func (mmi *ManageMachineInventory) CollectAndPublishMachineInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "CollectAndPublishMachineInventory").Logger()

	logger.Info().Msg("Starting activity")

	// Define workflow options
	workflowOptions := tClient.StartWorkflowOptions{
		ID:        "update-machine-inventory-" + mmi.siteID.String(),
		TaskQueue: mmi.temporalPublishQueue,
	}

	// Call Core gRPC endpoint to get available Machine IDs
	grpcClient := mmi.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	machineIDList, err := grpcServiceClient.FindMachineIds(ctx, &corev1.MachineSearchConfig{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve available Machine IDs using Core gRPC API")

		// Error encountered before we've published anything, report inventory collection error to Cloud
		inventory := &corev1.MachineInventory{
			Timestamp: &timestamppb.Timestamp{
				Seconds: time.Now().Unix(),
			},
			InventoryStatus: corev1.InventoryStatus_INVENTORY_STATUS_FAILED,
			StatusMsg:       err.Error(),
		}

		_, serr := mmi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateMachineInventory", mmi.siteID, inventory)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish Machine inventory error to Cloud")
			return serr
		}
		return err
	}

	// Paginate IDs and collect Machine inventory
	totalSiteCount := len(machineIDList.MachineIds)
	totalSitePages := len(machineIDList.MachineIds) / mmi.sitePageSize
	if totalSiteCount%mmi.sitePageSize > 0 {
		totalSitePages++
	}

	allMachineIDs := []*corev1.MachineId{}
	allMachineIDs = append(allMachineIDs, machineIDList.MachineIds...)

	if totalSitePages == 0 {
		inventoryPage := getPagedMachineInventory([]*corev1.Machine{}, allMachineIDs, totalSiteCount, 1, mmi.cloudPageSize, corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS, "No Machines reported by SIte Controller")

		_, serr := mmi.temporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, "UpdateMachineInventory", mmi.siteID, inventoryPage)
		if serr != nil {
			logger.Error().Err(serr).Msg("Failed to publish Machine inventory to Cloud")
			return serr
		}
	}

	// Iterate through all pages and publish Machine inventory
	effectiveCloudPage := 1
	for sitePage := 1; sitePage <= totalSitePages; sitePage++ {
		pagedMachineIDs := getPagedMachineIDs(machineIDList.MachineIds, sitePage, mmi.sitePageSize)

		// Call Core gRPC endpoint to get Machines for the paged IDs
		pagedMachines, serr := grpcServiceClient.FindMachinesByIds(ctx, &corev1.MachinesByIdsRequest{
			MachineIds: pagedMachineIDs,
		})
		if serr != nil {
			logger.Warn().Err(serr).Int("Site Page", sitePage).Msg("Failed to retrieve Machines using Core gRPC API")
			return serr
		}

		totalCloudCount := len(pagedMachines.Machines)
		totalCloudPages := len(pagedMachines.Machines) / mmi.cloudPageSize
		if totalCloudCount%mmi.cloudPageSize > 0 {
			totalCloudPages++
		}

		// Publish machine inventory to Cloud in separate chunks
		for cloudPage := 1; cloudPage <= totalCloudPages; cloudPage++ {
			startIndex := (cloudPage - 1) * mmi.cloudPageSize
			endIndex := startIndex + mmi.cloudPageSize
			if endIndex > totalCloudCount {
				endIndex = totalCloudCount
			}

			pagedWorkflowOptions := client.StartWorkflowOptions{
				ID:        fmt.Sprintf("%v-%v", workflowOptions.ID, effectiveCloudPage),
				TaskQueue: workflowOptions.TaskQueue,
			}

			// Create an inventory page with the subset of Machines
			inventoryPage := getPagedMachineInventory(pagedMachines.Machines[startIndex:endIndex], allMachineIDs, totalSiteCount, effectiveCloudPage, mmi.cloudPageSize, corev1.InventoryStatus_INVENTORY_STATUS_SUCCESS, "Successfully retrieved Machines from Site Controller")

			logger.Info().Msgf("Publishing Machine inventory page %d to Cloud", effectiveCloudPage)

			_, serr = mmi.temporalPublishClient.ExecuteWorkflow(context.Background(), pagedWorkflowOptions, "UpdateMachineInventory", mmi.siteID, inventoryPage)
			if serr != nil {
				logger.Error().Err(serr).Int("Cloud Page", effectiveCloudPage).Msg("Failed to publish Machine inventory to Cloud")
				return serr
			}

			effectiveCloudPage++
		}
	}

	return nil
}

// getPagedMachineIDs returns a slice of Machine IDs for a given page
func getPagedMachineIDs(machineIDs []*corev1.MachineId, page int, pageSize int) []*corev1.MachineId {
	totalCount := len(machineIDs)
	startIndex := (page - 1) * pageSize
	endIndex := startIndex + pageSize
	if endIndex > totalCount {
		endIndex = totalCount
	}

	return machineIDs[startIndex:endIndex]
}

// getPagedMachineInventory returns a subset of MachineInventory for a given page
func getPagedMachineInventory(pagedMachines []*corev1.Machine, machineIDs []*corev1.MachineId, totalCount int, page int, pageSize int, status corev1.InventoryStatus, statusMessage string) *corev1.MachineInventory {
	totalPages := (totalCount / pageSize)
	if totalCount%pageSize > 0 {
		totalPages++
	}

	pagedMachineInfo := []*corev1.MachineInfo{}
	for _, machine := range pagedMachines {
		pagedMachineInfo = append(pagedMachineInfo, &corev1.MachineInfo{
			Machine: machine,
		})
	}

	itemIDs := []string{}
	for _, machineID := range machineIDs {
		itemIDs = append(itemIDs, machineID.Id)
	}

	// Create an inventory page with the subset of Machines
	inventoryPage := &corev1.MachineInventory{
		Machines: pagedMachineInfo,
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
			ItemIds:     itemIDs,
		},
	}

	return inventoryPage
}

// NewManageMachineInventory returns a new ManageMachineInventory activity
func NewManageMachineInventory(siteID uuid.UUID, coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient, temporalPublishClient tClient.Client, temporalPublishQueue string, sitePageSize int, cloudPageSize int) ManageMachineInventory {
	return ManageMachineInventory{
		siteID:                siteID,
		coreGrpcAtomicClient:  coreGrpcAtomicClient,
		temporalPublishClient: temporalPublishClient,
		temporalPublishQueue:  temporalPublishQueue,
		sitePageSize:          sitePageSize,
		cloudPageSize:         cloudPageSize,
	}
}
