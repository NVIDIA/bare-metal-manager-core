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
)

// ManageVpcPeering is an activity wrapper for VpcPeering management
type ManageVpcPeering struct {
	coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient
}

// NewManageVpcPeering returns a new ManageVpcPeering client
func NewManageVpcPeering(coreGrpcAtomicClient *cClient.CoreGrpcAtomicClient) ManageVpcPeering {
	return ManageVpcPeering{
		coreGrpcAtomicClient: coreGrpcAtomicClient,
	}
}

// Function to create VpcPeering with NICo
func (mvp *ManageVpcPeering) CreateVpcPeeringOnSite(ctx context.Context, request *cwssaws.VpcPeeringCreationRequest) error {
	logger := log.With().Str("Activity", "CreateVpcPeeringOnSite").Logger()

	logger.Info().Msg("Starting activity'")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty create VpcPeering request")
	} else if request.VpcId == nil || request.VpcId.Value == "" {
		err = errors.New("received create VpcPeering request missing VpcId")
	} else if request.PeerVpcId == nil || request.PeerVpcId.Value == "" {
		err = errors.New("received create VpcPeering request missing PeerVpcId")
	} else if request.Id == nil || request.Id.Value == "" {
		// Don't let a request come in without a cloud-provided ID
		// or carbide will generate one and cloud won't know the relationship.
		err = errors.New("received create VpcPeering request missing VPC peering ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API
	grpcClient := mvp.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.CreateVpcPeering(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to create VpcPeering using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// Function to delete VpcPeering on NICo
func (mvp *ManageVpcPeering) DeleteVpcPeeringOnSite(ctx context.Context, request *cwssaws.VpcPeeringDeletionRequest) error {
	logger := log.With().Str("Activity", "DeleteVpcPeeringOnSite").Logger()

	logger.Info().Msg("Starting activity")

	var err error

	// Validate request
	if request == nil {
		err = errors.New("received empty delete VpcPeering request")
	} else if request.Id == nil || request.Id.Value == "" {
		err = errors.New("received delete VpcPeering request missing VPC peering ID")
	}

	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), swe.ErrTypeInvalidRequest, err)
	}

	// Call Core gRPC API
	grpcClient := mvp.coreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}
	grpcServiceClient := grpcClient.GrpcServiceClient()

	_, err = grpcServiceClient.DeleteVpcPeering(ctx, request)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to delete VpcPeering using Core gRPC API")
		return swe.WrapErr(err)
	}

	logger.Info().Msg("Completed activity")

	return nil
}

// ManageVpcPeeringInventory is an activity wrapper for VpcPeering inventory collection and publishing
type ManageVpcPeeringInventory struct {
	config ManageInventoryConfig
}

func NewManageVpcPeeringInventory(config ManageInventoryConfig) ManageVpcPeeringInventory {
	return ManageVpcPeeringInventory{
		config: config,
	}
}

// DiscoverVpcPeeringInventory is an activity to collect VpcPeering inventory and publish to Temporal queue
func (mvi *ManageVpcPeeringInventory) DiscoverVpcPeeringInventory(ctx context.Context) error {
	logger := log.With().Str("Activity", "DiscoverVpcPeeringInventory").Logger()
	logger.Info().Msg("Starting activity")

	inventoryImpl := manageInventoryImpl[*cwssaws.VpcPeeringId, *cwssaws.VpcPeering, *cwssaws.VPCPeeringInventory]{
		itemType:               "VpcPeering",
		config:                 mvi.config,
		internalFindIDs:        vpcPeeringFindIDs,
		internalFindByIDs:      vpcPeeringFindByIDs,
		internalPagedInventory: vpcPeeringPagedInventory,
	}
	return inventoryImpl.CollectAndPublishInventory(ctx, &logger)
}

func vpcPeeringFindIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient) ([]*cwssaws.VpcPeeringId, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	resp, err := grpcServiceClient.FindVpcPeeringIds(ctx, &cwssaws.VpcPeeringSearchFilter{})
	if err != nil {
		return nil, err
	}
	return resp.VpcPeeringIds, nil
}

func vpcPeeringFindByIDs(ctx context.Context, grpcClient *cClient.CoreGrpcClient, ids []*cwssaws.VpcPeeringId) ([]*cwssaws.VpcPeering, error) {
	grpcServiceClient := grpcClient.GrpcServiceClient()
	req := &cwssaws.VpcPeeringsByIdsRequest{
		VpcPeeringIds: ids,
	}
	resp, err := grpcServiceClient.FindVpcPeeringsByIds(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetVpcPeerings(), nil
}

func vpcPeeringPagedInventory(allItemIDs []*cwssaws.VpcPeeringId, pagedItems []*cwssaws.VpcPeering, input *pagedInventoryInput) *cwssaws.VPCPeeringInventory {
	itemIDs := []string{}
	for _, id := range allItemIDs {
		itemIDs = append(itemIDs, id.GetValue())
	}

	// Create an inventory page with the subset of VpcPeerings
	inventory := &cwssaws.VPCPeeringInventory{
		VpcPeerings: pagedItems,
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
