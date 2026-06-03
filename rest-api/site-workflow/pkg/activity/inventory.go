// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package activity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cClient "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/grpc/client"
	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tClient "go.temporal.io/sdk/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ManageInventoryConfig struct {
	SiteID                uuid.UUID
	CoreGrpcAtomicClient  *cClient.CoreGrpcAtomicClient
	TemporalPublishClient tClient.Client
	TemporalPublishQueue  string
	SitePageSize          int
	CloudPageSize         int
}

type manageInventoryImpl[K any, R any, P any] struct {
	itemType               string
	config                 ManageInventoryConfig
	internalFindIDs        func(context.Context, *cClient.CoreGrpcClient) ([]K, error)
	internalFindByIDs      func(context.Context, *cClient.CoreGrpcClient, []K) ([]R, error)
	internalPagedInventory func([]K, []R, *pagedInventoryInput) P
	// post-processing function that can optionally be used to attach additional inventory data
	// based on the data in the inventory.  This will only be called for pages with inventory.
	internalPagedInventoryPostProcess func(context.Context, *cClient.CoreGrpcClient, P) (P, error)
	// fallback function to get all the items when pagination is not supported
	internalFindFallback func(ctx context.Context, client *cClient.CoreGrpcClient) ([]K, []R, error)
}

type pagedInventoryInput struct {
	// total number of items we need to publish
	totalItems int
	// total number of pages we need to publish
	totalPages int
	// size of the page
	pageSize int
	// current page number
	pageNumber int
	// status
	status        cwssaws.InventoryStatus
	statusMessage string
}

func (pii *pagedInventoryInput) buildPage() *cwssaws.InventoryPage {
	// if we are reporting an error, we do not want to include paging information
	if pii.status != cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS {
		return nil
	}
	return &cwssaws.InventoryPage{
		TotalPages:  int32(pii.totalPages),
		CurrentPage: int32(pii.pageNumber),
		PageSize:    int32(pii.pageSize),
		TotalItems:  int32(pii.totalItems),
	}
}

func buildPagedInventoryInput(totalCount int, pageSize int) *pagedInventoryInput {
	input := &pagedInventoryInput{
		totalItems: totalCount,
		pageSize:   pageSize,
	}
	input.totalPages = totalCount / pageSize
	if totalCount%pageSize > 0 {
		input.totalPages++
	}
	return input
}

func (impl *manageInventoryImpl[K, R, P]) CollectAndPublishInventory(ctx context.Context, logger *zerolog.Logger) error {
	// Define workflow options
	workflowOptions := tClient.StartWorkflowOptions{
		ID:        fmt.Sprintf("update-%s-inventory-%s", strings.ToLower(impl.itemType), impl.config.SiteID.String()),
		TaskQueue: impl.config.TemporalPublishQueue,
	}

	// define workflow name
	workflowName := fmt.Sprintf("Update%sInventory", impl.itemType)
	// get Core gRPC client
	grpcClient := impl.config.CoreGrpcAtomicClient.GetClient()
	if grpcClient == nil {
		return cClient.ErrCoreGrpcClientNotConnected
	}

	// find IDs
	allIDs, err := impl.internalFindIDs(ctx, grpcClient)
	if err != nil {
		if grpcStatus, ok := status.FromError(err); ok {
			if grpcStatus.Code() == codes.Unimplemented {
				log.Info().Msg("Using fallback API to get inventory")
				if err = impl.collectAndPublishFallback(ctx, logger, grpcClient, workflowName, workflowOptions); err == nil {
					return err
				}
			}
		}
		logger.Warn().Err(err).Msg("Failed to retrieve IDs using Core gRPC API")
		// Error encountered before we've published anything, report inventory collection error to Cloud
		pagedInput := buildPagedInventoryInput(0, impl.config.CloudPageSize)
		pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED
		pagedInput.statusMessage = err.Error()
		inventory := impl.internalPagedInventory([]K{}, []R{}, pagedInput)
		if _, execErr := impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventory); execErr != nil {
			logger.Error().Err(execErr).Msg("Failed to publish inventory error to Cloud")
			return execErr
		}
		return err
	}

	// build paged inventory input with common values
	pagedInput := buildPagedInventoryInput(len(allIDs), impl.config.CloudPageSize)
	if pagedInput.totalItems == 0 {
		pagedInput.pageNumber = 1
		pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS
		pagedInput.statusMessage = "No items reported by Site Controller"
		inventoryPage := impl.internalPagedInventory([]K{}, []R{}, pagedInput)

		logger.Info().Msg("Publishing empty inventory page to Cloud")

		if _, err := impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventoryPage); err != nil {
			logger.Error().Err(err).Msg("Failed to publish inventory to Cloud")
			return err
		}
	}

	// Iterate through all pages and publish inventory
	cloudEffectivePage := 1
	sitePagedIDs := cClient.SliceToChunks(allIDs, impl.config.SitePageSize)
	for sitePage, siteItemIDs := range sitePagedIDs {
		// find items by IDs
		siteItems, err := impl.internalFindByIDs(ctx, grpcClient, siteItemIDs)
		if err != nil {
			logger.Warn().Err(err).Int("Site Page", sitePage+1).Msg("Failed to retrieve using Core gRPC API")
			return err
		}

		// We could return an error, but that might get us caught in
		// a scenerio where deletes on site between FindIDs and FindByIDs
		// calls creates a mismatch that fails.  If we log the error, we could
		// alert on it without letting it break inventory entirely.
		if len(siteItems) != len(siteItemIDs) {
			logger.Error().Msg("size of FindByIDs set does not match size of FindIDs set")
		}

		// publish inventory to Cloud in separate chunks
		cloudItems := cClient.SliceToChunks(siteItems, impl.config.CloudPageSize)
		for _, items := range cloudItems {
			workflowOptions := tClient.StartWorkflowOptions{
				ID:        fmt.Sprintf("%v-%v", workflowOptions.ID, cloudEffectivePage),
				TaskQueue: workflowOptions.TaskQueue,
			}
			// Create an inventory page
			pagedInput.pageNumber = cloudEffectivePage
			pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS
			pagedInput.statusMessage = "Successfully retrieved from Site Controller"
			inventoryPage := impl.internalPagedInventory(allIDs, items, pagedInput)

			// Handle any requested post processing
			if impl.internalPagedInventoryPostProcess != nil {
				inventoryPage, err = impl.internalPagedInventoryPostProcess(ctx, grpcClient, inventoryPage)
				if err != nil {
					return err
				}
			}

			// publish
			logger.Info().Msgf("Publishing inventory page %d to Cloud", cloudEffectivePage)
			if _, err = impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventoryPage); err != nil {
				logger.Error().Err(err).Int("Cloud Page", cloudEffectivePage).Msg("Failed to publish inventory to Cloud")
				return err
			}
			cloudEffectivePage++
		}
	}

	return nil
}

func (impl *manageInventoryImpl[K, R, P]) collectAndPublishFallback(ctx context.Context, logger *zerolog.Logger,
	grpcClient *cClient.CoreGrpcClient, workflowName string, workflowOptions tClient.StartWorkflowOptions) error {
	if impl.internalFindFallback == nil {
		return errors.New("no fallback find function defined")
	}
	allIDs, siteItems, err := impl.internalFindFallback(ctx, grpcClient)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to retrieve using Site Controller fallback API")
		// Error encountered before we've published anything, report inventory collection error to Cloud
		pagedInput := buildPagedInventoryInput(0, impl.config.CloudPageSize)
		pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_FAILED
		pagedInput.statusMessage = err.Error()
		inventory := impl.internalPagedInventory([]K{}, []R{}, pagedInput)
		if _, execErr := impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventory); execErr != nil {
			logger.Error().Err(execErr).Msg("Failed to publish inventory error to Cloud")
			return execErr
		}
		return err
	}

	// build paged inventory input with common values
	pagedInput := buildPagedInventoryInput(len(allIDs), impl.config.CloudPageSize)
	if pagedInput.totalItems == 0 {
		pagedInput.pageNumber = 1
		pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS
		pagedInput.statusMessage = "No items reported by Site Controller"
		inventoryPage := impl.internalPagedInventory([]K{}, []R{}, pagedInput)

		logger.Info().Msg("Publishing empty inventory page to Cloud")

		if _, err := impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventoryPage); err != nil {
			logger.Error().Err(err).Msg("Failed to publish inventory to Cloud")
			return err
		}
	}

	// publish inventory to Cloud in separate chunks
	cloudItems := cClient.SliceToChunks(siteItems, impl.config.CloudPageSize)
	for page, items := range cloudItems {
		workflowOptions := tClient.StartWorkflowOptions{
			ID:        fmt.Sprintf("%v-%v", workflowOptions.ID, page),
			TaskQueue: workflowOptions.TaskQueue,
		}
		// Create an inventory page
		pagedInput.pageNumber = page + 1
		pagedInput.status = cwssaws.InventoryStatus_INVENTORY_STATUS_SUCCESS
		pagedInput.statusMessage = "Successfully retrieved from Site Controller"
		inventoryPage := impl.internalPagedInventory(allIDs, items, pagedInput)

		// Handle any requested post processing
		if impl.internalPagedInventoryPostProcess != nil {
			inventoryPage, err = impl.internalPagedInventoryPostProcess(ctx, grpcClient, inventoryPage)
			if err != nil {
				return err
			}
		}

		// publish
		logger.Info().Msgf("Publishing inventory page %d to Cloud", page+1)
		if _, err = impl.config.TemporalPublishClient.ExecuteWorkflow(context.Background(), workflowOptions, workflowName, impl.config.SiteID, inventoryPage); err != nil {
			logger.Error().Err(err).Int("Cloud Page", page+1).Msg("Failed to publish inventory to Cloud")
			return err
		}
	}
	return nil
}
