// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	swe "github.com/NVIDIA/infra-controller-rest/site-workflow/pkg/error"
	wutil "github.com/NVIDIA/infra-controller-rest/workflow/pkg/util"
	"github.com/labstack/echo/v4"

	"go.opentelemetry.io/otel/attribute"
	temporalClient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	common "github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller-rest/api/pkg/client/site"
	auth "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"github.com/NVIDIA/infra-controller-rest/workflow/pkg/queue"
)

// ~~~~~ Create Handler ~~~~~ //

// CreateVPCHandler is the API Handler for creating new VPC
type CreateVPCHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateVPCHandler initializes and returns a new handler for creating Tenant
func NewCreateVPCHandler(dbSession *cdb.Session, tc temporalClient.Client, sc *sc.ClientPool, cfg *config.Config) CreateVPCHandler {
	return CreateVPCHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        sc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Create a VPC
// @Description Create a VPC for the org.
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param message body model.APIVpcCreateRequest true "VPC create request"
// @Success 201 {object} model.APIVpc
// @Router /v2/org/{org}/nico/vpc [post]
func (cvh CreateVPCHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "Create", c, cvh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIVpcCreateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating VPC creation request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating VPC creation request data", verr)
	}

	// Validate the site for which this VPC is being created
	site, err := common.GetSiteFromIDString(ctx, nil, apiRequest.SiteID, cvh.dbSession)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Could not find Site with ID specified in request data", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Site from DB by ID")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Site ID in request data", nil)
	}

	// Verify if site is ready
	if site.Status != cdbm.SiteStatusRegistered {
		logger.Warn().Msg(fmt.Sprintf("Site: %v specified in request data must be in Registered state in order to proceed", site.ID))
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data must be in Registered state in order to proceed", nil)
	}

	// Get Tenant for this org
	tenant, err := common.GetTenantForOrg(ctx, nil, cvh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	// Ensure that Tenant has an Allocation with specified Site
	aDAO := cdbm.NewAllocationDAO(cvh.dbSession)
	allocationFilter := cdbm.AllocationFilterInput{TenantIDs: []uuid.UUID{tenant.ID}, SiteIDs: []uuid.UUID{site.ID}}
	aCount, err := aDAO.GetCount(ctx, nil, allocationFilter)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Allocations count from DB for Tenant and Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site Allocations count for Tenant", nil)
	}

	if aCount == 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden,
			"Tenant does not have any Allocations with Site specified in request data", nil)
	}

	vpcDAO := cdbm.NewVpcDAO(cvh.dbSession)
	if apiRequest.ID != nil {
		_, total, err := vpcDAO.GetAll(ctx, nil, cdbm.VpcFilterInput{VpcIDs: []uuid.UUID{*apiRequest.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(paginator.DefaultLimit)}, nil)
		if err != nil {
			logger.Error().Err(err).Msg("db error checking for ID uniqueness of tenant vpc")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Vpc due to DB error", nil)
		}
		if total > 0 {
			logger.Warn().Str("tenantId", tenant.ID.String()).Str("name", apiRequest.ID.String()).Msg("vpc with same ID already exists")
			return cutil.NewAPIErrorResponse(c, http.StatusConflict, "A Vpc with specified ID already exists", validation.Errors{
				"id": errors.New(apiRequest.ID.String()),
			})
		}
	}

	// check for name uniqueness for the tenant, ie, tenant cannot have another vpc with same name at the site
	// TODO consider doing this with an advisory lock for correctness
	vpcs, tot, err := vpcDAO.GetAll(ctx, nil, cdbm.VpcFilterInput{Name: &apiRequest.Name, InfrastructureProviderID: cdb.GetUUIDPtr(site.InfrastructureProviderID), TenantIDs: []uuid.UUID{tenant.ID}, SiteIDs: []uuid.UUID{site.ID}}, cdbp.PageInput{}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("db error checking for name uniqueness of tenant vpc")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Vpc due to DB error", nil)
	}
	if tot > 0 {
		logger.Warn().Str("tenantId", tenant.ID.String()).Str("name", apiRequest.Name).Msg("vpc with same name already exists for tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusConflict, "A Vpc with specified name already exists for Tenant", validation.Errors{
			"id": errors.New(vpcs[0].ID.String()),
		})
	}

	// If an NSG was requested, validate it.
	if apiRequest.NetworkSecurityGroupID != nil {
		nsgDAO := cdbm.NewNetworkSecurityGroupDAO(cvh.dbSession)

		nsg, err := nsgDAO.GetByID(ctx, nil, *apiRequest.NetworkSecurityGroupID, nil)
		if err != nil {
			if err == cdb.ErrDoesNotExist {
				logger.Error().Err(err).Msg("could not find NetworkSecurityGroup with ID specified in request data")
				// Should probably be using StatusPreconditionFailed here, and maybe for all of these NSG errors.
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Could not find NetworkSecurityGroup with ID specified in request data", nil)
			}

			logger.Error().Err(err).Msg("error retrieving NetworkSecurityGroup with ID specified in request data")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NetworkSecurityGroup with ID specified in request data", nil)
		}

		if nsg.SiteID != site.ID {
			logger.Error().Msg("NetworkSecurityGroup in request does not belong to Site")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NetworkSecurityGroup with ID specified in request data does not belong to Site", nil)
		}

		if nsg.TenantID != tenant.ID {
			logger.Error().Msg("NetworkSecurityGroup in request does not belong to Tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NetworkSecurityGroup with ID specified in request data does not belong to Tenant", nil)
		}
	}

	siteConfig := &cdbm.SiteConfig{}
	if site.Config != nil {
		siteConfig = site.Config
	}

	// Network Virtualization type support
	networkVirtualizationType := apiRequest.NetworkVirtualizationType
	if networkVirtualizationType == nil {
		// Default to `EthernetVirtualizer`
		networkVirtualizationType = cdb.GetStrPtr(cdbm.VpcEthernetVirtualizer)

		// If site has native networking enabled, use FNN
		if siteConfig.NativeNetworking {
			networkVirtualizationType = cdb.GetStrPtr(cdbm.VpcFNN)
		}
	}

	// Verify if site has been enabled for FNN type
	if *networkVirtualizationType == cdbm.VpcFNN {
		if !siteConfig.NativeNetworking {
			logger.Warn().Msg(fmt.Sprintf("Site: %v specified in request data must have native networking enabled in order to create FNN VPCs", site.ID))
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data must have native networking enabled in order to create FNN VPCs", nil)
		}
	}

	var routingProfile *string
	if apiRequest.RoutingProfile != nil {
		// For now, we gate on TargetedInstanceCreation permission,
		// Which implies a "privileged tenant"
		if tenant.Config == nil || !tenant.Config.TargetedInstanceCreation {
			logger.Warn().Msg("tenant does not have sufficient privileges to set `routingProfile`")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant does not have sufficient privileges to set `routingProfile`", nil)
		}

		// The request-struct-only case (both RoutingProfile and
		// NetworkVirtualizationType supplied) is caught by Validate.
		// The implicit case below covers callers that supplied
		// `routingProfile` only and let the handler default
		// `networkVirtualizationType` from site config; Validate
		// cannot see that default, so the check lives here.
		if !cdbm.VpcTypeSupportsRoutingProfile(networkVirtualizationType) {
			logger.Warn().Str("routingProfile", *apiRequest.RoutingProfile).Msg("`routingProfile` can only be specified if network virtualization type is set to `FNN`, or Site has native networking enabled and no network virtualization type is specified")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "`routingProfile` can only be specified if network virtualization type is set to `FNN`, or Site has native networking enabled and no network virtualization type is specified", nil)
		}

		// Normalize the API routing profile before sending it to the site controller.
		routingProfile = cdb.GetStrPtr(model.NormalizeAPIVpcRoutingProfileForSite(*apiRequest.RoutingProfile))
	}

	var defaultNvllPartitionId *uuid.UUID
	if apiRequest.NVLinkLogicalPartitionID != nil {
		if !siteConfig.NVLinkPartition {
			logger.Warn().Msg(fmt.Sprintf("Site: %v specified in request data must have NVLink Partition enabled in order to create VPC with default NVLink Partition", site.ID))
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data must have NVLink Partition enabled in order to create VPC with default NVLink Partition", nil)
		}

		nvllpDAO := cdbm.NewNVLinkLogicalPartitionDAO(cvh.dbSession)
		nvllpID, err := uuid.Parse(*apiRequest.NVLinkLogicalPartitionID)
		if err != nil {
			logger.Error().Err(err).Msg("error parsing NVLink Logical Partition ID specified in request data")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid NVLink Logical Partition ID specified in request data", nil)
		}

		nvllPartition, err := nvllpDAO.GetByID(ctx, nil, nvllpID, nil)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving NVLink Logical Partition with ID specified in request data")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NVLink Logical Partition with ID specified in request data", nil)
		}

		if nvllPartition.SiteID != site.ID {
			logger.Error().Msg("NVLink Logical Partition in request does not belong to Site")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data does not belong to Site", nil)
		}

		if nvllPartition.Status != cdbm.NVLinkLogicalPartitionStatusReady {
			logger.Error().Msg("NVLink Logical Partition in request is not in Ready state")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data is not in Ready state", nil)
		}

		// Verify that the NVLink Logical Partition is associated with the VPC's Tenant
		if nvllPartition.TenantID != tenant.ID {
			logger.Error().Msg("NVLink Logical Partition in request does not belong to Tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data does not belong to Tenant", nil)
		}
		defaultNvllPartitionId = &nvllpID
	}

	// Labels support
	var labels map[string]string
	if apiRequest.Labels != nil {
		labels = apiRequest.Labels
	}

	sdDAO := cdbm.NewStatusDetailDAO(cvh.dbSession)

	var vpc *cdbm.Vpc
	var ssd *cdbm.StatusDetail
	controllerVpc := &cwssaws.Vpc{}

	// timeoutResp lets the closure signal a post-rollback handler — the
	// TerminateWorkflow call has to run after the closure returns so that
	// the DB tx unwinds before we make the second remote call. nil means
	// no timeout occurred and the normal flow continues.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, cvh.dbSession, func(tx *cdb.Tx) error {
		// Create VPC
		vpcInput := cdbm.VpcCreateInput{
			ID:                        apiRequest.ID,
			Name:                      apiRequest.Name,
			Description:               apiRequest.Description,
			Org:                       org,
			InfrastructureProviderID:  site.InfrastructureProviderID,
			NetworkSecurityGroupID:    apiRequest.NetworkSecurityGroupID,
			TenantID:                  tenant.ID,
			SiteID:                    site.ID,
			NetworkVirtualizationType: networkVirtualizationType,
			RoutingProfile:            routingProfile,
			NVLinkLogicalPartitionID:  defaultNvllPartitionId,
			Labels:                    labels,
			Status:                    cdbm.VpcStatusProvisioning,
			CreatedBy:                 *dbUser,
			Vni:                       apiRequest.Vni,
		}

		createdVpc, derr := vpcDAO.Create(ctx, tx, vpcInput)
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating VPC DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed creating new VPC record, DB error", nil)
		}

		// Update the controller ID
		// We need this to match the VPC ID.  This was previously handled
		// by the async cloud workflow after successful creation on site.
		uvpcInput := cdbm.VpcUpdateInput{
			VpcID:           createdVpc.ID,
			ControllerVpcID: cdb.GetUUIDPtr(createdVpc.ID),
		}
		updatedVpc, derr := vpcDAO.Update(ctx, tx, uvpcInput)
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating VPC DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed updating new VPC record, DB error", nil)
		}
		vpc = updatedVpc

		// Create status detail
		createdSsd, derr := sdDAO.CreateFromParams(ctx, tx, vpc.ID.String(), cdbm.VpcStatusProvisioning,
			cdb.GetStrPtr("VPC provisioning has been initiated on Site"))
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for VPC", nil)
		}
		if createdSsd == nil {
			logger.Error().Msg("Status Detail DB entry not returned from CreateFromParams")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to get new Status Detail for VPC", nil)
		}
		ssd = createdSsd

		// Get the temporal client for the site we are working with.
		stc, derr := cvh.scp.GetClientByID(vpc.SiteID)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
		}

		createVpcRequest := apiRequest.ToProto(vpc)

		workflowOptions := temporalClient.StartWorkflowOptions{
			ID:                       "vpc-create-" + vpc.ID.String(),
			TaskQueue:                queue.SiteTaskQueue,
			WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		}

		logger.Info().Msg("triggering VPC create workflow")

		// Add context deadlines
		wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
		defer cancel()

		// Trigger Site workflow
		we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "CreateVPCV2", createVpcRequest)
		if wferr != nil {
			logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to create VPC")
			return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to create VPC on Site: %s", wferr), nil)
		}

		wid := we.GetID()
		logger.Info().Str("Workflow ID", wid).Msg("executed synchronous create VPC workflow")

		// Block until the workflow has completed and returned success/error.
		wferr = we.Get(wfCtx, controllerVpc)
		if wferr != nil {
			var timeoutErr *tp.TimeoutError
			if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
				logger.Error().Err(wferr).Msg("failed to create VPC, timeout occurred executing workflow on Site.")
				timeoutResp = func() error {
					return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "VPC", "Create")
				}
				return cutil.NewAPIError(http.StatusInternalServerError, "VPC create workflow timed out", nil)
			}

			code, unwrapped := common.UnwrapWorkflowError(wferr)
			logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to create VPC")
			return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to create VPC on Site: %s", unwrapped), nil)
		}

		logger.Info().Str("Workflow ID", wid).Msg("completed synchronous create VPC workflow")
		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to create VPC due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	statusDetails := []cdbm.StatusDetail{*ssd}

	// Make a best-effort attempt to return a response with the allocated VNI.
	if controllerVpc.GetStatus() != nil {
		activeVni := wutil.GetUint32PtrToIntPtr(controllerVpc.GetStatus().Vni)

		uvpcInput := cdbm.VpcUpdateInput{
			VpcID:     vpc.ID,
			ActiveVni: activeVni,
			Status:    cdb.GetStrPtr(cdbm.VpcStatusReady),
		}
		updatedVpc, err := vpcDAO.Update(ctx, nil, uvpcInput)
		if err != nil {
			logger.Error().Err(err).Msg("error while updating VPC DB entry for VNI")
		} else {
			// Update the vpc being returned if all went well.
			vpc = updatedVpc

			// Best effort create status detail
			ssd, err = sdDAO.CreateFromParams(ctx, nil, vpc.ID.String(), cdbm.VpcStatusReady, cdb.GetStrPtr("VPC is ready for use"))
			if err != nil {
				logger.Error().Err(err).Msg("error creating Status Detail DB entry")
			} else if ssd == nil {
				logger.Error().Err(err).Msg("unexpected nil Status Detail returned from DB")
			} else {
				statusDetails = append(statusDetails, *ssd)
			}
		}
	}

	// Create response
	apiVpc := model.NewAPIVpc(*vpc, statusDetails)

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusCreated, apiVpc)
}

// ~~~~~ Update Handler ~~~~~ //

// UpdateVPCHandler is the API Handler for updating a VPC
type UpdateVPCHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewUpdateVPCHandler initializes and returns a new handler for updating VPC
func NewUpdateVPCHandler(dbSession *cdb.Session, tc temporalClient.Client, sc *sc.ClientPool, cfg *config.Config) UpdateVPCHandler {
	return UpdateVPCHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        sc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update an existing VPC
// @Description Update an existing VPC for the org
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Vpc"
// @Param message body model.APIVpcUpdateRequest true "VPC update request"
// @Success 200 {object} model.APIVpc
// @Router /v2/org/{org}/nico/vpc/{id} [patch]
func (uvh UpdateVPCHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "Update", c, uvh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get vpc instance ID from URL param
	vpcStrID := c.Param("id")

	uvh.tracerSpan.SetAttribute(handlerSpan, attribute.String("vpc_id", vpcStrID), logger)

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIVpcUpdateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating VPC update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating VPC update request data", verr)
	}

	// Check that VPC exists
	vpc, err := common.GetVpcFromIDString(ctx, nil, vpcStrID, []string{cdbm.SiteRelationName}, uvh.dbSession)
	if err != nil {
		// Check if it's a UUID parsing error (happens before DB call)
		if err == common.ErrInvalidID {
			logger.Warn().Err(err).Msg("invalid VPC ID in request")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid VPC ID in request", nil)
		}
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("VPC not found")
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve VPC to update", nil)
		}
		logger.Error().Err(err).Msg("error retrieving VPC DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPC", nil)
	}

	// Get Tenant for this org
	tenant, err := common.GetTenantForOrg(ctx, nil, uvh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	// Check that VPC belongs to the Tenant
	if vpc.TenantID != tenant.ID {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "VPC does not belong to current Tenant", nil)
	}

	// Ensure that Tenant has an Allocation with specified Site
	aDAO := cdbm.NewAllocationDAO(uvh.dbSession)
	allocationFilter := cdbm.AllocationFilterInput{TenantIDs: []uuid.UUID{tenant.ID}, SiteIDs: []uuid.UUID{vpc.SiteID}}
	aCount, err := aDAO.GetCount(ctx, nil, allocationFilter)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Allocations count from DB for Tenant and Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site Allocations count for Tenant", nil)
	}

	if aCount == 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden,
			"Tenant does not have any Allocations with Site specified in request data", nil)
	}

	vpcDAO := cdbm.NewVpcDAO(uvh.dbSession)
	// check for name uniqueness for the tenant, ie, tenant cannot have another vpc with same name at the site
	if apiRequest.Name != nil && *apiRequest.Name != vpc.Name {
		vpcs, tot, err := vpcDAO.GetAll(ctx, nil, cdbm.VpcFilterInput{Name: apiRequest.Name, InfrastructureProviderID: &vpc.InfrastructureProviderID, TenantIDs: []uuid.UUID{tenant.ID}, SiteIDs: []uuid.UUID{vpc.SiteID}}, cdbp.PageInput{}, nil)
		if err != nil {
			logger.Error().Err(err).Msg("db error checking for name uniqueness of tenant vpc")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Vpc due to DB error", nil)
		}
		if tot > 0 {
			return cutil.NewAPIErrorResponse(c, http.StatusConflict, "Another VPC with specified name already exists for Tenant", validation.Errors{
				"id": errors.New(vpcs[0].ID.String()),
			})
		}
	}

	var nsgID *string
	// If an NSG was requested, validate it.
	if apiRequest.NetworkSecurityGroupID != nil && *apiRequest.NetworkSecurityGroupID != "" {
		nsgDAO := cdbm.NewNetworkSecurityGroupDAO(uvh.dbSession)

		nsg, err := nsgDAO.GetByID(ctx, nil, *apiRequest.NetworkSecurityGroupID, nil)
		if err != nil {
			if err == cdb.ErrDoesNotExist {
				logger.Error().Err(err).Msg("could not find NetworkSecurityGroup with ID specified in request data")
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Could not find NetworkSecurityGroup with ID specified in request data", nil)
			}

			logger.Error().Err(err).Msg("error retrieving NetworkSecurityGroup with ID specified in request data")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NetworkSecurityGroup with ID specified in request data", nil)
		}

		if nsg.SiteID != vpc.SiteID {
			logger.Error().Msg("NetworkSecurityGroup in request does not belong to Site")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NetworkSecurityGroup with ID specified in request data does not belong to Site", nil)
		}

		if nsg.TenantID != tenant.ID {
			logger.Error().Msg("NetworkSecurityGroup in request does not belong to Tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NetworkSecurityGroup with ID specified in request data does not belong to Tenant", nil)
		}

		nsgID = cdb.GetStrPtr(nsg.ID)
	}

	// Labels support
	var labels map[string]string
	if apiRequest.Labels != nil {
		labels = apiRequest.Labels
	}

	siteConfig := &cdbm.SiteConfig{}
	if vpc.Site != nil && vpc.Site.Config != nil {
		siteConfig = vpc.Site.Config
	}

	var defaultNvllPartitionId *uuid.UUID
	if apiRequest.NVLinkLogicalPartitionID != nil {
		if !siteConfig.NVLinkPartition {
			logger.Warn().Msg(fmt.Sprintf("Site: %v specified in request data must have NVLink Partition enabled in order to update VPC with default NVLink Partition", vpc.SiteID.String()))
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Site: %v specified in request data must have NVLink Partition enabled in order to update VPC with default NVLink Partition", vpc.SiteID.String()), nil)
		}

		// Verify that the existing default NVLink Logical Partition is not being used by any Instance from the VPC
		instanceDAO := cdbm.NewInstanceDAO(uvh.dbSession)
		instances, _, err := instanceDAO.GetAll(ctx, nil, cdbm.InstanceFilterInput{VpcIDs: []uuid.UUID{vpc.ID}}, cdbp.PageInput{}, nil)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving Instances from DB for VPC")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Instances for VPC", nil)
		}

		nvlIfcDAO := cdbm.NewNVLinkInterfaceDAO(uvh.dbSession)
		for _, instance := range instances {
			// Get NVLink Interfaces for the Instance
			nvlIfcs, _, err := nvlIfcDAO.GetAll(ctx, nil, cdbm.NVLinkInterfaceFilterInput{InstanceIDs: []uuid.UUID{instance.ID}}, cdbp.PageInput{}, nil)
			if err != nil {
				logger.Error().Err(err).Msg("error retrieving NVLink Interfaces from DB for Instance")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NVLink Interfaces for Instance", nil)
			}

			for _, nvlIfc := range nvlIfcs {
				if nvlIfc.NVLinkLogicalPartitionID == *vpc.NVLinkLogicalPartitionID {
					logger.Error().Msg("Existing default NVLink Logical Partition is already being used by an Instance from the VPC")
					return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Existing default NVLink Logical Partition is already being used by an Instance from the VPC", nil)
				}
			}
		}

		// If a new NVLink Logical Partition ID is specified, validate it.
		// if it is empty then user wants
		if *apiRequest.NVLinkLogicalPartitionID != "" {
			nvllpDAO := cdbm.NewNVLinkLogicalPartitionDAO(uvh.dbSession)
			nvllpID, err := uuid.Parse(*apiRequest.NVLinkLogicalPartitionID)
			if err != nil {
				logger.Error().Err(err).Msg("error parsing NVLink Logical Partition ID specified in request data")
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid NVLink Logical Partition ID specified in request data", nil)
			}

			nvllPartition, err := nvllpDAO.GetByID(ctx, nil, nvllpID, nil)
			if err != nil {
				logger.Error().Err(err).Msg("error retrieving NVLink Logical Partition with ID specified in request data")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NVLink Logical Partition with ID specified in request data", nil)
			}

			// Verify that the NVLink Logical Partition is associated with the VPC's Site
			if nvllPartition.SiteID != vpc.SiteID {
				logger.Error().Msg("NVLink Logical Partition in request does not belong to Site")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data does not belong to Site", nil)
			}

			// Verify that the NVLink Logical Partition is in the Ready state
			if nvllPartition.Status != cdbm.NVLinkLogicalPartitionStatusReady {
				logger.Error().Msg("NVLink Logical Partition in request is not in Ready state")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data is not in Ready state", nil)
			}

			// Verify that the NVLink Logical Partition is associated with the VPC's Tenant
			if nvllPartition.TenantID != tenant.ID {
				logger.Error().Msg("NVLink Logical Partition in request does not belong to Tenant")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "NVLink Logical Partition with ID specified in request data does not belong to Tenant", nil)
			}

			defaultNvllPartitionId = &nvllpID
		}
	}

	sdDAO := cdbm.NewStatusDetailDAO(uvh.dbSession)
	var ssds []cdbm.StatusDetail

	// timeoutResp lets the closure signal a post-rollback handler — the
	// TerminateWorkflow call has to run after the closure returns so that
	// the DB tx unwinds before we make the second remote call. nil means
	// no timeout occurred and the normal flow continues.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, uvh.dbSession, func(tx *cdb.Tx) error {
		// Update VPC
		uvpcInput := cdbm.VpcUpdateInput{
			VpcID:                  vpc.ID,
			Name:                   apiRequest.Name,
			Description:            apiRequest.Description,
			Labels:                 labels,
			NetworkSecurityGroupID: nsgID,
		}

		if defaultNvllPartitionId != nil {
			uvpcInput.NVLinkLogicalPartitionID = defaultNvllPartitionId
		}

		updatedVpc, derr := vpcDAO.Update(ctx, tx, uvpcInput)
		if derr != nil {
			logger.Error().Err(derr).Msg("error updating VPC")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update VPC", nil)
		}
		vpc = updatedVpc

		clearInput := cdbm.VpcClearInput{VpcID: vpc.ID}
		shouldClear := false
		// If this request is attempting to clear the OS for the instance, set it.
		if apiRequest.NetworkSecurityGroupID != nil && *apiRequest.NetworkSecurityGroupID == "" {
			clearInput.NetworkSecurityGroupID = true
			shouldClear = true
		}

		// If this request is attempting to clear NSG for the VPC, set it.
		if apiRequest.NetworkSecurityGroupID != nil {
			if *apiRequest.NetworkSecurityGroupID == "" {
				clearInput.NetworkSecurityGroupID = true
			}

			// We should always clear details for any NSG change so that users don't see stale
			// status.
			clearInput.NetworkSecurityGroupPropagationDetails = true
			shouldClear = true
		}

		// If this request is attempting to clear the NVLink Logical Partition ID, set it.
		if apiRequest.NVLinkLogicalPartitionID != nil && *apiRequest.NVLinkLogicalPartitionID == "" {
			clearInput.NVLinkLogicalPartitionID = true
			shouldClear = true
		}

		// Clear it in the db if something should be cleared.
		if shouldClear {
			clearedVpc, derr := vpcDAO.Clear(ctx, tx, clearInput)
			if derr != nil {
				logger.Error().Err(derr).Msg("error clearing requested VPC properties")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to clear requested VPC properties", nil)
			}
			vpc = clearedVpc
		}

		// Get status details
		fetchedSsds, _, derr := sdDAO.GetAllByEntityID(ctx, tx, vpc.ID.String(), nil, cdb.GetIntPtr(pagination.MaxPageSize), nil)
		if derr != nil {
			logger.Error().Err(derr).Msg("error retrieving Status Details for VPC from DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve Status Details for VPC", nil)
		}
		ssds = fetchedSsds

		// Get the temporal client for the site we are working with.
		stc, derr := uvh.scp.GetClientByID(vpc.SiteID)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
		}

		updateVpcRequest := apiRequest.ToProto(vpc)

		workflowOptions := temporalClient.StartWorkflowOptions{
			ID:                       "vpc-update-" + vpc.ID.String(),
			TaskQueue:                queue.SiteTaskQueue,
			WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		}

		logger.Info().Msg("triggering VPC update workflow")

		// Add context deadlines
		wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
		defer cancel()

		// Trigger Site workflow
		we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "UpdateVPC", updateVpcRequest)
		if wferr != nil {
			logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to update VPC")
			return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to update VPC on Site: %s", wferr), nil)
		}

		wid := we.GetID()
		logger.Info().Str("Workflow ID", wid).Msg("executed synchronous update VPC workflow")

		// Block until the workflow has completed and returned success/error.
		wferr = we.Get(wfCtx, nil)
		if wferr != nil {
			var timeoutErr *tp.TimeoutError
			if errors.As(wferr, &timeoutErr) || wfCtx.Err() != nil {
				logger.Error().Err(wferr).Msg("failed to update VPC, timeout occurred executing workflow on Site.")
				timeoutResp = func() error {
					return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "VPC", "Update")
				}
				return cutil.NewAPIError(http.StatusInternalServerError, "VPC update workflow timed out", nil)
			}

			code, unwrapped := common.UnwrapWorkflowError(wferr)
			logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to update VPC")
			return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to update VPC on Site: %s", unwrapped), nil)
		}

		logger.Info().Str("Workflow ID", wid).Msg("completed synchronous update VPC workflow")
		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to update VPC due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// Create response
	apiVpc := model.NewAPIVpc(*vpc, ssds)

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiVpc)
}

// ~~~~~ Update Virtualization Handler ~~~~~ //

// UpdateVPCVirtualizationHandler is the API Handler for updating virtualization of a VPC
type UpdateVPCVirtualizationHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewUpdateVPCVirtualizationHandler initializes and returns a new handler for updating virtualization of a VPC
func NewUpdateVPCVirtualizationHandler(dbSession *cdb.Session, tc temporalClient.Client, sc *sc.ClientPool, cfg *config.Config) UpdateVPCVirtualizationHandler {
	return UpdateVPCVirtualizationHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        sc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update virtualization of a VPC
// @Description Update the network virtualization of a VPC
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Vpc"
// @Param message body model.APIVpcVirtualizationUpdateRequest true "VPC virtualization update request"
// @Success 200 {object} model.APIVpc
// @Router /v2/org/{org}/nico/vpc/{id}/virtualization [patch]
func (uvvh UpdateVPCVirtualizationHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "Update Virtualization", c, uvvh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get vpc instance ID from URL param
	vpcStrID := c.Param("id")

	uvvh.tracerSpan.SetAttribute(handlerSpan, attribute.String("vpc_id", vpcStrID), logger)

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIVpcVirtualizationUpdateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Check that VPC exists (load Site for status and native networking / FNN eligibility checks)
	vpc, err := common.GetVpcFromIDString(ctx, nil, vpcStrID, []string{cdbm.SiteRelationName}, uvvh.dbSession)
	if err != nil {
		// Check if it's a UUID parsing error (happens before DB call)
		if err == common.ErrInvalidID {
			logger.Warn().Err(err).Msg("invalid VPC ID in request")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid VPC ID in request", nil)
		}
		if err == cdb.ErrDoesNotExist {
			logger.Warn().Err(err).Msg("VPC not found")
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve VPC to update", nil)
		}
		logger.Error().Err(err).Msg("error retrieving VPC DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPC", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate(vpc)
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating VPC update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating VPC virtualization update request data", verr)
	}

	// Get Tenant for this org
	tenant, err := common.GetTenantForOrg(ctx, nil, uvvh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	// Check that VPC belongs to the Tenant
	if vpc.TenantID != tenant.ID {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "VPC does not belong to current Tenant", nil)
	}

	// Ensure that Tenant has access to Site
	tsDAO := cdbm.NewTenantSiteDAO(uvvh.dbSession)
	_, err = tsDAO.GetByTenantIDAndSiteID(ctx, nil, tenant.ID, vpc.SiteID, nil)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant does not have access to Site, VPC cannot be updated", nil)
		}

		logger.Error().Err(err).Msg("error retrieving Tenant Site association")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to determine Tenant/Site association, DB error", nil)
	}

	// Verify that the VPC Site is in a valid state
	if vpc.Site.Status != cdbm.SiteStatusRegistered {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site that VPC belongs to must be in Registered state in order to update virtualization type", nil)
	}

	// Get site config
	siteConfig := &cdbm.SiteConfig{}
	if vpc.Site.Config != nil {
		siteConfig = vpc.Site.Config
	}

	// Verify if site has been enabled for FNN type
	// No need to check for FNN type, as the request validator guarantees that
	if !siteConfig.NativeNetworking {
		logger.Warn().Msg(fmt.Sprintf("Site: %v that VPC belongs to does not have native networking enabled, unable to update virtualization type to FNN", vpc.SiteID))
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site that VPC belongs to does not have native networking enabled, unable to update virtualization type to FNN", nil)
	}

	subnetDAO := cdbm.NewSubnetDAO(uvvh.dbSession)
	_, subnetCount, err := subnetDAO.GetAll(ctx, nil, cdbm.SubnetFilterInput{VpcIDs: []uuid.UUID{vpc.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(0)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Subnets count from DB for VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Subnets count for VPC", nil)
	}

	instanceDAO := cdbm.NewInstanceDAO(uvvh.dbSession)
	instanceCount, err := instanceDAO.GetCount(ctx, nil, cdbm.InstanceFilterInput{VpcIDs: []uuid.UUID{vpc.ID}})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Instances count from DB for VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Instances count for VPC", nil)
	}

	if subnetCount > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Virtualization Type cannot be changed while VPC contains one or more Subnets", nil)
	}

	if instanceCount > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Virtualization Type cannot be changed while VPC contains one or more Instances", nil)
	}

	vpcDAO := cdbm.NewVpcDAO(uvvh.dbSession)
	sdDAO := cdbm.NewStatusDetailDAO(uvvh.dbSession)

	var uv *cdbm.Vpc
	var ssds []cdbm.StatusDetail
	var timeoutResp func() error

	err = cdb.WithTx(ctx, uvvh.dbSession, func(tx *cdb.Tx) error {
		// Update VPC
		uvpcInput := cdbm.VpcUpdateInput{
			VpcID:                     vpc.ID,
			NetworkVirtualizationType: &apiRequest.NetworkVirtualizationType,
		}
		updatedVpc, derr := vpcDAO.Update(ctx, tx, uvpcInput)
		if derr != nil {
			logger.Error().Err(derr).Msg("error updating VPC")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update VPC virtualization, DB error", nil)
		}
		uv = updatedVpc

		// Get status details
		fetchedSsds, _, derr := sdDAO.GetAllByEntityID(ctx, tx, uv.ID.String(), nil, cdb.GetIntPtr(pagination.MaxPageSize), nil)
		if derr != nil {
			logger.Error().Err(derr).Msg("error retrieving Status Details for VPC from DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve status history for VPC", nil)
		}
		ssds = fetchedSsds

		// Get the temporal client for the site we are working with.
		stc, derr := uvvh.scp.GetClientByID(vpc.SiteID)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
		}

		// VPC virtualization type can only be updated to FNN, the request validator guarantees that
		siteVirtualizationType := cwssaws.VpcVirtualizationType_FNN
		siteRequest := &cwssaws.VpcUpdateVirtualizationRequest{
			Id:                        &cwssaws.VpcId{Value: vpc.GetSiteID().String()},
			NetworkVirtualizationType: &siteVirtualizationType,
		}

		workflowOptions := temporalClient.StartWorkflowOptions{
			ID:                       "vpc-update-virtualzation-" + uv.ID.String(),
			TaskQueue:                queue.SiteTaskQueue,
			WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		}

		logger.Info().Msg("triggering VPC virtualization update workflow")

		// Add context deadlines
		wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
		defer cancel()

		// Trigger Site workflow
		we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "UpdateVPCVirtualization", siteRequest)
		if wferr != nil {
			logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to update VPC virtualization")
			return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to update VPC on Site: %s", wferr), nil)
		}

		wid := we.GetID()
		logger.Info().Str("Workflow ID", wid).Msg("executed synchronous update VPC virtualization workflow")

		// Block until the workflow has completed and returned success/error.
		wferr = we.Get(wfCtx, nil)

		if wferr != nil {
			var timeoutErr *tp.TimeoutError
			if errors.As(wferr, &timeoutErr) || errors.Is(wferr, context.DeadlineExceeded) || wfCtx.Err() != nil {
				timeoutResp = func() error {
					return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "VPC", "UpdateVirtualization")
				}
				return cutil.NewAPIError(http.StatusInternalServerError, "VPC virtualization update workflow timed out", nil)
			}
			code, unwrapped := common.UnwrapWorkflowError(wferr)
			logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to update VPC virtualization")
			return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to update VPC virtualization on Site: %s", unwrapped), nil)
		}

		logger.Info().Str("Workflow ID", wid).Msg("completed synchronous update VPC workflow")
		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to update VPC virtualization due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// Create response
	apiVpc := model.NewAPIVpc(*uv, ssds)

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiVpc)
}

// ~~~~~ Get Handler ~~~~~ //

// GetVPCHandler is the API Handler for getting a VPC
type GetVPCHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetVPCHandler initializes and returns a new handler for getting VPC
func NewGetVPCHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetVPCHandler {
	return GetVPCHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get a VPC
// @Description Get a VPC for the org
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Vpc"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Site', 'Tenant'"
// @Success 200 {object} model.APIVpc
// @Router /v2/org/{org}/nico/vpc/{id} [get]
func (gvh GetVPCHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "Get", c, gvh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errMsg := common.GetAndValidateQueryRelations(qParams, cdbm.VpcRelatedEntities)
	if errMsg != "" {
		logger.Warn().Msg(errMsg)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errMsg, nil)
	}

	// Get VPC ID from URL param
	vpcIDStr := c.Param("id")

	gvh.tracerSpan.SetAttribute(handlerSpan, attribute.String("vpc_id", vpcIDStr), logger)

	// Get VPC
	vpcDAO := cdbm.NewVpcDAO(gvh.dbSession)

	vpcID, err := uuid.Parse(vpcIDStr)
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid VPC ID in URL", nil)
	}

	vpc, err := vpcDAO.GetByID(ctx, nil, vpcID, qIncludeRelations)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find VPC with specified ID", nil)
		}
		logger.Error().Err(err).Msg("error retrieving VPC from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPC", nil)
	}

	// Get Tenant for this org
	tenant, err := common.GetTenantForOrg(ctx, nil, gvh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant", nil)
	}

	// Check if VPC belongs to Tenant
	if vpc.TenantID != tenant.ID {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "VPC does not belong to current Tenant", nil)
	}

	// Get status details
	sdDAO := cdbm.NewStatusDetailDAO(gvh.dbSession)

	ssds, err := sdDAO.GetRecentByEntityIDs(ctx, nil, []string{vpcID.String()}, common.RECENT_STATUS_DETAIL_COUNT)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Status Details for VPC from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for VPC", nil)
	}

	// Create response
	vc := model.NewAPIVpc(*vpc, ssds)

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusOK, vc)
}

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllVPCHandler is the API Handler for retrieving all VPCs
type GetAllVPCHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllVPCHandler initializes and returns a new handler for retreiving all VPCs
func NewGetAllVPCHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetAllVPCHandler {
	return GetAllVPCHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get all VPCs
// @Description Get all VPCs for the org
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteId query string false "Site ID"
// @Param nvLinkLogicalPartitionId query string false "NVLink Logical Partition ID"
// @Param status query string false "Filter by status" e.g. 'Pending', 'Error'"
// @Param query query string false "Query input for full text search"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Site', 'Tenant'"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Param orderBy query string false "Order by field"
// @Success 200 {array} []model.APIVpc
// @Router /v2/org/{org}/nico/vpc [get]
func (gavh GetAllVPCHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "GetAll", c, gavh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Validate pagination request
	pageRequest := pagination.PageRequest{}
	err = c.Bind(&pageRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding pagination request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request pagination data", nil)
	}

	// Validate request attributes
	err = pageRequest.Validate(cdbm.VpcOrderByFields)
	if err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errMsg := common.GetAndValidateQueryRelations(qParams, cdbm.VpcRelatedEntities)
	if errMsg != "" {
		logger.Warn().Msg(errMsg)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errMsg, nil)
	}

	// Get infrastructure provider ID from query param
	var infrastructureProviderID *uuid.UUID
	qInfrastructureProviderID := c.QueryParam("infrastructureProviderId")
	if qInfrastructureProviderID != "" {
		id, serr := uuid.Parse(qInfrastructureProviderID)
		if serr != nil {
			logger.Warn().Err(serr).Msg("error parsing infrastructureProviderId in query into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Infrastructure Provider ID in query", nil)
		}
		infrastructureProviderID = &id

		// Check for IP existence
		ipDAO := cdbm.NewInfrastructureProviderDAO(gavh.dbSession)
		_, verr := ipDAO.GetByID(ctx, nil, *infrastructureProviderID, nil)
		if verr != nil {
			logger.Warn().Err(verr).Msg("error retrieving InfrastructureProvider from DB by ID")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Could not retrieve InfrastructureProvider with ID specified in query", nil)
		}
	}

	// Get site IDs from query param
	var siteIDs []uuid.UUID

	siteIDStrs := qParams["siteId"]
	if len(siteIDStrs) > 0 {
		gavh.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("siteId", siteIDStrs), logger)
		for _, idStr := range siteIDStrs {
			parsedID, serr := uuid.Parse(idStr)
			if serr != nil {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid Site ID in query: %s", idStr), nil)
			}
			siteIDs = append(siteIDs, parsedID)
		}

		// Check for Site existence
		stDAO := cdbm.NewSiteDAO(gavh.dbSession)
		sites, _, err := stDAO.GetAll(ctx, nil, cdbm.SiteFilterInput{SiteIDs: siteIDs}, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
		if err != nil {
			logger.Warn().Err(err).Msg("error retrieving Sites from DB by IDs")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve Sites with IDs specified in query", nil)
		}
		// Build a set of site IDs for efficient lookup
		sitesByID := make(map[uuid.UUID]struct{}, len(sites))
		for _, site := range sites {
			sitesByID[site.ID] = struct{}{}
		}
		// For each siteIDStr, check if the corresponding site exists
		for _, siteID := range siteIDs {
			if _, ok := sitesByID[siteID]; !ok {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Could not find Site with ID specified in query: %s", siteID.String()), nil)
			}
		}
	}

	// Get query text for full text search from query param
	searchQuery := common.GetSearchQuery(c)
	if searchQuery != nil {
		gavh.tracerSpan.SetAttribute(handlerSpan, attribute.String("query", *searchQuery), logger)
	}

	// Get status from query param
	var statuses []string
	if statusStrings := qParams["status"]; len(statusStrings) != 0 {
		gavh.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("status", statusStrings), logger)
		for _, status := range statusStrings {
			_, ok := cdbm.VpcStatusMap[status]
			if !ok {
				logger.Warn().Msg(fmt.Sprintf("invalid value in status query: %v", status))
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Status value in query", nil)
			}
			statuses = append(statuses, status)
		}
	}

	// Get Tenant for this org
	tnDAO := cdbm.NewTenantDAO(gavh.dbSession)

	tenants, err := tnDAO.GetAllByOrg(ctx, nil, org, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Tenant for this org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant for org", nil)
	}

	if len(tenants) == 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Org does not have a Tenant associated", nil)
	}
	tenant := tenants[0]

	// Get all VPCs by Tenant, and Site, if specified
	vpcDAO := cdbm.NewVpcDAO(gavh.dbSession)

	vpcFilter := cdbm.VpcFilterInput{
		Org:                      &org,
		InfrastructureProviderID: infrastructureProviderID,
		SearchQuery:              searchQuery,
		TenantIDs:                []uuid.UUID{tenant.ID},
	}

	if len(siteIDs) > 0 {
		vpcFilter.SiteIDs = siteIDs
	}

	if len(statuses) > 0 {
		vpcFilter.Statuses = statuses
	}

	// Get network security group IDs from query param
	networkSecurityGroupIDs := qParams["networkSecurityGroupId"]
	if len(networkSecurityGroupIDs) > 0 {
		gavh.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("networkSecurityGroupId", networkSecurityGroupIDs), logger)
		networkSecurityGroupDAO := cdbm.NewNetworkSecurityGroupDAO(gavh.dbSession)

		networkSecurityGroups, _, err := networkSecurityGroupDAO.GetAll(
			ctx,
			nil,
			cdbm.NetworkSecurityGroupFilterInput{NetworkSecurityGroupIDs: networkSecurityGroupIDs, TenantIDs: []uuid.UUID{tenant.ID}},
			cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)},
			nil,
		)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving Network Security Groups from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Network Security Groups specified in query", nil)
		}
		networkSecurityGroupIDsMap := make(map[string]struct{}, len(networkSecurityGroups))
		for _, networkSecurityGroup := range networkSecurityGroups {
			networkSecurityGroupIDsMap[networkSecurityGroup.ID] = struct{}{}
		}
		for _, nsgID := range networkSecurityGroupIDs {
			if _, ok := networkSecurityGroupIDsMap[nsgID]; !ok {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Network Security Group ID: %s specified in query does not exist for current Tenant", nsgID), nil)
			}
		}
		vpcFilter.NetworkSecurityGroupIDs = networkSecurityGroupIDs
	}

	qNvLinkLogicalPartitionIDStrs := qParams["nvLinkLogicalPartitionId"]
	if len(qNvLinkLogicalPartitionIDStrs) > 0 {
		gavh.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("nvLinkLogicalPartitionId", qNvLinkLogicalPartitionIDStrs), logger)
		nvllpDAO := cdbm.NewNVLinkLogicalPartitionDAO(gavh.dbSession)
		nvLinkLogicalPartitionIDs := make([]uuid.UUID, 0, len(qNvLinkLogicalPartitionIDStrs))
		for _, nvLinkLogicalPartitionIDStr := range qNvLinkLogicalPartitionIDStrs {
			nvLinkLogicalPartitionID, err := uuid.Parse(nvLinkLogicalPartitionIDStr)
			if err != nil {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid NVLink Logical Partition ID: %s in query", nvLinkLogicalPartitionIDStr), nil)
			}
			nvLinkLogicalPartitionIDs = append(nvLinkLogicalPartitionIDs, nvLinkLogicalPartitionID)
		}
		nvLinkLogicalPartitions, _, err := nvllpDAO.GetAll(ctx, nil, cdbm.NVLinkLogicalPartitionFilterInput{NVLinkLogicalPartitionIDs: nvLinkLogicalPartitionIDs, TenantIDs: []uuid.UUID{tenant.ID}}, cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}, nil)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving NVLink Logical Partitions from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve NVLink Logical Partitions specified in query", nil)
		}
		nvLinkLogicalPartitionIDsMap := make(map[uuid.UUID]struct{}, len(nvLinkLogicalPartitions))
		for _, nvLinkLogicalPartition := range nvLinkLogicalPartitions {
			nvLinkLogicalPartitionIDsMap[nvLinkLogicalPartition.ID] = struct{}{}
		}
		for _, nvLinkLogicalPartitionID := range nvLinkLogicalPartitionIDs {
			if _, ok := nvLinkLogicalPartitionIDsMap[nvLinkLogicalPartitionID]; !ok {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("NVLink Logical Partition ID: %s specified in query does not exist for current Tenant", nvLinkLogicalPartitionID.String()), nil)
			}
		}
		vpcFilter.NVLinkLogicalPartitionIDs = nvLinkLogicalPartitionIDs
	}

	vpcPageInput := cdbp.PageInput{
		Limit:   pageRequest.Limit,
		Offset:  pageRequest.Offset,
		OrderBy: pageRequest.OrderBy,
	}

	vpcs, total, serr := vpcDAO.GetAll(
		ctx,
		nil,
		vpcFilter,
		vpcPageInput,
		qIncludeRelations,
	)

	if serr != nil {
		logger.Error().Err(serr).Msg("error retrieving VPCs for this Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPCs for Site", nil)
	}

	// Get status details
	sdDAO := cdbm.NewStatusDetailDAO(gavh.dbSession)

	sdEntityIDs := []string{}
	for _, vpc := range vpcs {
		sdEntityIDs = append(sdEntityIDs, vpc.ID.String())
	}
	ssds, serr := sdDAO.GetRecentByEntityIDs(ctx, nil, sdEntityIDs, common.RECENT_STATUS_DETAIL_COUNT)
	if serr != nil {
		logger.Warn().Err(serr).Msg("error retrieving Status Details for VPCs from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to populate status history for VPCs", nil)
	}
	ssdMap := map[string][]cdbm.StatusDetail{}
	for _, ssd := range ssds {
		cssd := ssd
		ssdMap[ssd.EntityID] = append(ssdMap[ssd.EntityID], cssd)
	}

	// Create response
	apiVpcs := []model.APIVpc{}

	for _, vpc := range vpcs {
		apiVpc := model.NewAPIVpc(vpc, ssdMap[vpc.ID.String()])
		apiVpcs = append(apiVpcs, apiVpc)
	}

	// Create pagination response header
	pageReponse := pagination.NewPageResponse(*pageRequest.PageNumber, *pageRequest.PageSize, total, pageRequest.OrderByStr)
	pageHeader, err := json.Marshal(pageReponse)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling pagination response")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to generate pagination response header", nil)
	}

	c.Response().Header().Set(pagination.ResponseHeaderName, string(pageHeader))

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusOK, apiVpcs)
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteVPCHandler is the API Handler for deleting a VPC
type DeleteVPCHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewDeleteVPCHandler initializes and returns a new handler for deleting VPC
func NewDeleteVPCHandler(dbSession *cdb.Session, tc temporalClient.Client, scp *sc.ClientPool, cfg *config.Config) DeleteVPCHandler {
	return DeleteVPCHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete a VPC
// @Description Delete a VPC fro the org
// @Tags vpc
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of VPC"
// @Success 202
// @Router /v2/org/{org}/nico/vpc/{id} [delete]
func (dvh DeleteVPCHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("VPC", "Delete", c, dvh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org
	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Tenant Admins are allowed to interact with VPC endpoints
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get VPC ID from URL param
	vpcStrID := c.Param("id")
	vpcID, err := uuid.Parse(vpcStrID)
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid VPC ID in URL", nil)
	}

	dvh.tracerSpan.SetAttribute(handlerSpan, attribute.String("vpc_id", vpcStrID), logger)

	// Get VPC from DB
	vpcDAO := cdbm.NewVpcDAO(dvh.dbSession)
	vpc, err := vpcDAO.GetByID(ctx, nil, vpcID, []string{
		cdbm.SiteRelationName,
		cdbm.TenantRelationName,
	})
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find VPC with specified ID", nil)
		}
		logger.Error().Err(err).Msg("error retrieving VPC from DB by ID")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPC with specified ID", nil)
	}

	if vpc.Tenant == nil {
		logger.Warn().Err(err).Msg("failed to retrieve Tenant details")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant details", nil)
	}

	// Validate the tenant for which this VPC is being deleted
	if vpc.Tenant.Org != org {
		logger.Warn().Msg("org specified in request does not match org of Tenant associated with VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org specified in request does not match org of Tenant associated with VPC", nil)
	}

	// Verify that the VPC is associated with a site and then that the site is
	// in a valid state.
	if vpc.Site == nil {
		logger.Error().Msg("failed to pull site data for VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site details for VPC", nil)
	}

	// Verify if site is ready
	if vpc.Site.Status != cdbm.SiteStatusRegistered {
		logger.Warn().Str("Site ID", vpc.SiteID.String()).Msg("Site associated with VPC must be in Registered state in order to proceed")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site associated with VPC must be in Registered state in order to proceed", nil)
	}

	// Check if VPC has any resources subnet attached
	// Check if VPC has subnet attached
	sbDAO := cdbm.NewSubnetDAO(dvh.dbSession)
	subnets, _, err := sbDAO.GetAll(ctx, nil, cdbm.SubnetFilterInput{TenantIDs: []uuid.UUID{vpc.TenantID}, VpcIDs: []uuid.UUID{vpc.ID}}, cdbp.PageInput{}, []string{})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Subnet for this VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Subnets for this VPC", nil)
	}
	if len(subnets) > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Cannot delete VPC, one or more Subnets exist for this VPC", nil)
	}

	// Check if VPC has VPC prefix attached
	vpcPrefixDAO := cdbm.NewVpcPrefixDAO(dvh.dbSession)
	vpcPrefixes, _, err := vpcPrefixDAO.GetAll(ctx, nil, cdbm.VpcPrefixFilterInput{TenantIDs: []uuid.UUID{vpc.TenantID}, VpcIDs: []uuid.UUID{vpc.ID}}, cdbp.PageInput{}, []string{})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving VPC prefixes for this VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve VPC prefixes for this VPC", nil)
	}
	if len(vpcPrefixes) > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Cannot delete VPC, one or more VPC prefixes exist for this VPC", nil)
	}

	// Check if VPC has instance
	insDAO := cdbm.NewInstanceDAO(dvh.dbSession)
	instances, _, err := insDAO.GetAll(ctx, nil, cdbm.InstanceFilterInput{TenantIDs: []uuid.UUID{vpc.TenantID}, VpcIDs: []uuid.UUID{vpc.ID}}, cdbp.PageInput{}, []string{})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving instances for this VPC")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve instances for this VPC", nil)
	}
	if len(instances) > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Cannot delete VPC, one or more instances for this VPC", nil)
	}

	sdDAO := cdbm.NewStatusDetailDAO(dvh.dbSession)

	// timeoutResp lets the closure signal a post-rollback handler — the
	// TerminateWorkflow call has to run after the closure returns so that
	// the DB tx unwinds before we make the second remote call. nil means
	// no timeout occurred and the normal flow continues.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, dvh.dbSession, func(tx *cdb.Tx) error {
		// Update VPC to set status to Deleting
		uvpcInput := cdbm.VpcUpdateInput{
			VpcID:  vpc.ID,
			Status: cdb.GetStrPtr(cdbm.VpcStatusDeleting),
		}
		if _, derr := vpcDAO.Update(ctx, tx, uvpcInput); derr != nil {
			logger.Error().Err(derr).Msg("error updating VPC in DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete VPC", nil)
		}

		// Create status detail (best-effort: original code only logs on error)
		if _, derr := sdDAO.CreateFromParams(ctx, tx, vpc.ID.String(), *cdb.GetStrPtr(cdbm.VpcStatusDeleting),
			cdb.GetStrPtr("received request for deletion, pending processing")); derr != nil {
			logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
		}

		// Get the temporal client for the site we are working with.
		stc, derr := dvh.scp.GetClientByID(vpc.SiteID)
		if derr != nil {
			logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
		}

		deleteVpcRequest := vpc.ToDeletionRequestProto()

		workflowOptions := temporalClient.StartWorkflowOptions{
			ID:                       "vpc-delete-" + vpc.ID.String(),
			TaskQueue:                queue.SiteTaskQueue,
			WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		}

		logger.Info().Msg("triggering VPC delete workflow")

		// Add context deadlines
		wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
		defer cancel()

		// Trigger Site workflow
		we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "DeleteVPCV2", deleteVpcRequest)
		if wferr != nil {
			logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to delete VPC")
			return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to delete VPC on Site: %s", wferr), nil)
		}

		wid := we.GetID()
		logger.Info().Str("Workflow ID", wid).Msg("executed synchronous delete VPC workflow")

		// Execute the workflow synchronously
		wferr = we.Get(wfCtx, nil)
		// Handle skippable errors
		if wferr != nil {
			// If this was a 404 back from NICo, we can treat the object as already having been deleted and allow things to proceed.
			var applicationErr *tp.ApplicationError
			if errors.As(wferr, &applicationErr) && slices.Contains(swe.ObjectNotFoundErrTypes(), applicationErr.Type()) {
				logger.Warn().Msg(swe.ErrTypeNICoObjectNotFound + " received from Site")
				// Reset error to nil
				wferr = nil
			}
		}

		if wferr != nil {
			var timeoutErr *tp.TimeoutError
			if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
				logger.Error().Err(wferr).Msg("failed to delete VPC, timeout occurred executing workflow on Site.")
				timeoutResp = func() error {
					return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "VPC", "Delete")
				}
				return cutil.NewAPIError(http.StatusInternalServerError, "VPC delete workflow timed out", nil)
			}

			code, unwrapped := common.UnwrapWorkflowError(wferr)
			logger.Error().Err(unwrapped).Msg("failed to synchronously execute Temporal workflow to delete VPC")
			return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to delete VPC on Site: %s", unwrapped), nil)
		}

		logger.Info().Str("Workflow ID", wid).Msg("completed synchronous delete VPC workflow")
		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to delete VPC due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// Return response
	logger.Info().Msg("finishing API handler")

	return c.String(http.StatusAccepted, "Deletion request was accepted")
}
