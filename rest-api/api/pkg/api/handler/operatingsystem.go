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

	"go.opentelemetry.io/otel/attribute"
	temporalClient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	auth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

// ~~~~~ Create Handler ~~~~~ //

// CreateOperatingSystemHandler is the API Handler for creating new OperatingSystem
type CreateOperatingSystemHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateOperatingSystemHandler initializes and returns a new handler for creating OperatingSystem
func NewCreateOperatingSystemHandler(dbSession *cdb.Session, tc temporalClient.Client, scp *sc.ClientPool, cfg *config.Config) CreateOperatingSystemHandler {
	return CreateOperatingSystemHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Create an OperatingSystem
// @Description Create an OperatingSystem
// @Tags OperatingSystem
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param message body model.APIOperatingSystemCreateRequest true "OperatingSystem creation request"
// @Success 201 {object} model.APIOperatingSystem
// @Router /v2/org/{org}/nico/operating-system [post]
func (csh CreateOperatingSystemHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("OperatingSystem", "Create", c, csh.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to create OperatingSystem
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIOperatingSystemCreateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	// Validate the tenant for which this OperatingSystem is being created
	tenant, err := common.GetTenantForOrg(ctx, nil, csh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Warn().Err(err).Msg("Org does not have a Tenant associated")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("unable to retrieve tenant for org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
	}

	// Default TenantID to org's Tenant when nil; validate when set
	if apiRequest.TenantID == nil {
		apiRequest.TenantID = cutil.GetPtr(tenant.ID.String())
	} else if *apiRequest.TenantID != tenant.ID.String() {
		logger.Warn().Str("tenantId", *apiRequest.TenantID).Msg("TenantID in request does not match org's Tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "TenantID specified in request does not match org's Tenant", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Operating System creation request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Operating System request creation data", verr)
	}

	// Validate and Set UserData
	verr = apiRequest.ValidateAndSetUserData(csh.cfg.GetSitePhoneHomeUrl())
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating user data in Operating System creation request")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating user data in Operating System creation request", verr)
	}

	// check for name uniqueness for the tenant, ie, tenant cannot have another os with same name
	// TODO consider doing this with an advisory lock for correctness
	osDAO := cdbm.NewOperatingSystemDAO(csh.dbSession)
	oss, tot, err := osDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemFilterInput{
			TenantIDs: []uuid.UUID{tenant.ID},
			Names:     []string{apiRequest.Name},
		},
		cdbp.PageInput{},
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("db error checking for name uniqueness of tenant os")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create OperatingSystem due to DB error", nil)
	}
	if tot > 0 {
		logger.Warn().Str("tenantId", tenant.ID.String()).Str("name", apiRequest.Name).Msg("Operating System with same name already exists for tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusConflict, "Another Operating System with specified name already exists for Tenant", validation.Errors{
			"id": errors.New(oss[0].ID.String()),
		})
	}

	// check OS type from request
	osType := cdbm.OperatingSystemTypeImage
	if apiRequest.IpxeScript != nil {
		osType = cdbm.OperatingSystemTypeIPXE
	}

	// Set the phoneHomeEnabled if provided in request
	phoneHomeEnabled := false
	if apiRequest.PhoneHomeEnabled != nil {
		phoneHomeEnabled = *apiRequest.PhoneHomeEnabled
	}

	// Verify or validate site
	tsDAO := cdbm.NewTenantSiteDAO(csh.dbSession)
	rdbst := []cdbm.Site{}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}
	dbossd := []cdbm.StatusDetail{}

	// Get all TenantSite records for the Tenant
	tss, _, err := tsDAO.GetAll(
		ctx,
		nil,
		cdbm.TenantSiteFilterInput{
			TenantIDs: []uuid.UUID{tenant.ID},
		},
		cdbp.PageInput{
			Limit: cutil.GetPtr(cdbp.TotalLimit),
		},
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("db error retrieving TenantSite records for Tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site associations for Tenant, DB error", nil)
	}
	for _, ts := range tss {
		cts := ts
		sttsmap[ts.SiteID] = &cts
	}

	// Validate the site for which this image based Operating System is being created
	for _, stID := range apiRequest.SiteIDs {
		site, serr := common.GetSiteFromIDString(ctx, nil, stID, csh.dbSession)
		if serr != nil {
			if serr == common.ErrInvalidID {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to create Operating System, invalid Site ID: %s", stID), nil)
			}
			if serr == cdb.ErrDoesNotExist {
				return cutil.NewAPIErrorResponse(c, http.StatusNotFound, fmt.Sprintf("Failed to create Operating System, could not find Site with ID: %s ", stID), nil)
			}
			logger.Warn().Err(serr).Str("Site ID", stID).Msg("error retrieving Site from DB by ID")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to create Operating System, could not retrieve Site with ID: %s, DB error", stID), nil)
		}

		if site.Status != cdbm.SiteStatusRegistered {
			logger.Warn().Msg(fmt.Sprintf("Unable to associate Operating System to Site: %s. Site is not in Registered state", site.ID.String()))
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to create Operating System, Site: %s specified in request is not in Registered state", site.ID.String()), nil)
		}

		// Validate the TenantSite exists for current tenant and this site
		_, ok := sttsmap[site.ID]
		if !ok {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Unable to associate Operating System with Site: %s, Tenant does not have access to Site", stID), nil)
		}

		// Validate the Site has the ImageBasedOperatingSystem capability enabled for Image based Operating Systems
		if osType == cdbm.OperatingSystemTypeImage && (site.Config == nil || !site.Config.ImageBasedOperatingSystem) {
			logger.Warn().Str("siteId", stID).Msg("Image based Operating System is not supported for Site, ImageBasedOperatingSystem capability is not enabled")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Creation of Image based Operating Systems is not supported. Site must have ImageBasedOperatingSystem capability enabled.", nil)
		}

		rdbst = append(rdbst, *site)
	}

	// Create status based on OS type
	osStatus := cdbm.OperatingSystemStatusReady
	osStatusMessage := "Operating System is ready for use"
	if osType == cdbm.OperatingSystemTypeImage {
		osStatus = cdbm.OperatingSystemStatusSyncing
		osStatusMessage = "received Operating System creation request, syncing"
	}

	// Values needed after the transaction closure
	var os *cdbm.OperatingSystem
	var dbossa []cdbm.OperatingSystemSiteAssociation
	// timeoutResp captures any post-rollback work (terminating timed-out
	// Temporal workflows) that must run after the transaction has been rolled
	// back. It is invoked after the closure if non-nil.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, csh.dbSession, func(tx *cdb.Tx) error {
		// Create the db record for Operating System
		osInput := cdbm.OperatingSystemCreateInput{
			Name:               apiRequest.Name,
			Description:        apiRequest.Description,
			Org:                org,
			TenantID:           &tenant.ID,
			OsType:             osType,
			ImageURL:           apiRequest.ImageURL,
			ImageSHA:           apiRequest.ImageSHA,
			ImageAuthType:      apiRequest.ImageAuthType,
			ImageAuthToken:     apiRequest.ImageAuthToken,
			ImageDisk:          apiRequest.ImageDisk,
			RootFsId:           apiRequest.RootFsID,
			RootFsLabel:        apiRequest.RootFsLabel,
			IpxeScript:         apiRequest.IpxeScript,
			UserData:           apiRequest.UserData,
			IsCloudInit:        apiRequest.IsCloudInit,
			AllowOverride:      apiRequest.AllowOverride,
			EnableBlockStorage: apiRequest.EnableBlockStorage,
			PhoneHomeEnabled:   phoneHomeEnabled,
			Status:             osStatus,
			CreatedBy:          dbUser.ID,
		}
		createdOs, derr := osDAO.Create(ctx, tx, osInput)
		if derr != nil {
			logger.Error().Err(derr).Msg("unable to create Operating System record in DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed creating Operating System record", nil)
		}
		os = createdOs

		// Create the status detail record for Operating System
		sdDAO := cdbm.NewStatusDetailDAO(csh.dbSession)
		ossd, derr := sdDAO.CreateFromParams(ctx, tx, os.ID.String(), *cutil.GetPtr(osStatus),
			cutil.GetPtr(osStatusMessage))
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for Operating System", nil)
		}

		if ossd == nil {
			logger.Error().Msg("Status Detail DB entry not returned from CreateFromParams")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to get new Status Detail for Operating System", nil)
		}
		dbossd = append(dbossd, *ossd)

		// Create Operating System Site Associations
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(csh.dbSession)
		for _, st := range rdbst {
			// Create Operating System Site Association
			ossa, derr := ossaDAO.Create(
				ctx,
				tx,
				cdbm.OperatingSystemSiteAssociationCreateInput{
					OperatingSystemID: os.ID,
					SiteID:            st.ID,
					Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
					CreatedBy:         dbUser.ID,
				},
			)
			if derr != nil {
				logger.Error().Err(derr).Msg("unable to create the Operating System association record in DB")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to associate Operating System with one or more Sites, DB error", nil)
			}

			// Create Status details
			_, derr = sdDAO.CreateFromParams(ctx, tx, ossa.ID.String(), *cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusSyncing),
				cutil.GetPtr("received Operating System Association create request, syncing"))
			if derr != nil {
				logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for Operating System Association", nil)
			}

			// Update Operating System Site Association version
			_, derr = ossaDAO.GenerateAndUpdateVersion(ctx, tx, ossa.ID)
			if derr != nil {
				logger.Error().Err(derr).Msg("error updating version for created Operating System Association")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to set version for created Operating System Association, DB error", nil)
			}
		}

		// Retrieve Operating System Associations details
		retossa, _, derr := ossaDAO.GetAll(
			ctx,
			tx,
			cdbm.OperatingSystemSiteAssociationFilterInput{
				OperatingSystemIDs: []uuid.UUID{os.ID},
			},
			cdbp.PageInput{
				Limit: cutil.GetPtr(cdbp.TotalLimit),
			},
			[]string{cdbm.SiteRelationName, cdbm.OperatingSystemRelationName},
		)
		if derr != nil {
			logger.Error().Err(derr).Msg("error retrieving Operating System Site associations from DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
		}
		dbossa = retossa

		// Trigger workflows to sync Image based Operating System with various Sites
		for _, ossa := range dbossa {
			// Iteration body wrapped in a function literal so `defer cancel()`
			// scopes to the iteration; otherwise the deferred cancels would
			// pile up until the WithTx closure returns.
			iterErr := func() *cutil.APIError {
				// Get the temporal client for the site we are working with.
				stc, derr := csh.scp.GetClientByID(ossa.SiteID)
				if derr != nil {
					logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
					return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
				}

				createOsRequest := apiRequest.ToProto(os, tenant.Org)

				workflowOptions := temporalClient.StartWorkflowOptions{
					ID:                       "image-os-create-" + ossa.SiteID.String() + "-" + os.ID.String() + "-" + *ossa.Version,
					WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
					TaskQueue:                queue.SiteTaskQueue,
				}

				logger.Info().Str("Site ID", ossa.SiteID.String()).Msg("triggering Image based Operating System create workflow ")

				// Add context deadlines
				wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
				defer cancel()

				// Trigger Site workflow
				we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "CreateOsImage", createOsRequest)
				if wferr != nil {
					logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to create Operating System")
					return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to create Operating System on Site: %s", wferr), nil)
				}

				wid := we.GetID()
				logger.Info().Str("Workflow ID", wid).Msg("executed synchronous create Operating System workflow")

				// Block until the workflow has completed and returned success/error.
				wferr = we.Get(wfCtx, nil)
				if wferr != nil {
					var timeoutErr *tp.TimeoutError
					if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
						logger.Error().Err(wferr).Msg("failed to create Operating System, timeout occurred executing workflow on Site.")
						timeoutResp = func() error {
							return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "OperatingSystem", "Create")
						}
						return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Operating System, timeout occurred executing workflow on Site", nil)
					}

					code, uwerr := common.UnwrapWorkflowError(wferr)
					logger.Error().Err(uwerr).Msg("failed to synchronously execute Temporal workflow to create Operating System")
					return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to create Operating System on Site: %s", uwerr), nil)
				}
				logger.Info().Str("Workflow ID", wid).Str("Site ID", ossa.SiteID.String()).Msg("completed synchronous create Operating System workflow")
				return nil
			}()
			if iterErr != nil {
				return iterErr
			}
		}

		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to create Operating System due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// create response
	apiOperatingSystem := model.NewAPIOperatingSystem(os, dbossd, dbossa, sttsmap)
	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusCreated, apiOperatingSystem)
}

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllOperatingSystemHandler is the API Handler for getting all OperatingSystems
type GetAllOperatingSystemHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllOperatingSystemHandler initializes and returns a new handler for getting all OperatingSystems
func NewGetAllOperatingSystemHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetAllOperatingSystemHandler {
	return GetAllOperatingSystemHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get all OperatingSystems
// @Description Get all OperatingSystems
// @Tags OperatingSystem
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteId query string true "ID of Site"
// @Param type query string true "type of Operating System" e.g. 'iPXE', 'Image'"
// @Param status query string false "Filter by status" e.g. 'Pending', 'Error'"
// @Param query query string false "Query input for full text search"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Tenant'"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Param orderBy query string false "Order by field"
// @Success 200 {object} []model.APIOperatingSystem
// @Router /v2/org/{org}/nico/operating-system [get]
func (gash GetAllOperatingSystemHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("OperatingSystem", "GetAll", c, gash.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to retrieve OperatingSystems
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
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
	err = pageRequest.Validate(cdbm.OperatingSystemOrderByFields)
	if err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	// Validate the tenant associated with the org
	tenant, err := common.GetTenantForOrg(ctx, nil, gash.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Warn().Err(err).Msg("Org does not have a Tenant associated")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("unable to retrieve tenant for org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
	}

	filter := cdbm.OperatingSystemFilterInput{
		TenantIDs: []uuid.UUID{tenant.ID},
		Orgs:      []string{org},
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errMsg := common.GetAndValidateQueryRelations(qParams, cdbm.OperatingSystemRelatedEntities)
	if errMsg != "" {
		logger.Warn().Msg(errMsg)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errMsg, nil)
	}

	// now check siteID in query
	tsDAO := cdbm.NewTenantSiteDAO(gash.dbSession)

	qSiteID := qParams["siteId"]
	if len(qSiteID) > 0 {
		for _, siteID := range qSiteID {
			site, err := common.GetSiteFromIDString(ctx, nil, siteID, gash.dbSession)
			if err != nil {
				logger.Warn().Err(err).Msg("error getting Site from query string")
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to retrieve Site specified in query", nil)
			}

			// Determine if tenant has access to requested site
			_, err = tsDAO.GetByTenantIDAndSiteID(ctx, nil, tenant.ID, site.ID, nil)
			if err != nil {
				if err == cdb.ErrDoesNotExist {
					return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant is not associated with Site specified in query", nil)
				}
				logger.Warn().Err(err).Msg("error retrieving Tenant Site association from DB")
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to determine if Tenant has access to Site specified in query, DB error", nil)
			}
			filter.SiteIDs = append(filter.SiteIDs, site.ID)
		}
	}

	// Get query type from query param
	if typeQuery := qParams["type"]; len(typeQuery) > 0 {
		gash.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("type", typeQuery), logger)
		for _, typeVal := range typeQuery {
			_, ok := cdbm.OperatingSystemsTypeMap[typeVal]
			if !ok {
				logger.Warn().Msg(fmt.Sprintf("Invalid type value in query: %v", typeVal))
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid type value in query", nil)
			}
			filter.OsTypes = append(filter.OsTypes, typeVal)
		}
	}

	// Get query text for full text search from query param
	searchQuery := common.GetSearchQuery(c)
	if searchQuery != nil {
		filter.SearchQuery = searchQuery
		gash.tracerSpan.SetAttribute(handlerSpan, attribute.String("query", *searchQuery), logger)
	}

	// Get status from query param
	if statusQuery := qParams["status"]; len(statusQuery) > 0 {
		gash.tracerSpan.SetAttribute(handlerSpan, attribute.StringSlice("status", statusQuery), logger)
		for _, status := range statusQuery {
			_, ok := cdbm.OperatingSystemStatusMap[status]
			if !ok {
				logger.Warn().Msg(fmt.Sprintf("invalid value in status query: %v", status))
				statusError := validation.Errors{
					"status": errors.New(status),
				}
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Status value in query", statusError)
			}
			filter.Statuses = append(filter.Statuses, status)
		}
	}

	// Get all Operating System by Tenant
	osDAO := cdbm.NewOperatingSystemDAO(gash.dbSession)
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(gash.dbSession)

	// Create response
	oss, total, err := osDAO.GetAll(
		ctx,
		nil,
		filter,
		cdbp.PageInput{
			Offset:  pageRequest.Offset,
			Limit:   pageRequest.Limit,
			OrderBy: pageRequest.OrderBy,
		},
		qIncludeRelations,
	)
	if err != nil {
		logger.Error().Err(err).Msg("error getting os from db")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve OperatingSystems", nil)
	}

	// Get status details
	sdDAO := cdbm.NewStatusDetailDAO(gash.dbSession)

	osIDs := []uuid.UUID{}
	sdEntityIDs := []string{}
	for _, os := range oss {
		sdEntityIDs = append(sdEntityIDs, os.ID.String())
		osIDs = append(osIDs, os.ID)
	}

	ssds, serr := sdDAO.GetRecentByEntityIDs(ctx, nil, sdEntityIDs, common.RECENT_STATUS_DETAIL_COUNT)
	if serr != nil {
		logger.Warn().Err(serr).Msg("error retrieving Status Details for Operating Systems from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to populate status history for Operating Systems", nil)
	}
	ssdMap := map[string][]cdbm.StatusDetail{}
	for _, ssd := range ssds {
		cssd := ssd
		ssdMap[ssd.EntityID] = append(ssdMap[ssd.EntityID], cssd)
	}

	// Get all OperatingSystemSiteAssociations
	var siteIDs []uuid.UUID
	if filter.SiteIDs != nil {
		siteIDs = filter.SiteIDs
	}
	dbossas, _, err := ossaDAO.GetAll(
		ctx,
		nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{
			OperatingSystemIDs: osIDs,
			SiteIDs:            siteIDs,
		},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
		[]string{cdbm.SiteRelationName},
	)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
	}

	// Prepare OperatingSystemSiteAssociation for each OS if it exists
	dbossaMap := map[uuid.UUID][]cdbm.OperatingSystemSiteAssociation{}
	for _, dbossa := range dbossas {
		curVal := dbossa
		dbossaMap[dbossa.OperatingSystemID] = append(dbossaMap[dbossa.OperatingSystemID], curVal)
	}

	// Get all TenantSite records for the Tenant
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}

	tsDAO = cdbm.NewTenantSiteDAO(gash.dbSession)
	tss, _, err := tsDAO.GetAll(
		ctx,
		nil,
		cdbm.TenantSiteFilterInput{
			TenantIDs: []uuid.UUID{tenant.ID},
			SiteIDs:   siteIDs,
		},
		cdbp.PageInput{
			Limit: cutil.GetPtr(cdbp.TotalLimit),
		},
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("db error retrieving TenantSite records for Tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site associations for Tenant, DB error", nil)
	}

	for _, ts := range tss {
		curVal := ts
		sttsmap[ts.SiteID] = &curVal
	}

	// Create response
	apiOperatingSystems := []*model.APIOperatingSystem{}

	for _, os := range oss {
		if os.Type == cdbm.OperatingSystemTypeImage {
			fmt.Printf("Processing Operating System: %s, Type: %s\n", os.Name, os.Type)
		}

		curVal := os
		apiOperatingSystem := model.NewAPIOperatingSystem(&curVal, ssdMap[os.ID.String()], dbossaMap[os.ID], sttsmap)
		apiOperatingSystems = append(apiOperatingSystems, apiOperatingSystem)
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

	return c.JSON(http.StatusOK, apiOperatingSystems)

}

// ~~~~~ Get Handler ~~~~~ //

// GetOperatingSystemHandler is the API Handler for retrieving OperatingSystem
type GetOperatingSystemHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetOperatingSystemHandler initializes and returns a new handler to retrieve OperatingSystem
func NewGetOperatingSystemHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetOperatingSystemHandler {
	return GetOperatingSystemHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve the OperatingSystem
// @Description Retrieve the OperatingSystem
// @Tags OperatingSystem
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of OperatingSystem"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Tenant', 'Site'"
// @Success 200 {object} model.APIOperatingSystem
// @Router /v2/org/{org}/nico/operating-system/{id} [get]
func (gsh GetOperatingSystemHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("OperatingSystem", "Get", c, gsh.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to retrieve OperatingSystem
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errMsg := common.GetAndValidateQueryRelations(qParams, cdbm.OperatingSystemRelatedEntities)
	if errMsg != "" {
		logger.Warn().Msg(errMsg)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errMsg, nil)
	}

	// Get os ID from URL param
	osStrID := c.Param("id")

	gsh.tracerSpan.SetAttribute(handlerSpan, attribute.String("operatingsystem_id", osStrID), logger)

	sID, err := uuid.Parse(osStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid OperatingSystem ID in URL", nil)
	}

	osDAO := cdbm.NewOperatingSystemDAO(gsh.dbSession)

	// Validate the tenant for which this OperatingSystem is being retrieved
	tenant, err := common.GetTenantForOrg(ctx, nil, gsh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Warn().Err(err).Msg("Org does not have a Tenant associated")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("unable to retrieve tenant for org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
	}

	// Check that operating system exists
	os, err := osDAO.GetByID(ctx, nil, sID, qIncludeRelations)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving OperatingSystem DB entity")
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve OperatingSystem to update", nil)
		}
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve OperatingSystem to update", nil)
	}

	// verify tenant matches
	if os.TenantID == nil || tenant.ID != *os.TenantID {
		logger.Warn().Msg("tenant in org does not match tenant in operating system")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant for OperatingSystem in request does not match tenant in org", nil)
	}

	// get status details for the response
	sdDAO := cdbm.NewStatusDetailDAO(gsh.dbSession)
	ssds, err := sdDAO.GetRecentByEntityIDs(ctx, nil, []string{os.ID.String()}, common.RECENT_STATUS_DETAIL_COUNT)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Status Details for operating system from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for OperatingSystem", nil)
	}

	dbossas := []cdbm.OperatingSystemSiteAssociation{}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}
	if os.Type == cdbm.OperatingSystemTypeImage {
		// Get all OperatingSystemSiteAssociations
		ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(gsh.dbSession)
		dbossas, _, err = ossaDAO.GetAll(
			ctx,
			nil,
			cdbm.OperatingSystemSiteAssociationFilterInput{
				OperatingSystemIDs: []uuid.UUID{os.ID},
			},
			cdbp.PageInput{
				Limit: cutil.GetPtr(cdbp.TotalLimit),
			},
			[]string{cdbm.SiteRelationName},
		)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
		}

		// Get all TenantSite records for the Tenant
		tsDAO := cdbm.NewTenantSiteDAO(gsh.dbSession)
		tss, _, err := tsDAO.GetAll(
			ctx,
			nil,
			cdbm.TenantSiteFilterInput{
				TenantIDs: []uuid.UUID{tenant.ID},
			},
			cdbp.PageInput{
				Limit: cutil.GetPtr(cdbp.TotalLimit),
			},
			nil,
		)
		if err != nil {
			logger.Error().Err(err).Msg("db error retrieving TenantSite records for Tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site associations for Tenant, DB error", nil)
		}

		for _, ts := range tss {
			cts := ts
			sttsmap[ts.SiteID] = &cts
		}
	}

	// Send response
	apiInstance := model.NewAPIOperatingSystem(os, ssds, dbossas, sttsmap)
	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiInstance)
}

// ~~~~~ Update Handler ~~~~~ //

// UpdateOperatingSystemHandler is the API Handler for updating a OperatingSystem
type UpdateOperatingSystemHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewUpdateOperatingSystemHandler initializes and returns a new handler for updating OperatingSystem
func NewUpdateOperatingSystemHandler(dbSession *cdb.Session, tc temporalClient.Client, scp *sc.ClientPool, cfg *config.Config) UpdateOperatingSystemHandler {
	return UpdateOperatingSystemHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update an existing OperatingSystem
// @Description Update an existing OperatingSystem
// @Tags OperatingSystem
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of OperatingSystem"
// @Param message body model.APIOperatingSystemUpdateRequest true "OperatingSystem update request"
// @Success 200 {object} model.APIOperatingSystem
// @Router /v2/org/{org}/nico/operating-system/{id} [patch]
func (ush UpdateOperatingSystemHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("OperatingSystem", "Update", c, ush.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to update OperatingSystem
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get os ID from URL param
	osStrID := c.Param("id")

	ush.tracerSpan.SetAttribute(handlerSpan, attribute.String("operatingsystem_id", osStrID), logger)

	osID, err := uuid.Parse(osStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid OperatingSystem ID in URL", nil)
	}

	osDAO := cdbm.NewOperatingSystemDAO(ush.dbSession)

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIOperatingSystemUpdateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Check that os exists
	os, err := osDAO.GetByID(ctx, nil, osID, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving OperatingSystem DB entity")
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Operating System with ID specified in URL", nil)
		}
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve OperatingSystem to update", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate(os)
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Operating System update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Operating System update request data", verr)
	}

	// Validate and Set UserData
	verr = apiRequest.ValidateAndSetUserData(ush.cfg.GetSitePhoneHomeUrl(), os)
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating user data in Operating System creation request")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating user data in Operating System creation request", verr)
	}

	// Validate the tenant for which this OperatingSystem is being updated
	tenant, err := common.GetTenantForOrg(ctx, nil, ush.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Warn().Err(err).Msg("Org does not have a Tenant associated")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("unable to retrieve tenant for org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
	}

	// verify tenant matches
	if os.TenantID == nil || tenant.ID != *os.TenantID {
		logger.Warn().Msg("tenant in os does not belong to tenant in org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant for OperatingSystem in request does not match tenant in org", nil)
	}

	// check for name uniqueness for the tenant, ie, tenant cannot have another os with same name
	if apiRequest.Name != nil && *apiRequest.Name != os.Name {
		oss, tot, serr := osDAO.GetAll(
			ctx,
			nil,
			cdbm.OperatingSystemFilterInput{
				TenantIDs: []uuid.UUID{tenant.ID},
				Names:     []string{*apiRequest.Name},
			},
			cdbp.PageInput{},
			nil,
		)
		if serr != nil {
			logger.Error().Err(serr).Msg("db error checking for name uniqueness of tenant os")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update OperatingSystem due to DB error", nil)
		}
		if tot > 0 {
			return cutil.NewAPIErrorResponse(c, http.StatusConflict, "Another Operating System with specified name already exists for Tenant", validation.Errors{
				"id": errors.New(oss[0].ID.String()),
			})
		}
	}

	dbossas := []cdbm.OperatingSystemSiteAssociation{}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(ush.dbSession)
	tsDAO := cdbm.NewTenantSiteDAO(ush.dbSession)

	// Verify Tenant Site Association
	// Verify if Site is in Registered state
	if os.Type == cdbm.OperatingSystemTypeImage {
		dbossas, _, err = ossaDAO.GetAll(
			ctx,
			nil,
			cdbm.OperatingSystemSiteAssociationFilterInput{
				OperatingSystemIDs: []uuid.UUID{os.ID},
			},
			cdbp.PageInput{},
			[]string{cdbm.SiteRelationName},
		)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
		}

		// Get all TenantSite records for the Tenant
		tss, _, err := tsDAO.GetAll(
			ctx,
			nil,
			cdbm.TenantSiteFilterInput{
				TenantIDs: []uuid.UUID{tenant.ID},
			},
			cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
			nil,
		)
		if err != nil {
			logger.Error().Err(err).Msg("db error retrieving TenantSite records for Tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site associations for Tenant, DB error", nil)
		}

		for _, ts := range tss {
			cts := ts
			sttsmap[ts.SiteID] = &cts
		}

		// Verify if associated Site is not registered state
		// Verify if current tenant not associated Site
		for _, dbosa := range dbossas {
			if dbosa.Site.Status != cdbm.SiteStatusRegistered {
				logger.Warn().Msg(fmt.Sprintf("unable to update Operating System. Site: %s. Site is not in Registered state", dbosa.Site.Name))
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to update Operating System, Associated Site: %s is not in Registered state", dbosa.Site.Name), nil)
			}

			// Validate the TenantSite exists for current tenant and this site
			_, ok := sttsmap[dbosa.SiteID]
			if !ok {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Unable to update associate Operating System with Site: %s, Tenant does not have access to Site", dbosa.Site.Name), nil)
			}
		}
	}

	// Save update status in DB
	osStatus := cutil.GetPtr(cdbm.OperatingSystemStatusReady)
	osStatusMessage := "Operating System has been updated and ready for use"
	if apiRequest.IsActive != nil && !*apiRequest.IsActive {
		osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusDeactivated)
		osStatusMessage = "Operating System has been deactivated"
		if apiRequest.DeactivationNote != nil && *apiRequest.DeactivationNote != "" {
			osStatusMessage += ". " + *apiRequest.DeactivationNote
		}
	} else {
		if apiRequest.IsActive != nil && *apiRequest.IsActive {
			osStatusMessage = "Operating System has been reactivated and is ready for use"
		}
		if os.Type == cdbm.OperatingSystemTypeImage {
			osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusSyncing)
			osStatusMessage = "received Operating System update request, syncing"
		}
	}

	// Values needed after the transaction closure
	var uos *cdbm.OperatingSystem
	var ssds []cdbm.StatusDetail
	// timeoutResp captures any post-rollback work (terminating timed-out
	// Temporal workflows) that must run after the transaction has been rolled
	// back. It is invoked after the closure if non-nil.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, ush.dbSession, func(tx *cdb.Tx) error {
		// When switching from inactive to active, clear deactivation note
		deactivationNote := apiRequest.DeactivationNote
		if apiRequest.IsActive != nil && *apiRequest.IsActive {
			deactivationNote = nil
			_, derr := osDAO.Clear(ctx, tx, cdbm.OperatingSystemClearInput{OperatingSystemId: osID, DeactivationNote: true})
			if derr != nil {
				logger.Error().Err(derr).Msg("error updating/clearing Operating System in DB")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update/clear Operating System", nil)
			}
		}
		updatedOs, derr := osDAO.Update(ctx, tx, cdbm.OperatingSystemUpdateInput{
			OperatingSystemId: osID,
			Name:              apiRequest.Name,
			Description:       apiRequest.Description,
			ImageURL:          apiRequest.ImageURL,
			ImageSHA:          apiRequest.ImageSHA,
			ImageAuthType:     apiRequest.ImageAuthType,
			ImageAuthToken:    apiRequest.ImageAuthToken,
			ImageDisk:         apiRequest.ImageDisk,
			RootFsId:          apiRequest.RootFsID,
			RootFsLabel:       apiRequest.RootFsLabel,
			IpxeScript:        apiRequest.IpxeScript,
			UserData:          apiRequest.UserData,
			IsCloudInit:       apiRequest.IsCloudInit,
			AllowOverride:     apiRequest.AllowOverride,
			PhoneHomeEnabled:  apiRequest.PhoneHomeEnabled,
			IsActive:          apiRequest.IsActive,
			DeactivationNote:  deactivationNote,
			Status:            osStatus,
		})
		if derr != nil {
			logger.Error().Err(derr).Msg("error updating Operating System in DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update Operating System", nil)
		}
		uos = updatedOs
		logger.Info().Msg("done updating os in DB")

		sdDAO := cdbm.NewStatusDetailDAO(ush.dbSession)
		_, derr = sdDAO.CreateFromParams(ctx, tx, uos.ID.String(), *osStatus, &osStatusMessage)
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create status detail for Operating System update", nil)
		}

		// get status details for the response
		retssds, _, derr := sdDAO.GetAllByEntityID(ctx, tx, uos.ID.String(), nil, cutil.GetPtr(pagination.MaxPageSize), nil)
		if derr != nil {
			logger.Error().Err(derr).Msg("error retrieving Status Details for os from DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve Status Details for Operating System", nil)
		}
		ssds = retssds

		// If OS is Image based, update version too
		// Retrieve Operating System Associations details
		// Trigger workflows to sync Image based Operating System with various Sites
		if uos.Type == cdbm.OperatingSystemTypeImage {
			for _, dbossa := range dbossas {
				_, derr := ossaDAO.Update(
					ctx,
					tx,
					cdbm.OperatingSystemSiteAssociationUpdateInput{
						OperatingSystemSiteAssociationID: dbossa.ID,
						Status:                           cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusSyncing),
					},
				)
				if derr != nil {
					logger.Error().Err(derr).Msg("unable to update the Operating System association record in DB")
					return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update Operating System Site Association status, DB error", nil)
				}

				// Create Status details
				_, derr = sdDAO.CreateFromParams(ctx, tx, dbossa.ID.String(), *cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusSyncing),
					cutil.GetPtr("received Operating System Association update request, syncing"))
				if derr != nil {
					logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
					return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for Operating System Site Association", nil)
				}

				// Update Operating System Association version
				updatedOssa, derr := ossaDAO.GenerateAndUpdateVersion(ctx, tx, dbossa.ID)
				if derr != nil {
					logger.Error().Err(derr).Msg("error updating version for updated Operating System Association")
					return cutil.NewAPIError(http.StatusInternalServerError, "Failed to set version for updated Operating System Site Association, DB error", nil)
				}

				// Get the temporal client for the site we are working with.
				stc, derr := ush.scp.GetClientByID(dbossa.SiteID)
				if derr != nil {
					logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
					return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
				}

				updateOsRequest := apiRequest.ToProto(uos, tenant.Org)

				workflowOptions := temporalClient.StartWorkflowOptions{
					ID:                       "image-os-update-" + updatedOssa.SiteID.String() + "-" + uos.ID.String() + "-" + *updatedOssa.Version,
					WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
					TaskQueue:                queue.SiteTaskQueue,
				}

				logger.Info().Str("Site ID", dbossa.SiteID.String()).Msg("triggering Image based Operating System update workflow ")

				// Workflow execution wrapped in a function literal so `defer cancel()`
				// scopes to this iteration; otherwise the deferred cancels would pile
				// up until the WithTx closure returns.
				iterErr := func() *cutil.APIError {
					// Add context deadlines
					wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
					defer cancel()

					// Trigger Site workflow
					we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "UpdateOsImage", updateOsRequest)
					if wferr != nil {
						logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to update Operating System")
						return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed start sync workflow to update Operating System on Site: %s", wferr), nil)
					}

					wid := we.GetID()
					logger.Info().Str("Workflow ID", wid).Msg("executed synchronous update Operating System workflow")

					// Block until the workflow has completed and returned success/error.
					wferr = we.Get(wfCtx, nil)
					if wferr != nil {
						var timeoutErr *tp.TimeoutError
						if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
							logger.Error().Err(wferr).Msg("failed to update Operating System, timeout occurred executing workflow on Site.")
							timeoutResp = func() error {
								return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "OperatingSystem", "Update")
							}
							return cutil.NewAPIError(http.StatusInternalServerError, "Failed to update Operating System, timeout occurred executing workflow on Site", nil)
						}
						code, uwerr := common.UnwrapWorkflowError(wferr)
						logger.Error().Err(uwerr).Msg("failed to synchronously execute Temporal workflow to update Operating System")
						return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to update Operating System on Site: %s", uwerr), nil)
					}
					logger.Info().Str("Workflow ID", wid).Str("Site ID", dbossa.SiteID.String()).Msg("completed synchronous update Operating System workflow")
					return nil
				}()
				if iterErr != nil {
					return iterErr
				}
			}

			// Re-read the site associations so the response reflects the
			// status/version writes we just made (the dbossas slice loaded
			// pre-tx is now stale).
			refreshedOssas, _, derr := ossaDAO.GetAll(
				ctx,
				tx,
				cdbm.OperatingSystemSiteAssociationFilterInput{
					OperatingSystemIDs: []uuid.UUID{uos.ID},
				},
				cdbp.PageInput{
					Limit: cutil.GetPtr(cdbp.TotalLimit),
				},
				[]string{cdbm.SiteRelationName},
			)
			if derr != nil {
				logger.Error().Err(derr).Msg("error refreshing Operating System Site associations from DB")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve updated Operating System Site associations from DB", nil)
			}
			dbossas = refreshedOssas
		}

		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to update Operating System due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// Send response
	apiOperatingSystem := model.NewAPIOperatingSystem(uos, ssds, dbossas, sttsmap)
	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiOperatingSystem)
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteOperatingSystemHandler is the API Handler for deleting a OperatingSystem
type DeleteOperatingSystemHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewDeleteOperatingSystemHandler initializes and returns a new handler for deleting OperatingSystem
func NewDeleteOperatingSystemHandler(dbSession *cdb.Session, tc temporalClient.Client, scp *sc.ClientPool, cfg *config.Config) DeleteOperatingSystemHandler {
	return DeleteOperatingSystemHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete an existing OperatingSystem
// @Description Delete an existing OperatingSystem
// @Tags OperatingSystem
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of OperatingSystem"
// @Success 202
// @Router /v2/org/{org}/nico/operating-system/{id} [delete]
func (dsh DeleteOperatingSystemHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("OperatingSystem", "Delete", c, dsh.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to delete OperatingSystem
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get operating system ID from URL param
	osStrID := c.Param("id")

	dsh.tracerSpan.SetAttribute(handlerSpan, attribute.String("operatingsystem_id", osStrID), logger)

	osID, err := uuid.Parse(osStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Operating System ID in URL", nil)
	}

	// Validate the tenant for which this OperatingSystem is being updated
	tenant, err := common.GetTenantForOrg(ctx, nil, dsh.dbSession, org)
	if err != nil {
		if err == common.ErrOrgTenantNotFound {
			logger.Warn().Err(err).Msg("Org does not have a Tenant associated")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Org does not have a Tenant associated", nil)
		}
		logger.Error().Err(err).Msg("unable to retrieve tenant for org")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
	}

	// Check that operating system exists
	osDAO := cdbm.NewOperatingSystemDAO(dsh.dbSession)
	os, err := osDAO.GetByID(ctx, nil, osID, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Operating System DB entity")
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve Operating System to delete", nil)
		}
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve Operating System to delete", nil)
	}

	// verify tenant matches
	if os.TenantID == nil || tenant.ID != *os.TenantID {
		logger.Warn().Msg("tenant in os does not belong to tenant in org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant for Operating System in request does not match tenant in org", nil)
	}

	// Verify if tenant associated with Site in case of Image based OS
	// Verify Tenant Site Association
	// Verify if Site is in Registered state
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dsh.dbSession)
	ossasToDelete := []cdbm.OperatingSystemSiteAssociation{}
	if os.Type == cdbm.OperatingSystemTypeImage {
		ossasToDelete, _, err = ossaDAO.GetAll(
			ctx,
			nil,
			cdbm.OperatingSystemSiteAssociationFilterInput{
				OperatingSystemIDs: []uuid.UUID{os.ID},
			},
			cdbp.PageInput{},
			[]string{cdbm.SiteRelationName},
		)
		if err != nil {
			logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
		}

		// Verify if associated Site is not registered state
		for _, dbosa := range ossasToDelete {
			if dbosa.Site.Status != cdbm.SiteStatusRegistered {
				logger.Warn().Msg(fmt.Sprintf("unable to delete Operating System. Site: %s. is not in Registered state", dbosa.SiteID.String()))
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete Operating System, Associated Site: %s is not in Registered state", dbosa.Site.Name), nil)
			}
		}
	}

	// verify no instances are using the os
	isDAO := cdbm.NewInstanceDAO(dsh.dbSession)

	instances, _, err := isDAO.GetAll(ctx, nil, cdbm.InstanceFilterInput{TenantIDs: []uuid.UUID{tenant.ID}, OperatingSystemIDs: []uuid.UUID{os.ID}}, paginator.PageInput{}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Instances for Operating System from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Instances for deleting operatingsystem", nil)
	}

	if len(instances) > 0 {
		logger.Warn().Msg("Instances exist for Operating System, cannot delete it")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Operating System is being used by one or more Instances and cannot be deleted", nil)
	}

	// timeoutResp captures any post-rollback work (terminating timed-out
	// Temporal workflows) that must run after the transaction has been rolled
	// back. It is invoked after the closure if non-nil.
	var timeoutResp func() error

	err = cdb.WithTx(ctx, dsh.dbSession, func(tx *cdb.Tx) error {
		// acquire an advisory lock on the Operating System on which there could be contention
		// this lock is released when the transaction commits or rollsback
		derr := tx.TryAcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(os.ID.String()), nil)
		if derr != nil {
			logger.Error().Err(derr).Msg("Failed to acquire advisory lock on Operating System")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Operating System, could not acquire data store lock on Operating System", nil)
		}

		// Verify if OS is image based
		if os.Type == cdbm.OperatingSystemTypeImage {

			// Update Operating System to set status to Deleting
			_, derr := osDAO.Update(ctx, tx, cdbm.OperatingSystemUpdateInput{OperatingSystemId: os.ID, Status: cutil.GetPtr(cdbm.OperatingSystemStatusDeleting)})
			if derr != nil {
				logger.Error().Err(derr).Msg("error updating Operating System in DB")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Operating System", nil)
			}

			// Create status detail
			sdDAO := cdbm.NewStatusDetailDAO(dsh.dbSession)
			// create a status detail record for the Operating System
			_, derr = sdDAO.CreateFromParams(ctx, tx, os.ID.String(), cdbm.OperatingSystemStatusDeleting, cutil.GetPtr("received request for deletion, pending processing"))
			if derr != nil {
				logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
				return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for Operating System", nil)
			}

			// Update Status Deleting for Operating System Association
			for _, ossa := range ossasToDelete {
				if ossa.Status != cdbm.OperatingSystemSiteAssociationStatusDeleting {
					// Update Operating System Association to set status to Deleting
					_, derr := ossaDAO.Update(
						ctx,
						tx,
						cdbm.OperatingSystemSiteAssociationUpdateInput{
							OperatingSystemSiteAssociationID: ossa.ID,
							Status:                           cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusDeleting),
						},
					)
					if derr != nil {
						logger.Error().Err(derr).Msg("error updating Operating System Association in DB")
						return cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Operating Systems", nil)
					}

					// create a status detail record for the Operating System Association
					_, derr = sdDAO.CreateFromParams(ctx, tx, ossa.ID.String(), cdbm.OperatingSystemSiteAssociationStatusDeleting, cutil.GetPtr("received request for deletion, pending processing"))
					if derr != nil {
						logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
						return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for Operating System Association", nil)
					}

					// Get the temporal client for the site we are working with.
					stc, derr := dsh.scp.GetClientByID(ossa.SiteID)
					if derr != nil {
						logger.Error().Err(derr).Msg("failed to retrieve Temporal client for Site")
						return cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
					}

					// Prepare the delete/release request workflow object
					deleteOsRequest := os.ToDeletionRequestProto(tenant.Org)

					workflowOptions := temporalClient.StartWorkflowOptions{
						ID:                       "image-os-delete-" + ossa.SiteID.String() + "-" + os.ID.String() + "-" + *ossa.Version,
						WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
						TaskQueue:                queue.SiteTaskQueue,
					}

					logger.Info().Msg("triggering Operating System delete workflow")

					// Workflow execution wrapped in a function literal so `defer cancel()`
					// scopes to this iteration; otherwise the deferred cancels would pile
					// up until the WithTx closure returns.
					iterErr := func() *cutil.APIError {
						wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
						defer cancel()

						// Trigger Site workflow to delete Image based OperatingSystem
						we, wferr := stc.ExecuteWorkflow(wfCtx, workflowOptions, "DeleteOsImage", deleteOsRequest)
						if wferr != nil {
							logger.Error().Err(wferr).Msg("failed to synchronously start Temporal workflow to delete Operating System")
							return cutil.NewAPIError(http.StatusInternalServerError, fmt.Sprintf("Failed to start sync workflow to delete Operating System on Site: %s", wferr), nil)
						}

						wid := we.GetID()
						logger.Info().Str("Workflow ID", wid).Msg("executed synchronous delete Operating System workflow")

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

						// Check if err is still nil now that we've handled any skippable errors.
						if wferr != nil {
							var timeoutErr *tp.TimeoutError
							if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
								logger.Error().Err(wferr).Msg("failed to delete Operating System, timeout occurred executing workflow on Site.")
								timeoutResp = func() error {
									return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, wferr, "OperatingSystem", "Delete")
								}
								return cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Operating System, timeout occurred executing workflow on Site", nil)
							}

							code, uwerr := common.UnwrapWorkflowError(wferr)
							logger.Error().Err(uwerr).Msg("failed to synchronously execute Temporal workflow to delete Operating System")
							return cutil.NewAPIError(code, fmt.Sprintf("Failed to execute sync workflow to delete Operating System on Site: %s", uwerr), nil)
						}

						logger.Info().Str("Workflow ID", wid).Msg("completed synchronous delete Operating System workflow")
						return nil
					}()
					if iterErr != nil {
						return iterErr
					}
				}
			}
		}

		// Delete OS if its not Image
		// Delete OS if there is no Operating Site Association in case of Image based OS
		if os.Type == cdbm.OperatingSystemTypeIPXE || len(ossasToDelete) == 0 {
			derr := osDAO.Delete(ctx, tx, os.ID)
			if derr != nil {
				logger.Error().Err(derr).Msg("error deleting Operating System record in DB")
				return cutil.NewAPIError(http.StatusInternalServerError, "Error deleting Operating System record in DB", nil)
			}
		}

		return nil
	})
	// The wrapping `if err != nil` ensures real tx-helper errors (commit /
	// rollback failures that wrap into something other than the cutil.APIError
	// marker we returned for the timeout case) are surfaced via HandleTxError,
	// while the timeout-case APIError falls through to the timeoutResp call.
	if err != nil {
		var apiErr *cutil.APIError
		if !errors.As(err, &apiErr) || timeoutResp == nil {
			return common.HandleTxError(c, logger, err, "Failed to delete Operating System due to DB transaction error")
		}
	}
	if timeoutResp != nil {
		return timeoutResp()
	}

	// Create response
	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusAccepted, model.NewAPIDeletionAcceptedResponse())

}
