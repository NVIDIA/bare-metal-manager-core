// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

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
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
	osWorkflow "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/workflow/operatingsystem"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
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

	ip, tenant, apiError := common.IsProviderOrTenant(ctx, logger, csh.dbSession, org, dbUser, false, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	// Bind request data to API model before OS-type check so we can inspect the OS type.
	apiRequest := model.APIOperatingSystemCreateRequest{}
	err := c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	// Infer type of OS from provided parameters:
	osType := apiRequest.GetOperatingSystemType()

	// Image-based OS creation is not supported via this handler; Image OS
	// definitions originate from nico-core inventory synchronization.
	if osType == cdbm.OperatingSystemTypeImage {
		logger.Warn().Msg("attempted to create Image based Operating System via API")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Creation of Image based Operating Systems is no longer supported. Check your parameters and use ipxeScript or ipxeTemplateId.", nil)
	}

	// Provider Admin is limited to iPXE Template-based OSes. When both roles
	// allow the action, Provider Admin takes priority (provider-owned OS).
	allowedByProvider := ip != nil && osType == cdbm.OperatingSystemTypeTemplatedIPXE
	allowedByTenant := tenant != nil
	if !allowedByProvider && !allowedByTenant {
		logger.Warn().Msg("provider admin attempted to create non-template OS without tenant admin role")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Provider Admin can only create iPXE Template-based Operating Systems", nil)
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

	// If the caller provided an explicit tenantId in the body, validate it matches the org.
	// TODO: tenantId as parameter is deprecated and will need to be removed by 2026-10-01.
	if tenant != nil && apiRequest.TenantID != nil {
		apiTenant, terr := common.GetTenantFromIDString(ctx, nil, *apiRequest.TenantID, csh.dbSession)
		if terr != nil {
			logger.Warn().Err(terr).Msg("error retrieving tenant from request")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "TenantID in request is not valid", nil)
		}
		if apiTenant.ID != tenant.ID {
			logger.Warn().Msg("tenant id in request does not match tenant in org")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "TenantID in request does not match tenant in org", nil)
		}
	}

	// Check for name uniqueness within the owner's scope.
	osDAO := cdbm.NewOperatingSystemDAO(csh.dbSession)
	uniquenessFilter := cdbm.OperatingSystemFilterInput{Names: []string{apiRequest.Name}}
	if allowedByProvider {
		uniquenessFilter.InfrastructureProviderID = &ip.ID
	} else {
		uniquenessFilter.TenantIDs = []uuid.UUID{tenant.ID}
	}
	oss, tot, err := osDAO.GetAll(ctx, nil, uniquenessFilter, cdbp.PageInput{}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("db error checking for name uniqueness of os")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create OperatingSystem due to DB error", nil)
	}
	if tot > 0 {
		logger.Warn().Str("name", apiRequest.Name).Msg("Operating System with same name already exists")
		return cutil.NewAPIErrorResponse(c, http.StatusConflict, fmt.Sprintf("Operating System: %s with specified name already exists", oss[0].ID.String()), validation.Errors{
			"id": errors.New(oss[0].ID.String()),
		})
	}

	// Set the phoneHomeEnabled if provided in request
	phoneHomeEnabled := false
	if apiRequest.PhoneHomeEnabled != nil {
		phoneHomeEnabled = *apiRequest.PhoneHomeEnabled
	}

	// Start a db tx
	tx, err := cdb.BeginTx(ctx, csh.dbSession, &sql.TxOptions{})
	if err != nil {
		logger.Error().Err(err).Msg("unable to start transaction")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Operating System", nil)
	}

	// This variable is used in cleanup actions to indicate if this transaction committed
	txCommitted := false
	defer common.RollbackTx(ctx, tx, &txCommitted)

	// Determine the effective scope before site-association logic:
	//   - Raw iPXE:       always Global. validateRawIpxeOS accepts only nil
	//                     or "Global"; the handler then forces it to Global so
	//                     downstream logic can treat it uniformly.
	//   - Templated iPXE: scope is provided by the caller (Global or Limited).
	osScope := apiRequest.Scope
	if osType == cdbm.OperatingSystemTypeIPXE {
		osScope = cutil.GetPtr(cdbm.OperatingSystemScopeGlobal)
	}

	// Resolve target sites for the Operating System.
	// - Global scope:  auto-discover all registered sites for the owner (provider or tenant).
	// - Limited scope: use explicitly requested siteIds, validated for existence and ownership.
	// Note: scope "Local" is rejected at validation — Local OS are only created in nico-core.
	dbossd := []cdbm.StatusDetail{}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}

	isGlobal := osScope != nil && *osScope == cdbm.OperatingSystemScopeGlobal
	isLimited := osScope != nil && *osScope == cdbm.OperatingSystemScopeLimited

	stDAO := cdbm.NewSiteDAO(csh.dbSession)
	var targetSites []cdbm.Site
	siteFilter := cdbm.SiteFilterInput{}
	runSiteQuery := false

	if isLimited {
		// Limited-scope iPXE: resolve the explicitly requested site IDs.
		if ip == nil {
			ip, err = common.GetInfrastructureProviderForOrg(ctx, nil, csh.dbSession, org)
			if err != nil {
				logger.Error().Err(err).Msg("error retrieving Infrastructure Provider for org")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Infrastructure Provider for org", nil)
			}
		}

		requestedSiteIDs := make([]uuid.UUID, 0, len(apiRequest.SiteIDs))
		for _, stID := range apiRequest.SiteIDs {
			parsed, perr := uuid.Parse(stID)
			if perr != nil {
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to create Operating System, invalid Site ID: %s", stID), nil)
			}
			requestedSiteIDs = append(requestedSiteIDs, parsed)
		}
		siteFilter.SiteIDs = requestedSiteIDs
		runSiteQuery = len(requestedSiteIDs) > 0
	} else if isGlobal {
		// Global scope: auto-discover all registered sites for the owner.
		siteFilter.Statuses = []string{cdbm.SiteStatusRegistered}
		if allowedByProvider {
			siteFilter.InfrastructureProviderIDs = []uuid.UUID{ip.ID}
			runSiteQuery = true
		} else {
			// Tenant Global (raw iPXE): restrict to sites accessible to the tenant.
			tenantSiteIDs, tserr := getTenantSiteIDs(ctx, csh.dbSession, tenant.ID)
			if tserr != nil {
				logger.Error().Err(tserr).Msg("error retrieving tenant site IDs for global-scope raw iPXE OS")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant sites, DB error", nil)
			}
			if len(tenantSiteIDs) > 0 {
				siteFilter.SiteIDs = tenantSiteIDs
				runSiteQuery = true
			}
		}
	}

	if runSiteQuery {
		sites, _, sterr := stDAO.GetAll(
			ctx, nil,
			siteFilter,
			cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
			nil,
		)
		if sterr != nil {
			logger.Error().Err(sterr).Msg("error retrieving sites for Operating System")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve sites, DB error", nil)
		}
		targetSites = sites
	}

	// For Limited scope, ensure every requested site was found.
	if isLimited && len(targetSites) != len(apiRequest.SiteIDs) {
		found := make(map[uuid.UUID]struct{}, len(targetSites))
		for i := range targetSites {
			found[targetSites[i].ID] = struct{}{}
		}
		for _, stID := range apiRequest.SiteIDs {
			parsed, _ := uuid.Parse(stID)
			if _, ok := found[parsed]; !ok {
				return cutil.NewAPIErrorResponse(c, http.StatusNotFound, fmt.Sprintf("Failed to create Operating System, could not find Site with ID: %s ", stID), nil)
			}
		}
	}

	// Validate all target sites: must be in Registered state and, for Limited scope,
	// must belong to the caller's infrastructure provider (if set).
	for i := range targetSites {
		st := &targetSites[i]
		if st.Status != cdbm.SiteStatusRegistered {
			logger.Warn().Str("siteID", st.ID.String()).Msg("Unable to associate Operating System to Site: Site is not in Registered state")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to create Operating System, Site: %s is not in Registered state", st.ID.String()), nil)
		}
		if isLimited && ip != nil && st.InfrastructureProviderID != ip.ID {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Unable to associate Operating System with Site: %s, Site does not belong to provider", st.ID.String()), nil)
		}
	}

	// Create status: starts as Syncing since the definition is pushed to sites
	// asynchronously via the SynchronizeOperatingSystem workflow.
	osStatus := cdbm.OperatingSystemStatusSyncing
	osStatusMessage := "received Operating System creation request, syncing"

	// Assign ownership: provider-owned OSes carry InfrastructureProviderID (tenant_id=nil);
	// tenant-owned OSes carry TenantID (infrastructure_provider_id=nil).
	// This aligns with the sync model where OSes from nico-core are provider-owned.
	var ownerTenantID *uuid.UUID
	var ownerProviderID *uuid.UUID
	if allowedByProvider {
		ownerProviderID = &ip.ID
	} else {
		ownerTenantID = &tenant.ID
	}

	// Create the db record for Operating System
	osInput := cdbm.OperatingSystemCreateInput{
		Name:                     apiRequest.Name,
		Description:              apiRequest.Description,
		Org:                      org,
		TenantID:                 ownerTenantID,
		InfrastructureProviderID: ownerProviderID,
		OsType:                   osType,
		ImageURL:                 apiRequest.ImageURL,
		ImageSHA:                 apiRequest.ImageSHA,
		ImageAuthType:            apiRequest.ImageAuthType,
		ImageAuthToken:           apiRequest.ImageAuthToken,
		ImageDisk:                apiRequest.ImageDisk,
		RootFsId:                 apiRequest.RootFsID,
		RootFsLabel:              apiRequest.RootFsLabel,
		IpxeScript:               apiRequest.IpxeScript,
		IpxeTemplateId:           apiRequest.IpxeTemplateId,
		IpxeTemplateParameters:   apiRequest.IpxeTemplateParameters,
		IpxeTemplateArtifacts:    apiRequest.IpxeTemplateArtifacts,
		IpxeOsScope:              osScope,
		UserData:                 apiRequest.UserData,
		IsCloudInit:              apiRequest.IsCloudInit,
		AllowOverride:            apiRequest.AllowOverride,
		EnableBlockStorage:       apiRequest.EnableBlockStorage,
		PhoneHomeEnabled:         phoneHomeEnabled,
		Status:                   osStatus,
		CreatedBy:                dbUser.ID,
	}
	os, err := osDAO.Create(ctx, tx, osInput)
	if err != nil {
		logger.Error().Err(err).Msg("unable to create Operating System record in DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed creating Operating System record", nil)
	}

	// Create the status detail record for Operating System
	sdDAO := cdbm.NewStatusDetailDAO(csh.dbSession)
	ossd, serr := sdDAO.CreateFromParams(ctx, tx, os.ID.String(), *cutil.GetPtr(osStatus),
		cutil.GetPtr(osStatusMessage))
	if serr != nil {
		logger.Error().Err(serr).Msg("error creating Status Detail DB entry")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Status Detail for Operating System", nil)
	}

	if ossd == nil {
		logger.Error().Msg("Status Detail DB entry not returned from CreateFromParams")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to get new Status Detail for Operating System", nil)
	}
	dbossd = append(dbossd, *ossd)

	// Create Operating System Site Associations
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(csh.dbSession)
	for _, st := range targetSites {
		// Create Operating System Site Association
		ossa, serr := ossaDAO.Create(
			ctx,
			tx,
			cdbm.OperatingSystemSiteAssociationCreateInput{
				OperatingSystemID: os.ID,
				SiteID:            st.ID,
				Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
				CreatedBy:         dbUser.ID,
			},
		)
		if serr != nil {
			logger.Error().Err(serr).Msg("unable to create the Operating System association record in DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to associate Operating System with one or more Sites, DB error", nil)
		}

		// Create Status details
		_, serr = sdDAO.CreateFromParams(ctx, tx, ossa.ID.String(), *cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusSyncing),
			cutil.GetPtr("received Operating System Association create request, syncing"))
		if serr != nil {
			logger.Error().Err(serr).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Status Detail for Operating System Association", nil)
		}

		// Update Operating System Site Association version
		_, err := ossaDAO.GenerateAndUpdateVersion(ctx, tx, ossa.ID)
		if err != nil {
			logger.Error().Err(err).Msg("error updating version for created Operating System Association")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to set version for created Operating System Association, DB error", nil)
		}
	}

	// Retrieve Operating System Associations details
	dbossa, _, err := ossaDAO.GetAll(
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
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
	}

	targetSiteIDs := make([]uuid.UUID, len(targetSites))
	for i, site := range targetSites {
		targetSiteIDs[i] = site.ID
	}

	// Trigger async workflow before committing so a failure to enqueue rolls back the transaction.
	// Note: first run WILL fail since data is not committed so we rely on retry. We choose that initial inocuous failure vs failing to queue silently.
	if cdbm.IsIPXEType(osType) && len(dbossa) > 0 {
		wid, werr := osWorkflow.ExecuteCreateOrUpdateOperatingSystemByIDWorkflow(ctx, csh.tc, targetSiteIDs, os.ID)
		if werr != nil {
			logger.Error().Err(werr).Msg("failed to trigger SynchronizeOperatingSystem workflow for create")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to trigger Operating System synchronization workflow", nil)
		}
		logger.Info().Str("Workflow ID", *wid).Interface("Site IDs", targetSiteIDs).Msg("triggered async CreateOrUpdateOperatingSystemByID workflow for create")
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		logger.Error().Err(err).Msg("error committing Operating System transaction to DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Operating System", nil)
	}
	txCommitted = true

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

	ip, tenant, apiError := common.IsProviderOrTenant(ctx, logger, gash.dbSession, org, dbUser, false, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	// Validate pagination request
	pageRequest := pagination.PageRequest{}
	err := c.Bind(&pageRequest)
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

	// Visibility rules:
	//   Provider admin: sees only provider-created entries (no tenant entries).
	//   Tenant admin:   sees own entries + provider entries at tenant-accessible sites.
	//   Dual-role:      visibility is the union of both (own tenant + own provider).
	filter := cdbm.OperatingSystemFilterInput{}

	switch {
	case ip != nil && tenant == nil:
		// Provider admin only: sees only provider-created entries.
		filter.InfrastructureProviderID = &ip.ID
	case tenant != nil && ip == nil:
		// Tenant admin only: own entries + provider entries at tenant-accessible sites.
		filter.TenantIDs = []uuid.UUID{tenant.ID}
		if providerIP, iperr := common.GetInfrastructureProviderForOrg(ctx, nil, gash.dbSession, org); iperr == nil {
			filter.InfrastructureProviderID = &providerIP.ID
			tenantSiteIDs, tsErr := getTenantSiteIDs(ctx, gash.dbSession, tenant.ID)
			if tsErr != nil {
				logger.Error().Err(tsErr).Msg("error retrieving tenant site IDs for visibility filter")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to determine site access for tenant", nil)
			}
			filter.ProviderOSVisibleAtSiteIDs = &tenantSiteIDs
		}
	case tenant != nil && ip != nil:
		// Dual-role: own tenant + own provider entries, no site restriction.
		filter.TenantIDs = []uuid.UUID{tenant.ID}
		filter.InfrastructureProviderID = &ip.ID
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

			// Determine if caller has access to the requested site.
			// Tenant path: TenantSite association exists.
			// Provider path: site belongs to the caller's infrastructure provider.
			tenantHasAccess := false
			if tenant != nil {
				_, tsErr := tsDAO.GetByTenantIDAndSiteID(ctx, nil, tenant.ID, site.ID, nil)
				if tsErr == nil {
					tenantHasAccess = true
				} else if tsErr != cdb.ErrDoesNotExist {
					logger.Warn().Err(tsErr).Msg("error retrieving Tenant Site association from DB")
					return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to determine if Tenant has access to Site specified in query, DB error", nil)
				}
			}
			providerHasAccess := ip != nil && site.InfrastructureProviderID == ip.ID
			if !tenantHasAccess && !providerHasAccess {
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Caller is not associated with Site specified in query", nil)
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
	searchQueryStr := c.QueryParam("query")
	if searchQueryStr != "" {
		filter.SearchQuery = &searchQueryStr
		gash.tracerSpan.SetAttribute(handlerSpan, attribute.String("query", searchQueryStr), logger)
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
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Invalid Status value in query: %s", status), statusError)
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

	// Get all TenantSite records for the Tenant (only relevant when the caller
	// is acting as a Tenant; provider-only admins have no tenant-site context).
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}

	if tenant != nil {
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
	}

	// Create response
	apiOperatingSystems := []*model.APIOperatingSystem{}

	for _, os := range oss {
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

	ip, tenant, apiError := common.IsProviderOrTenant(ctx, logger, gsh.dbSession, org, dbUser, false, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
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

	// Check that operating system exists
	os, err := osDAO.GetByID(ctx, nil, sID, qIncludeRelations)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving OperatingSystem DB entity")
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve OperatingSystem to update", nil)
		}
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve OperatingSystem to update", nil)
	}

	// Visibility check with role-based rules:
	//   Provider admin: can only see provider-owned entries.
	//   Tenant admin:   can see own entries + provider entries at accessible sites.
	//   Dual-role:      can see both tenant and provider entries.
	ownedByTenant := tenant != nil && os.TenantID != nil && *os.TenantID == tenant.ID
	ownedByProvider := ip != nil && os.InfrastructureProviderID != nil && *os.InfrastructureProviderID == ip.ID

	// A tenant-only caller may also view provider-owned OSes belonging to the org's
	// provider (subject to site-scoped visibility checked below). Lazy-fetch the
	// org's provider to evaluate that case.
	if !ownedByProvider && ip == nil && os.InfrastructureProviderID != nil {
		if providerIP, iperr := common.GetInfrastructureProviderForOrg(ctx, nil, gsh.dbSession, org); iperr == nil {
			ownedByProvider = *os.InfrastructureProviderID == providerIP.ID
		}
	}

	if !ownedByTenant && !ownedByProvider {
		logger.Warn().Msg("operating system does not belong to the tenant or provider in org")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Operating System does not belong to the tenant or infrastructure provider in org", nil)
	}

	// If caller has dual role (Tenant+Provider) we already know we can go forward.
	// Otherwise we need additional checks:
	if !(tenant != nil && ip != nil) {
		if ip != nil && !ownedByProvider {
			logger.Warn().Msg("provider admin cannot view tenant-owned operating system")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Operating System does not belong to the infrastructure provider in org", nil)
		}
		if tenant != nil && !ownedByTenant && ownedByProvider {
			// Tenant admin seeing a provider-owned entry: verify site-scoped visibility.
			ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(gsh.dbSession)
			ossas, _, ossaErr := ossaDAO.GetAll(ctx, nil,
				cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
				cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
				nil,
			)
			if ossaErr != nil {
				logger.Error().Err(ossaErr).Msg("error retrieving OS site associations for visibility check")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to verify site access for Operating System", nil)
			}

			tenantSiteIDs, tsErr := getTenantSiteIDs(ctx, gsh.dbSession, tenant.ID)
			if tsErr != nil {
				logger.Error().Err(tsErr).Msg("error retrieving tenant site IDs for visibility check")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to determine site access for tenant", nil)
			}
			tsSet := make(map[uuid.UUID]struct{}, len(tenantSiteIDs))
			for _, sid := range tenantSiteIDs {
				tsSet[sid] = struct{}{}
			}
			visible := false
			for _, ossa := range ossas {
				if _, ok := tsSet[ossa.SiteID]; ok {
					visible = true
					break
				}
			}
			if !visible {
				logger.Warn().Msg("provider-owned OS has no site associations at sites accessible to the tenant")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Operating System is not associated with any site accessible to the caller", nil)
			}
		}
	}

	// get status details for the response
	sdDAO := cdbm.NewStatusDetailDAO(gsh.dbSession)
	ssds, err := sdDAO.GetRecentByEntityIDs(ctx, nil, []string{os.ID.String()}, common.RECENT_STATUS_DETAIL_COUNT)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Status Details for operating system from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for OperatingSystem", nil)
	}

	// Get all OperatingSystemSiteAssociations (both iPXE and Image types may have them).
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(gsh.dbSession)
	dbossas, _, err := ossaDAO.GetAll(
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

	// Get all TenantSite records for the Tenant (only relevant when the caller
	// is acting as a Tenant; provider-only admins have no tenant-site context).
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}
	if tenant != nil {
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

	ip, tenant, apiError := common.IsProviderOrTenant(ctx, logger, ush.dbSession, org, dbUser, false, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
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

	// Image-based OS updates are not supported via this handler; Image OS
	// definitions are managed through nico-core inventory synchronization.
	if os.Type == cdbm.OperatingSystemTypeImage {
		logger.Warn().Msg("attempted to update Image based Operating System via API")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Updating Image based Operating Systems is not supported", nil)
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

	// Enforce ownership: both roles are evaluated independently so a dual-role
	// caller is permitted if either role authorizes the operation.
	ownedByTenant := tenant != nil && os.TenantID != nil && *os.TenantID == tenant.ID && os.InfrastructureProviderID == nil
	ownedByProvider := false
	if ip != nil && os.InfrastructureProviderID != nil {
		if *os.InfrastructureProviderID != ip.ID {
			logger.Warn().Msg("provider admin cannot update operating system owned by a different provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Provider Admin can only update Operating Systems owned by their own provider", nil)
		}
		ownedByProvider = true
	}
	if !ownedByProvider && !ownedByTenant {
		if ip != nil && tenant == nil {
			logger.Warn().Msg("provider admin cannot update tenant-owned operating system")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Provider Admin can only update provider-owned Operating Systems", nil)
		}
		if tenant != nil && ip == nil {
			logger.Warn().Msg("tenant admin cannot update provider-owned operating system")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant Admin can only update their own Operating Systems", nil)
		}
		logger.Warn().Msg("user does not have permission to update this operating system")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Operating System does not belong to your tenant or infrastructure provider", nil)
	}

	// Check for name uniqueness within the owner's scope (provider or tenant).
	if apiRequest.Name != nil && *apiRequest.Name != os.Name {
		uniquenessFilter := cdbm.OperatingSystemFilterInput{Names: []string{*apiRequest.Name}}
		if os.InfrastructureProviderID != nil {
			uniquenessFilter.InfrastructureProviderID = os.InfrastructureProviderID
		} else {
			uniquenessFilter.TenantIDs = []uuid.UUID{tenant.ID}
		}
		oss, tot, serr := osDAO.GetAll(
			ctx,
			nil,
			uniquenessFilter,
			cdbp.PageInput{},
			nil,
		)
		if serr != nil {
			logger.Error().Err(serr).Msg("db error checking for name uniqueness of os")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update OperatingSystem due to DB error", nil)
		}
		if tot > 0 {
			return cutil.NewAPIErrorResponse(c, http.StatusConflict, fmt.Sprintf("Operating System: %s with specified name already exists", oss[0].ID.String()), validation.Errors{
				"id": errors.New(oss[0].ID.String()),
			})
		}
	}

	dbossas := []cdbm.OperatingSystemSiteAssociation{}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{}
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(ush.dbSession)

	// start a database transaction
	tx, err := cdb.BeginTx(ctx, ush.dbSession, &sql.TxOptions{})
	if err != nil {
		logger.Error().Err(err).Msg("error updating os in DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update Operating System", nil)
	}
	txCommitted := false
	defer common.RollbackTx(ctx, tx, &txCommitted)

	// Save update status in DB.
	// Status goes to Syncing since updates are pushed asynchronously.
	osStatus := cutil.GetPtr(cdbm.OperatingSystemStatusSyncing)
	osStatusMessage := "received Operating System update request, syncing"
	if apiRequest.IsActive != nil && !*apiRequest.IsActive {
		osStatus = cutil.GetPtr(cdbm.OperatingSystemStatusDeactivated)
		osStatusMessage = "Operating System has been deactivated"
		if apiRequest.DeactivationNote != nil && *apiRequest.DeactivationNote != "" {
			osStatusMessage += ". " + *apiRequest.DeactivationNote
		}
	} else if apiRequest.IsActive != nil && *apiRequest.IsActive {
		osStatusMessage = "Operating System has been reactivated, syncing"
	}

	// When switching from inactive to active, clear deactivation note
	deactivationNote := apiRequest.DeactivationNote
	if apiRequest.IsActive != nil && *apiRequest.IsActive {
		deactivationNote = nil
		_, err := osDAO.Clear(ctx, tx, cdbm.OperatingSystemClearInput{OperatingSystemId: osID, DeactivationNote: true})
		if err != nil {
			logger.Error().Err(err).Msg("error updating/clearing Operating System in DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update/clear Operating System", nil)
		}
	}
	uos, err := osDAO.Update(ctx, tx, cdbm.OperatingSystemUpdateInput{
		OperatingSystemId:      osID,
		Name:                   apiRequest.Name,
		Description:            apiRequest.Description,
		ImageURL:               apiRequest.ImageURL,
		ImageSHA:               apiRequest.ImageSHA,
		ImageAuthType:          apiRequest.ImageAuthType,
		ImageAuthToken:         apiRequest.ImageAuthToken,
		ImageDisk:              apiRequest.ImageDisk,
		RootFsId:               apiRequest.RootFsID,
		RootFsLabel:            apiRequest.RootFsLabel,
		IpxeScript:             apiRequest.IpxeScript,
		IpxeTemplateId:         apiRequest.IpxeTemplateId,
		IpxeTemplateParameters: apiRequest.IpxeTemplateParameters,
		IpxeTemplateArtifacts:  apiRequest.IpxeTemplateArtifacts,
		UserData:               apiRequest.UserData,
		IsCloudInit:            apiRequest.IsCloudInit,
		AllowOverride:          apiRequest.AllowOverride,
		PhoneHomeEnabled:       apiRequest.PhoneHomeEnabled,
		IsActive:               apiRequest.IsActive,
		DeactivationNote:       deactivationNote,
		Status:                 osStatus,
	})
	if err != nil {
		logger.Error().Err(err).Msg("error updating Operating System in DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update Operating System", nil)
	}
	logger.Info().Msg("done updating os in DB")

	sdDAO := cdbm.NewStatusDetailDAO(ush.dbSession)
	_, serr := sdDAO.CreateFromParams(ctx, tx, uos.ID.String(), *osStatus, &osStatusMessage)
	if serr != nil {
		logger.Error().Err(serr).Msg("error creating Status Detail DB entry")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create status detail for Operating System update", nil)
	}

	// get status details for the response
	ssds, _, err := sdDAO.GetAllByEntityID(ctx, tx, uos.ID.String(), nil, cutil.GetPtr(pagination.MaxPageSize), nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Status Details for os from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for Operating System", nil)
	}

	// Load existing site associations for the response and trigger async sync workflow.
	dbossas, _, err = ossaDAO.GetAll(ctx, tx,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{uos.ID}},
		cdbp.PageInput{}, []string{cdbm.SiteRelationName})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Operating System Site associations from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Operating System Site associations from DB", nil)
	}

	if len(dbossas) > 0 && cdbm.IsIPXEType(os.Type) {
		targetSiteIDs := make([]uuid.UUID, len(dbossas))
		for i, dbossa := range dbossas {
			targetSiteIDs[i] = dbossa.SiteID
		}

		// Trigger async workflow before committing so a failure to enqueue rolls back the transaction.
		wid, werr := osWorkflow.ExecuteCreateOrUpdateOperatingSystemByIDWorkflow(ctx, ush.tc, targetSiteIDs, uos.ID)
		if werr != nil {
			logger.Error().Err(werr).Interface("Site IDs", targetSiteIDs).Msg("failed to trigger CreateOrUpdateOperatingSystemByID workflow for update")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to trigger Oprating System update on Sites", nil)
		}
		logger.Info().Str("Workflow ID", *wid).Interface("Site IDs", targetSiteIDs).Msg("triggered async CreateOrUpdateOperatingSystemByID workflow for update on Sites")
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		logger.Error().Err(err).Msg("error updating OperatingSystem in DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update OperatingSystem", nil)
	}
	txCommitted = true

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

	ip, tenant, apiError := common.IsProviderOrTenant(ctx, logger, dsh.dbSession, org, dbUser, false, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	// Get operating system ID from URL param
	osStrID := c.Param("id")

	dsh.tracerSpan.SetAttribute(handlerSpan, attribute.String("operatingsystem_id", osStrID), logger)

	osID, err := uuid.Parse(osStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Operating System ID in URL", nil)
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

	// Enforce ownership: both roles are evaluated independently so a dual-role
	// caller is permitted if either role authorizes the operation.
	ownedByTenantD := tenant != nil && os.TenantID != nil && *os.TenantID == tenant.ID && os.InfrastructureProviderID == nil
	ownedByProviderD := false
	if ip != nil && os.InfrastructureProviderID != nil {
		if *os.InfrastructureProviderID != ip.ID {
			logger.Warn().Msg("provider admin cannot delete operating system owned by a different provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Provider Admin can only delete Operating Systems owned by their own provider", nil)
		}
		ownedByProviderD = true
	}
	if !ownedByProviderD && !ownedByTenantD {
		if ip != nil && tenant == nil {
			logger.Warn().Msg("provider admin cannot delete tenant-owned operating system")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Provider Admin can only delete provider-owned Operating Systems", nil)
		}
		if tenant != nil && ip == nil {
			logger.Warn().Msg("tenant admin cannot delete provider-owned operating system")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant Admin can only delete their own Operating Systems", nil)
		}
		logger.Warn().Msg("user does not have permission to delete this operating system")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Operating System does not belong to your tenant or infrastructure provider", nil)
	}

	// Retrieve site associations for this Operating System (both iPXE and Image types
	// may have associations that need per-site workflow propagation on delete).
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(dsh.dbSession)
	ossasToDelete, _, err := ossaDAO.GetAll(
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

	// For image-based OS, verify all associated sites are in Registered state
	// TODO: Do we not want this for iPXE-based OSes?
	if os.Type == cdbm.OperatingSystemTypeImage {
		for _, dbosa := range ossasToDelete {
			if dbosa.Site.Status != cdbm.SiteStatusRegistered {
				logger.Warn().Msg(fmt.Sprintf("unable to delete Operating System. Site: %s. is not in Registered state", dbosa.SiteID.String()))
				return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, fmt.Sprintf("Failed to delete Operating System, Associated Site: %s is not in Registered state", dbosa.Site.Name), nil)
			}
		}
	}

	// verify no instances are using the os
	isDAO := cdbm.NewInstanceDAO(dsh.dbSession)

	instanceFilter := cdbm.InstanceFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}}
	if tenant != nil {
		instanceFilter.TenantIDs = []uuid.UUID{tenant.ID}
	}
	instances, _, err := isDAO.GetAll(ctx, nil, instanceFilter, paginator.PageInput{}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Instances for Operating System from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Instances for deleting operatingsystem", nil)
	}

	if len(instances) > 0 {
		logger.Warn().Msg("Instances exist for Operating System, cannot delete it")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Operating System is being used by one or more Instances and cannot be deleted", nil)
	}

	// Start a db tx
	tx, err := cdb.BeginTx(ctx, dsh.dbSession, &sql.TxOptions{})
	if err != nil {
		logger.Error().Err(err).Msg("unable to start transaction")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Error deleting Operating System", nil)
	}
	// this variable is used in cleanup actions to indicate if this transaction committed
	txCommitted := false
	defer common.RollbackTx(ctx, tx, &txCommitted)

	// acquire an advisory lock on the Operating System on which there could be contention
	// this lock is released when the transaction commits or rollsback
	err = tx.TryAcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(os.ID.String()), nil)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to acquire advisory lock on Operating System")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to delete Operating System, could not acquire data store lock on Operating System", nil)
	}

	// Propagate the delete to associated sites (iPXE via DeleteOperatingSystem, Image via DeleteOsImage).
	if len(ossasToDelete) > 0 {
		// Update Operating System to set status to Deleting
		_, err = osDAO.Update(ctx, tx, cdbm.OperatingSystemUpdateInput{OperatingSystemId: os.ID, Status: cutil.GetPtr(cdbm.OperatingSystemStatusDeleting)})
		if err != nil {
			logger.Error().Err(err).Msg("error updating Operating System in DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to delete Operating System", nil)
		}

		sdDAO := cdbm.NewStatusDetailDAO(dsh.dbSession)
		_, err = sdDAO.CreateFromParams(ctx, tx, os.ID.String(), cdbm.OperatingSystemStatusDeleting, cutil.GetPtr("received request for deletion, pending processing"))
		if err != nil {
			logger.Error().Err(err).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Status Detail for Operating System", nil)
		}

		for _, ossa := range ossasToDelete {
			if ossa.Status != cdbm.OperatingSystemSiteAssociationStatusDeleting {
				_, err = ossaDAO.Update(ctx, tx,
					cdbm.OperatingSystemSiteAssociationUpdateInput{
						OperatingSystemSiteAssociationID: ossa.ID,
						Status:                           cutil.GetPtr(cdbm.OperatingSystemSiteAssociationStatusDeleting),
					})
				if err != nil {
					logger.Error().Err(err).Msg("error updating Operating System Association in DB")
					return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to delete Operating Systems", nil)
				}

				_, err = sdDAO.CreateFromParams(ctx, tx, ossa.ID.String(), cdbm.OperatingSystemSiteAssociationStatusDeleting, cutil.GetPtr("received request for deletion, pending processing"))
				if err != nil {
					logger.Error().Err(err).Msg("error creating Status Detail DB entry")
					return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Status Detail for Operating System Association", nil)
				}
			}
		}
	}

	// Soft-delete the OS if it has no site associations (legacy iPXE, or image-based with
	// associations already cleaned up by the workflows above).
	if len(ossasToDelete) == 0 {
		err = osDAO.Delete(ctx, tx, os.ID)
		if err != nil {
			logger.Error().Msg("error deleting Operating System record in DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Error deleting Operating System record in DB", nil)
		}
	}

	// Trigger async workflow before committing so a failure to enqueue rolls back the transaction.
	if len(ossasToDelete) > 0 && cdbm.IsIPXEType(os.Type) {
		targetSiteIDs := make([]uuid.UUID, len(ossasToDelete))
		for i, ossa := range ossasToDelete {
			targetSiteIDs[i] = ossa.SiteID
		}
		wid, werr := osWorkflow.ExecuteDeleteOperatingSystemByIDWorkflow(ctx, dsh.tc, targetSiteIDs, os.ID)
		if werr != nil {
			logger.Error().Err(werr).Interface("Site IDs", targetSiteIDs).Msg("failed to trigger DeleteOperatingSystemByID workflow for delete")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to trigger Operating System deletion on Sites", nil)
		}
		logger.Info().Str("Workflow ID", *wid).Interface("Site IDs", targetSiteIDs).Msg("triggered async DeleteOperatingSystemByID workflow for delete on Sites")
	}

	// Commit transaction.
	err = tx.Commit()
	if err != nil {
		logger.Error().Err(err).Msg("error committing Operating System transaction to DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to delete Operating System", nil)
	}
	txCommitted = true

	// Image-based OSes still use the synchronous per-site workflow pattern (post-commit).
	if len(ossasToDelete) > 0 && os.Type == cdbm.OperatingSystemTypeImage {
		for _, ossa := range ossasToDelete {
			if ossa.Status == cdbm.OperatingSystemSiteAssociationStatusDeleting {
				continue
			}
			stc, serr := dsh.scp.GetClientByID(ossa.SiteID)
			if serr != nil {
				logger.Error().Err(serr).Msg("failed to retrieve Temporal client for Site")
				continue
			}
			workflowOptions := temporalClient.StartWorkflowOptions{
				ID:        "image-os-delete-" + ossa.SiteID.String() + "-" + os.ID.String() + "-" + *ossa.Version,
				TaskQueue: queue.SiteTaskQueue,
			}
			deleteOsRequest := &cwssaws.DeleteOsImageRequest{
				Id:                   &cwssaws.UUID{Value: os.ID.String()},
				TenantOrganizationId: tenant.Org,
			}
			we, werr := stc.ExecuteWorkflow(ctx, workflowOptions, "DeleteOsImage", deleteOsRequest)
			if werr != nil {
				logger.Error().Err(werr).Msg("failed to start DeleteOsImage workflow")
				continue
			}
			werr = we.Get(ctx, nil)
			if werr != nil {
				var applicationErr *tp.ApplicationError
				if errors.As(werr, &applicationErr) && applicationErr.Type() == swe.ErrTypeCarbideObjectNotFound {
					werr = nil
				}
			}
			if werr != nil {
				var timeoutErr *tp.TimeoutError
				if errors.As(werr, &timeoutErr) {
					logger.Error().Err(werr).Msg("failed to delete Operating System, timeout occurred executing workflow on Site.")
					newctx := context.Background()
					serr := stc.TerminateWorkflow(newctx, we.GetID(), "", "timeout occurred executing delete Operating System workflow")
					if serr != nil {
						logger.Error().Err(serr).Msg("failed to execute terminate Temporal workflow for deleting Operating System")
						return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, fmt.Sprintf("Failed to terminate synchronous Operating System delete workflow after timeout, Cloud and Site data may be de-synced: %s", serr), nil)
					}
					logger.Info().Str("Workflow ID", we.GetID()).Msg("initiated terminate synchronous delete Operating System workflow successfully")
					return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, fmt.Sprintf("Failed to delete Operating System, timeout occurred executing workflow on Site: %s", werr), nil)
				}
				logger.Error().Err(werr).Str("Workflow ID", we.GetID()).Msg("DeleteOsImage workflow failed")
			}
		}
	}

	// Create response
	logger.Info().Msg("finishing API handler")
	return c.String(http.StatusAccepted, "Deletion request was accepted")

}

// getTenantSiteIDs returns the IDs of all sites the given tenant has access to.
func getTenantSiteIDs(ctx context.Context, dbSession *db.Session, tenantID uuid.UUID) ([]uuid.UUID, error) {
	tsDAO := cdbm.NewTenantSiteDAO(dbSession)
	tss, _, err := tsDAO.GetAll(ctx, nil,
		cdbm.TenantSiteFilterInput{TenantIDs: []uuid.UUID{tenantID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)},
		nil,
	)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(tss))
	for i, ts := range tss {
		ids[i] = ts.SiteID
	}
	return ids, nil
}
