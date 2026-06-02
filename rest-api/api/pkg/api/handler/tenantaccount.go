// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/json"
	"fmt"
	"net/http"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/labstack/echo/v4"

	"go.opentelemetry.io/otel/attribute"
	temporalClient "go.temporal.io/sdk/client"

	"github.com/google/uuid"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	common "github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/pagination"
	auth "github.com/NVIDIA/infra-controller-rest/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
)

// ~~~~~ Create Handler ~~~~~ //

// CreateTenantAccountHandler is the API Handler for creating new TenantAccount
type CreateTenantAccountHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateTenantAccountHandler initializes and returns a new handler for creating TenantAccount
func NewCreateTenantAccountHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) CreateTenantAccountHandler {
	return CreateTenantAccountHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Create a TenantAccount
// @Description Create a TenantAccount
// @Tags tenantaccount
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param message body model.APITenantAccountCreateRequest true "TenantAccount creation request"
// @Success 201 {object} model.APITenantAccount
// @Router /v2/org/{org}/nico/tenant/account [post]
func (ctah CreateTenantAccountHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("TenantAccount", "Create", c, ctah.tracerSpan)
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

	// Validate role, only Provider Admins are allowed to create TenantAccounts
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	// Validate request
	// Bind request data to API model
	apiRequest := model.APITenantAccountCreateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Tenant Account creation request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Tenant Account creation request data", verr)
	}

	// Check that infrastructureProvider for org matches request
	ip, err := common.GetInfrastructureProviderForOrg(ctx, nil, ctah.dbSession, org)
	if err != nil {
		logger.Warn().Err(err).Msg("error getting infrastructure provider for org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to retrieve Infrastructure Provider for current org", nil)
	}

	if ip.ID.String() != apiRequest.InfrastructureProviderID {
		logger.Warn().Err(err).Msg("infrastructure provider in request does not belong to org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Infrastructure ProviderId in request", nil)
	}

	// Validate the Tenant for which this TenantAccount is being created
	// Atmost 1 tenant account can be created per (Infrastructure Provider, Tenant)
	tnDAO := cdbm.NewTenantDAO(ctah.dbSession)
	taDAO := cdbm.NewTenantAccountDAO(ctah.dbSession)

	// Request data validation guarantees that either TenantID or TenantOrg is specified
	var tenantID *uuid.UUID
	var tenantOrg *string

	if apiRequest.TenantID != nil {
		id, serr := uuid.Parse(*apiRequest.TenantID)
		if serr != nil {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant ID specified in request", nil)
		}
		tenant, serr := tnDAO.GetByID(ctx, nil, id, nil)
		if serr != nil {
			logger.Warn().Err(serr).Msg("error retrieving tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to retrieve Tenant specified in request", nil)
		}
		tenantID = &tenant.ID
		tenantOrg = &tenant.Org
	} else {
		tenantOrg = apiRequest.TenantOrg
		tenants, serr := tnDAO.GetAllByOrg(ctx, nil, *tenantOrg, nil)
		if serr != nil {
			logger.Warn().Err(err).Msg("error retrieving tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to retrieve Tenant specified in request", nil)
		}

		if len(tenants) > 1 {
			logger.Warn().Err(err).Msg("multiple tenants found for org")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Multiple tenants found for org", nil)
		} else if len(tenants) > 0 {
			tenantID = &tenants[0].ID
		}
	}

	// NOTE: At this point tenantID may be nil, if the Tenant entity does not exist in the DB yet
	var tas []cdbm.TenantAccount
	var terr error
	tas, _, terr = taDAO.GetAll(ctx, nil, cdbm.TenantAccountFilterInput{
		InfrastructureProviderID: &ip.ID,
		TenantOrgs:               []string{*tenantOrg},
	}, cdbp.PageInput{}, nil)
	if terr != nil {
		logger.Error().Err(terr).Msg("error retrieving Tenant Accounts")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant Accounts", nil)
	}
	if len(tas) > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant Account between Infrastructure Provider and Tenant already exists", nil)
	}

	// Generate a unique account number
	accountNumber := common.GenerateAccountNumber()

	sdDAO := cdbm.NewStatusDetailDAO(ctah.dbSession)

	var ta *cdbm.TenantAccount
	var ssd *cdbm.StatusDetail

	err = cdb.WithTx(ctx, ctah.dbSession, func(tx *cdb.Tx) error {
		var derr error
		ta, derr = taDAO.Create(ctx, tx, cdbm.TenantAccountCreateInput{
			AccountNumber:             accountNumber,
			TenantID:                  tenantID,
			TenantOrg:                 *tenantOrg,
			InfrastructureProviderID:  ip.ID,
			InfrastructureProviderOrg: ip.Org,
			Status:                    cdbm.TenantAccountStatusInvited,
			CreatedBy:                 dbUser.ID,
		})
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating TenantAccount in DB")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create tenant account", nil)
		}

		// Create a status detail record for the tenantaccount
		ssd, derr = sdDAO.CreateFromParams(ctx, tx, ta.ID.String(), *cdb.GetStrPtr(cdbm.TenantAccountStatusInvited),
			cdb.GetStrPtr("received tenant account creation request, pending accept"))
		if derr != nil {
			logger.Error().Err(derr).Msg("error creating Status Detail DB entry")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Status Detail for TenantAccount", nil)
		}
		if ssd == nil {
			logger.Error().Msg("Status Detail DB entry not returned from CreateFromParams")
			return cutil.NewAPIError(http.StatusInternalServerError, "Failed to get new Status Detail for TenantAccount", nil)
		}

		return nil
	})
	if err != nil {
		return common.HandleTxError(c, logger, err, "Failed to create Tenant Account, DB transaction error")
	}

	// Create response
	apiInstance := model.NewAPITenantAccount(ta, []cdbm.StatusDetail{*ssd}, 0)

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusCreated, apiInstance)
}

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllTenantAccountHandler is the API Handler for getting all TenantAccounts
type GetAllTenantAccountHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllTenantAccountHandler initializes and returns a new handler for getting all TenantAccounts
func NewGetAllTenantAccountHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetAllTenantAccountHandler {
	return GetAllTenantAccountHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get all TenantAccounts
// @Description Get all TenantAccounts
// @Tags tenantaccount
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param infrastructureProviderId query string true "ID of InfrastructureProvider"
// @Param tenantId query string true "ID of Tenant"
// @Param status query string false "Query input for status"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Tenant'"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Param orderBy query string false "Order by field"
// @Success 200 {object} []model.APITenantAccount
// @Router /v2/org/{org}/nico/tenant/account [get]
func (gatah GetAllTenantAccountHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("TenantAccount", "GetAll", c, gatah.tracerSpan)
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

	// Validate paginantion request
	pageRequest := pagination.PageRequest{}
	err = c.Bind(&pageRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding pagination request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request pagination data", nil)
	}

	// Validate request attributes
	err = pageRequest.Validate(cdbm.TenantAccountOrderByFields)
	if err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	// Get and validate query params
	qInfrastructureProviderID := c.QueryParam("infrastructureProviderId")
	qTenantID := c.QueryParam("tenantId")
	if qInfrastructureProviderID == "" && qTenantID == "" {
		errStr := "Either infrastructureProviderId or tenantId query param must be specified."
		logger.Warn().Msg(errStr)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errStr, nil)
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errMsg := common.GetAndValidateQueryRelations(qParams, cdbm.TenantAccountRelatedEntities)
	if errMsg != "" {
		logger.Warn().Msg(errMsg)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errMsg, nil)
	}

	// Get status from query param
	var status *string

	statusQuery := c.QueryParam("status")
	if statusQuery != "" {
		gatah.tracerSpan.SetAttribute(handlerSpan, attribute.String("status", statusQuery), logger)
		_, sok := cdbm.TenantAccountStatusMap[statusQuery]
		if !sok {
			logger.Warn().Msg(fmt.Sprintf("invalid value in status query: %v", statusQuery))
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Status value in query", nil)
		}
		status = &statusQuery
	}

	searchQuery := common.GetSearchQuery(c)
	if searchQuery != nil {
		gatah.tracerSpan.SetAttribute(handlerSpan, attribute.String("query", *searchQuery), logger)
	}

	var infrastructureProviderID *uuid.UUID

	// Validate infrastructure provider id if provided
	if qInfrastructureProviderID != "" {
		id, serr := uuid.Parse(qInfrastructureProviderID)
		if serr != nil {
			logger.Warn().Err(serr).Msg("error parsing infrastructureProviderId in query into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Infrastructure Provider ID in query", nil)
		}

		infrastructureProviderID = &id
	}

	// Validate tenant id if provided
	var tenantID *uuid.UUID
	if qTenantID != "" {
		id, serr := uuid.Parse(qTenantID)
		if serr != nil {
			logger.Warn().Err(serr).Msg("error parsing tenantId in query into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant ID in query", nil)
		}

		tenantID = &id
	}

	// The query params must match _either_ the org's Infrastructure Provider _or_ the org's Tenant
	// This allows the cases where:
	// - A Tenant associated with the org could be filtering on Infrastructure Provider by providing both param
	// - An Infrastructure Provider associated with the org could be filtering on Tenant by providing both param
	isAssociated := false
	orgInfrastructureProvider, err := common.GetInfrastructureProviderForOrg(ctx, nil, gatah.dbSession, org)
	if err != nil {
		if err != common.ErrOrgInstrastructureProviderNotFound {
			logger.Error().Err(err).Msg("error getting infrastructure provider for org")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Infrastructure Provider for org, DB error", nil)
		}
	} else if infrastructureProviderID != nil && orgInfrastructureProvider.ID == *infrastructureProviderID {
		// Validate role, only Provider Admins are allowed to proceed from here
		ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole, auth.ProviderViewerRole)
		if !ok {
			logger.Warn().Msg("user does not have Provider Admin role with org, access denied")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
		}

		isAssociated = true
	}

	// If the Infrastructure Provider in query does not belong to the org, then check if the Tenant in query belongs to the org
	if !isAssociated {
		orgTenant, err1 := common.GetTenantForOrg(ctx, nil, gatah.dbSession, org)
		if err1 != nil {
			if err1 != common.ErrOrgTenantNotFound {
				logger.Error().Err(err1).Msg("error getting tenant for org")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve tenant for org", nil)
			}
		} else if tenantID != nil && orgTenant.ID == *tenantID {
			// Validate role, only Tenant Admins are allowed to proceed from here
			ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
			if !ok {
				logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
			}

			isAssociated = true
		}
	}

	if !isAssociated {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Either Infrastructure Provider or Tenant in query param must be associated with org", nil)
	}

	// Get Tenant Accounts
	taDAO := cdbm.NewTenantAccountDAO(gatah.dbSession)

	// default append `TenantContact`
	qIncludeRelations = append(qIncludeRelations, "TenantContact")

	var tenantIDs []uuid.UUID
	if tenantID != nil {
		tenantIDs = []uuid.UUID{*tenantID}
	}
	var statuses []string
	if status != nil {
		statuses = []string{*status}
	}

	filter := cdbm.TenantAccountFilterInput{
		InfrastructureProviderID: infrastructureProviderID,
		TenantIDs:                tenantIDs,
		Statuses:                 statuses,
		SearchQuery:              searchQuery,
	}

	tas, total, err := taDAO.GetAll(ctx, nil, filter, cdbp.PageInput{
		Offset:  pageRequest.Offset,
		Limit:   pageRequest.Limit,
		OrderBy: pageRequest.OrderBy,
	}, qIncludeRelations)
	if err != nil {
		logger.Error().Err(err).Msg("error getting TenantAccounts from db")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve TenantAccounts", nil)
	}

	// Get status details
	sdDAO := cdbm.NewStatusDetailDAO(gatah.dbSession)

	sdEntityIDs := []string{}
	for _, ta := range tas {
		sdEntityIDs = append(sdEntityIDs, ta.ID.String())
	}
	ssds, serr := sdDAO.GetRecentByEntityIDs(ctx, nil, sdEntityIDs, common.RECENT_STATUS_DETAIL_COUNT)
	if serr != nil {
		logger.Warn().Err(serr).Msg("error retrieving Status Details for Tenant Accounts from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to populate status history for Tenant Accounts", nil)
	}
	ssdMap := map[string][]cdbm.StatusDetail{}
	for _, ssd := range ssds {
		cssd := ssd
		ssdMap[ssd.EntityID] = append(ssdMap[ssd.EntityID], cssd)
	}

	// Create response
	apiTas := []*model.APITenantAccount{}
	aDAO := cdbm.NewAllocationDAO(gatah.dbSession)

	// Get Allocation count by InfrastructureProvider/Tenant
	var allocationCountByTenantIDMap map[uuid.UUID]int
	if len(tas) > 0 {
		allocationCountByTenantIDMap = make(map[uuid.UUID]int)
		allocationFilter := cdbm.AllocationFilterInput{InfrastructureProviderID: infrastructureProviderID}
		if tenantID != nil {
			allocationFilter.TenantIDs = append(allocationFilter.TenantIDs, *tenantID)
		}
		allocationPage := cdbp.PageInput{Limit: cdb.GetIntPtr(cdbp.TotalLimit)}
		als, _, serr := aDAO.GetAll(ctx, nil, allocationFilter, allocationPage, nil)
		if serr != nil {
			logger.Error().Err(serr).Msg("error retrieving allocation for Tenant from DB")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Allocations to determine total Allocation count for Tenants", nil)
		}

		for _, al := range als {
			allocationCountByTenantIDMap[al.TenantID]++
		}
	}

	for _, ta := range tas {
		tmpTa := ta
		// Check for Allocation for Tenant
		total := 0
		if tmpTa.TenantID != nil {
			total = allocationCountByTenantIDMap[*tmpTa.TenantID]
		}
		apiTa := model.NewAPITenantAccount(&tmpTa, ssdMap[ta.ID.String()], total)
		apiTas = append(apiTas, apiTa)
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

	return c.JSON(http.StatusOK, apiTas)
}

// ~~~~~ Get Current Handler ~~~~~ //

// GetTenantAccountHandler is the API Handler for retrieving TenantAccount
type GetTenantAccountHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetTenantAccountHandler initializes and returns a new handler to retrieve TenantAccount
func NewGetTenantAccountHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) GetTenantAccountHandler {
	return GetTenantAccountHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve the TenantAccount
// @Description Retrieve the TenantAccount
// @Tags tenantaccount
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Tenant Account"
// @Param infrastructureProviderId query string true "ID of InfrastructureProvider"
// @Param tenantId query string true "ID of Tenant"
// @Param includeRelation query string false "Related entities to include in response e.g. 'InfrastructureProvider', 'Tenant'"
// @Success 200 {object} model.APITenantAccount
// @Router /v2/org/{org}/nico/tenant/account/{id} [get]
func (gtah GetTenantAccountHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("TenantAccount", "Get", c, gtah.tracerSpan)
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

	// Get tenant account ID from URL param
	taStrID := c.Param("id")

	gtah.tracerSpan.SetAttribute(handlerSpan, attribute.String("tenantaccount_id", taStrID), logger)

	taID, err := uuid.Parse(taStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant Account ID in URL", nil)
	}

	// Get and validate includeRelation params
	qParams := c.QueryParams()
	qIncludeRelations, errStr := common.GetAndValidateQueryRelations(qParams, cdbm.TenantAccountRelatedEntities)
	if errStr != "" {
		logger.Warn().Msg(errStr)
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, errStr, nil)
	}

	// Check that TenantAccount exists
	taDAO := cdbm.NewTenantAccountDAO(gtah.dbSession)

	// default append `TenantContact`
	qIncludeRelations = append(qIncludeRelations, "TenantContact")

	ta, err := taDAO.GetByID(ctx, nil, taID, qIncludeRelations)
	if err != nil {
		logger.Warn().Err(err).Msg("error retrieving TenantAccount DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve Tenant Account to update", nil)
	}

	// Get and validate query params
	qInfrastructureProviderID := c.QueryParam("infrastructureProviderId")
	qTenantID := c.QueryParam("tenantId")

	if qInfrastructureProviderID == "" && qTenantID == "" {
		// Logging common user request data error can add a lot to system logs
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Either Infrastructure Provider ID or Tenant ID query param must be specified.", nil)
	}

	var infrastructureProviderID *uuid.UUID
	var tenantID *uuid.UUID

	// Validate infrastructure provider id if provided
	if qInfrastructureProviderID != "" {
		id, err1 := uuid.Parse(qInfrastructureProviderID)
		if err1 != nil {
			logger.Warn().Err(err1).Msg("error parsing infrastructureProviderId in query into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Infrastructure Provider ID in query", nil)
		}

		// If the Infrastructure Provider ID in query is not the same as the one in the Tenant Account, return an error
		if id != ta.InfrastructureProviderID {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Tenant Account matching Infrastructure Provider in query", nil)
		}

		infrastructureProviderID = &id
	}

	// Validate tenant id if provided
	if qTenantID != "" {
		id, err1 := uuid.Parse(qTenantID)
		if err1 != nil {
			logger.Warn().Err(err1).Msg("error parsing tenantId in query into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant ID in query", nil)
		}

		// If the Tenant in query is not the same as the one in the Tenant Account, return an error
		if ta.TenantID == nil || *ta.TenantID != id {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Tenant Account matching Tenant in query", nil)
		}

		tenantID = &id
	}

	// The query params must match _either_ the org's Infrastructure Provider _or_ the org's Tenant
	// This allows the cases where:
	// - A Tenant associated with the org could be filtering on Infrastructure Provider by providing both param
	// - An Infrastructure Provider associated with the org could be filtering on Tenant by providing both param
	isAssociated := false
	orgInfrastructureProvider, err := common.GetInfrastructureProviderForOrg(ctx, nil, gtah.dbSession, org)
	if err != nil {
		if err != common.ErrOrgInstrastructureProviderNotFound {
			logger.Error().Err(err).Msg("error getting infrastructure provider for org")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve infrastructure provider for org, DB error", nil)
		}
	} else if infrastructureProviderID != nil && orgInfrastructureProvider.ID == *infrastructureProviderID {
		// Validate role, only Provider Admins are allowed to proceed from here
		ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole, auth.ProviderViewerRole)
		if !ok {
			logger.Warn().Msg("user does not have Provider Admin role with org, access denied")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
		}

		isAssociated = true
	}

	// If the Infrastructure Provider in query does not belong to the org, then check if the Tenant in query belongs to the org
	if !isAssociated {
		orgTenant, err1 := common.GetTenantForOrg(ctx, nil, gtah.dbSession, org)
		if err1 != nil {
			if err1 != common.ErrOrgTenantNotFound {
				logger.Error().Err(err1).Msg("error getting tenant for org")
				return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Tenant for org", nil)
			}
		} else if tenantID != nil && orgTenant.ID == *tenantID {
			// Validate role, only Tenant Admins are allowed to proceed from here
			ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
			if !ok {
				logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
				return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
			}

			isAssociated = true
		}
	}

	if !isAssociated {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Either Infrastructure Provider or Tenant in query param must be associated with org", nil)
	}

	// Check for Allocation
	aDAO := cdbm.NewAllocationDAO(gtah.dbSession)
	allocationFilter := cdbm.AllocationFilterInput{InfrastructureProviderID: infrastructureProviderID}
	if tenantID != nil {
		allocationFilter.TenantIDs = append(allocationFilter.TenantIDs, *tenantID)
	}
	total, serr := aDAO.GetCount(ctx, nil, allocationFilter)
	if serr != nil {
		logger.Error().Err(serr).Msg("error retrieving allocation for Tenant from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Allocations to determine total allocation for tenant account", nil)
	}

	sdDAO := cdbm.NewStatusDetailDAO(gtah.dbSession)
	ssds, err := sdDAO.GetRecentByEntityIDs(ctx, nil, []string{ta.ID.String()}, common.RECENT_STATUS_DETAIL_COUNT)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Status Details for TenantAccount from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for TenantAccount", nil)
	}

	// Create response
	apiTenantAccount := model.NewAPITenantAccount(ta, ssds, total)

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusOK, apiTenantAccount)
}

// ~~~~~ Update Handler ~~~~~ //

// UpdateTenantAccountHandler is the API Handler for updating a TenantAccount
type UpdateTenantAccountHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewUpdateTenantAccountHandler initializes and returns a new handler for updating Tenant
func NewUpdateTenantAccountHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) UpdateTenantAccountHandler {
	return UpdateTenantAccountHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Update an existing TenantAccount
// @Description Update an existing TenantAccount
// @Tags tenantaccount
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Tenant Account"
// @Param message body model.APITenantAccountUpdateRequest true "TenantAccount update request"
// @Success 200 {object} model.APITenantAccount
// @Router /v2/org/{org}/nico/tenant/account/{id} [patch]
func (utah UpdateTenantAccountHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("TenantAccount", "Update", c, utah.tracerSpan)
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

	// Validate role, only Tenant Admins are allowed to update TenantAccount
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.TenantAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Tenant Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Tenant Admin role with org", nil)
	}

	// Get tenant account ID from URL param
	taStrID := c.Param("id")

	utah.tracerSpan.SetAttribute(handlerSpan, attribute.String("tenantaccount_id", taStrID), logger)

	taID, err := uuid.Parse(taStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant Account ID in URL", nil)
	}

	taDAO := cdbm.NewTenantAccountDAO(utah.dbSession)

	// Validate request
	// Bind request data to API model
	apiRequest := model.APITenantAccountUpdateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Tenant Account update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating Tenant Account update request data", verr)
	}

	// Check that TenantAccount exists
	ta, err := taDAO.GetByID(ctx, nil, taID, nil)
	if err != nil {
		logger.Warn().Err(err).Msg("error retrieving TenantAccount DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not retrieve TenantAccount to update", nil)
	}

	// Check that the org's tenant matches tenant in tenant-account
	tn, err := common.GetTenantForOrg(ctx, nil, utah.dbSession, org)
	if err != nil {
		logger.Warn().Err(err).Msg("tenant does not exist for org")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Org does not have tenant", nil)
	}

	// CHeck that Tenant in TenantAccount matches tenant in org
	if ta.TenantID == nil || *ta.TenantID != tn.ID {
		logger.Warn().Msg("tenant in tenant account does not match tenant in org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest,
			"Tenant in org does not match tenant in TenantAccount", nil)
	}

	// Check that the tenant contact id if exists, matches the requesting user
	if apiRequest.TenantContactID != nil {
		tnContactID, err1 := uuid.Parse(*apiRequest.TenantContactID)
		if err1 != nil {
			logger.Warn().Err(err1).Msg("error parsing tenantContactId in request into uuid")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant Contact ID in request", nil)
		}
		if tnContactID != dbUser.ID {
			logger.Warn().Msg("tenant contact id in request must be the requesting user")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant Contact ID in request must match requesting user", nil)
		}
	}

	// Check that the tenant account status is invited
	if ta.Status != cdbm.TenantAccountStatusInvited {
		logger.Warn().Msg("tenant account status is not Invited")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Tenant Account status is not Invited", nil)
	}

	// Update TenantAccount in DB
	// TODO start transaction
	ta, err = taDAO.Update(ctx, nil, cdbm.TenantAccountUpdateInput{
		TenantAccountID: taID,
		TenantContactID: cdb.GetUUIDPtr(dbUser.ID),
		Status:          cdb.GetStrPtr(cdbm.TenantAccountStatusReady),
	})
	if err != nil {
		logger.Error().Err(err).Msg("error updating TenantAccount in DB")
		// TODO rollback transaction
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to update Tenant", nil)
	}

	// create status detail record for the update
	sdDAO := cdbm.NewStatusDetailDAO(utah.dbSession)
	_, serr := sdDAO.CreateFromParams(ctx, nil, ta.ID.String(), *cdb.GetStrPtr(cdbm.TenantAccountStatusReady),
		cdb.GetStrPtr("received tenant account update request, ready"))
	if serr != nil {
		// TODO rollback transaction
		logger.Error().Err(serr).Msg("error updating Status Detail DB entry")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create Status Detail for TenantAccount", nil)
	}

	ssds, _, err := sdDAO.GetAllByEntityID(ctx, nil, ta.ID.String(), nil, cdb.GetIntPtr(pagination.MaxPageSize), nil)
	if err != nil {
		// TODO rollback transaction
		logger.Error().Err(err).Msg("error retrieving Status Details for TenantAccount from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Status Details for TenantAccount", nil)
	}
	// TODO commit transaction

	// Create response
	apiInstance := model.NewAPITenantAccount(ta, ssds, 0)

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusOK, apiInstance)
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteTenantAccountHandler is the API Handler for deleting a TenantAccount
type DeleteTenantAccountHandler struct {
	dbSession  *cdb.Session
	tc         temporalClient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewDeleteTenantAccountHandler initializes and returns a new handler for deleting Tenant
func NewDeleteTenantAccountHandler(dbSession *cdb.Session, tc temporalClient.Client, cfg *config.Config) DeleteTenantAccountHandler {
	return DeleteTenantAccountHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete an existing TenantAccount
// @Description Delete an existing TenantAccount
// @Tags tenantaccount
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Tenant Account"
// @Success 202
// @Router /v2/org/{org}/nico/tenant/account/{id} [delete]
func (dtah DeleteTenantAccountHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("TenantAccount", "Delete", c, dtah.tracerSpan)
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

	// Validate role, only Provider Admins are allowed to delete TenantAccounts
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role with org, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	// Get tenant account ID from URL param
	taStrID := c.Param("id")

	dtah.tracerSpan.SetAttribute(handlerSpan, attribute.String("tenantaccount_id", taStrID), logger)

	taID, err := uuid.Parse(taStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Tenant Account ID in URL", nil)
	}

	logger.Info().Str("tenantaccount", taStrID).Msg("deleting tenant account")

	// Check that TenantAccount exists
	taDAO := cdbm.NewTenantAccountDAO(dtah.dbSession)

	ta, err := taDAO.GetByID(ctx, nil, taID, nil)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find TenantAccount with specified ID", nil)
		}
		logger.Error().Str("tenantaccount", taID.String()).Err(err).Msg("error retrieving TenantAccount DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Could not retrieve TenantAccount", nil)
	}

	// Check that the org's infrastructureProvider matches infrastructureProvider in TenantAccount
	ip, err := common.GetInfrastructureProviderForOrg(ctx, nil, dtah.dbSession, org)
	if err != nil {
		logger.Warn().Err(err).Msg("error getting infrastructure provider for org")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error getting InfrastructureProvider for Org", nil)
	}
	if ip.ID != ta.InfrastructureProviderID {
		logger.Warn().Msg("infrastructureProvider in org does not match infrastructureProvider in tenant")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "InfrastructureProvider for Org does not match InfrastructureProvider in TenantAccount", nil)
	}

	if ta.TenantID != nil {
		// Verify that Tenant does not have any Allocations with the Provider
		allocationDAO := cdbm.NewAllocationDAO(dtah.dbSession)
		allocationFilter := cdbm.AllocationFilterInput{InfrastructureProviderID: &ip.ID}
		if ta.TenantID != nil {
			allocationFilter.TenantIDs = append(allocationFilter.TenantIDs, *ta.TenantID)
		}
		aCount, err := allocationDAO.GetCount(ctx, nil, allocationFilter)
		if err != nil {
			logger.Error().Str("ip", ip.ID.String()).Str("tenant", ta.TenantID.String()).Err(err).Msg("error getting allocations")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Error getting allocations for InfrastructureProvider, Tenant", nil)
		}

		if aCount > 0 {
			logger.Warn().Str("tenant", ta.TenantID.String()).Msg("allocations exist for tenant")
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Allocations exist for Tenant", nil)
		}
	}

	// Delete TenantAccount in DB
	err = taDAO.Delete(ctx, nil, taID)
	if err != nil {
		logger.Error().Err(err).Msg("error deleting TenantAccount in DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to delete Tenant", nil)
	}

	// Create response
	logger.Info().Msg("finishing API handler")

	return c.String(http.StatusAccepted, "Deletion request was accepted")
}
