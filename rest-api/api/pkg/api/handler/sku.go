// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"go.opentelemetry.io/otel/attribute"
	tclient "go.temporal.io/sdk/client"
)

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllSkuHandler is the API Handler for getting all SKUs
type GetAllSkuHandler struct {
	dbSession  *cdb.Session
	tc         tclient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllSkuHandler initializes and returns a new handler for getting all SKUs
func NewGetAllSkuHandler(dbSession *cdb.Session, tc tclient.Client, cfg *config.Config) GetAllSkuHandler {
	return GetAllSkuHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get all SKUs
// @Description Get all SKUs
// @Tags SKU
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteId query string false "ID of Site (optional, filters results to specific site)"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Param orderBy query string false "Order by field"
// @Success 200 {object} []model.APISku
// @Router /v2/org/{org}/nico/sku [get]
func (gash GetAllSkuHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("GetAll", "SKU", c, gash.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	// Is DB user missing?
	if dbUser == nil {
		logger.Error().Msg("invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org membership
	if _, err := dbUser.OrgData.GetOrgByName(org); err != nil {
		logger.Warn().Msg("could not validate org membership for user, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins/Viewers or Tenant Admins with TargetedInstanceCreation capability are allowed to retrieve SKUs
	infrastructureProvider, tenant, apiError := common.IsProviderOrTenant(ctx, logger, gash.dbSession, org, dbUser, true, true)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	// Get Site ID from query param - REQUIRED
	siteIDStr := c.QueryParam("siteId")
	if siteIDStr == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site ID must be specified in query parameter 'siteId'", nil)
	}

	site, err := common.GetSiteFromIDString(ctx, nil, siteIDStr, gash.dbSession)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data does not exist", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Site from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site specified in request data, DB error", nil)
	}

	// Validate based on whether user is provider or tenant
	if infrastructureProvider != nil {
		// Validate that site belongs to the organization's infrastructure provider
		if site.InfrastructureProviderID != infrastructureProvider.ID {
			logger.Warn().Msg("Site specified in request data does not belong to current org's Infrastructure Provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Site specified in request data is does not belong to current org", nil)
		}
	} else if tenant != nil {
		// Check if Tenant is privileged
		if !tenant.Config.TargetedInstanceCreation {
			logger.Warn().Msg("Tenant doesn't have targeted Instance creation capability, access denied")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant must have targeted Instance creation capability in order to retrieve SKUs", nil)
		}

		// Check if privileged Tenant has an account with Infrastructure Provider
		taDAO := cdbm.NewTenantAccountDAO(gash.dbSession)
		_, taCount, serr := taDAO.GetAll(ctx, nil, cdbm.TenantAccountFilterInput{
			InfrastructureProviderID: &site.InfrastructureProviderID,
			TenantIDs:                []uuid.UUID{tenant.ID},
		}, cdbp.PageInput{}, []string{})
		if serr != nil {
			logger.Error().Err(serr).Msg("error retrieving Tenant Account for Site")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Error retrieving Tenant Account for Site", nil)
		}

		if taCount == 0 {
			logger.Error().Msg("privileged Tenant doesn't have an account with Infrastructure Provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Privileged Tenant must have an account with Provider of Site specified in query", nil)
		}
	}

	filterInput := cdbm.SkuFilterInput{
		SiteIDs: []uuid.UUID{site.ID},
	}

	// Validate pagination request
	pageRequest := pagination.PageRequest{}
	err = c.Bind(&pageRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding pagination request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request pagination data", nil)
	}

	// Validate pagination attributes
	err = pageRequest.Validate(cdbm.SkuOrderByFields)
	if err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	// Get SKUs from DB
	skuDAO := cdbm.NewSkuDAO(gash.dbSession)
	skus, total, err := skuDAO.GetAll(
		ctx,
		nil,
		filterInput,
		paginator.PageInput{
			Offset:  pageRequest.Offset,
			Limit:   pageRequest.Limit,
			OrderBy: pageRequest.OrderBy,
		},
	)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving SKUs from db")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve SKUs, DB error", nil)
	}

	// Create response
	apiSkus := []*model.APISku{}
	for _, sku := range skus {
		apiSku := model.NewAPISku(&sku)
		apiSkus = append(apiSkus, apiSku)
	}

	// Create pagination response header
	pageResponse := pagination.NewPageResponse(*pageRequest.PageNumber, *pageRequest.PageSize, total, pageRequest.OrderByStr)
	pageHeader, err := json.Marshal(pageResponse)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling pagination response")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to generate pagination response header", nil)
	}

	c.Response().Header().Set(pagination.ResponseHeaderName, string(pageHeader))

	logger.Info().Msg("finishing API handler")

	return c.JSON(http.StatusOK, apiSkus)
}

// ~~~~~ Get Handler ~~~~~ //

// GetSkuHandler is the API Handler for retrieving SKU
type GetSkuHandler struct {
	dbSession  *cdb.Session
	tc         tclient.Client
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetSkuHandler initializes and returns a new handler to retrieve SKU
func NewGetSkuHandler(dbSession *cdb.Session, tc tclient.Client, cfg *config.Config) GetSkuHandler {
	return GetSkuHandler{
		dbSession:  dbSession,
		tc:         tc,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve the SKU
// @Description Retrieve the SKU by ID
// @Tags SKU
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of SKU"
// @Success 200 {object} model.APISku
// @Router /v2/org/{org}/nico/sku/{id} [get]
func (gsh GetSkuHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Get", "SKU", c, gsh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	// Is DB user missing?
	if dbUser == nil {
		logger.Error().Msg("invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Validate org membership
	if _, err := dbUser.OrgData.GetOrgByName(org); err != nil {
		logger.Warn().Msg("could not validate org membership for user, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	// Validate role, only Provider Admins/Viewers or Tenant Admins with TargetedInstanceCreation capability are allowed to retrieve SKUs
	infrastructureProvider, tenant, apiError := common.IsProviderOrTenant(ctx, logger, gsh.dbSession, org, dbUser, true, true)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	// Get SKU ID from URL param
	skuID := c.Param("id")

	logger = logger.With().Str("SKU ID", skuID).Logger()

	gsh.tracerSpan.SetAttribute(handlerSpan, attribute.String("sku_id", skuID), logger)

	// Get SKU from DB by ID
	skuDAO := cdbm.NewSkuDAO(gsh.dbSession)
	sku, err := skuDAO.Get(ctx, nil, skuID)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, fmt.Sprintf("Could not find SKU with ID: %s", skuID), nil)
		}
		logger.Error().Err(err).Msg("error retrieving SKU from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve SKU, DB error", nil)
	}

	// Get Site for the SKU
	siteDAO := cdbm.NewSiteDAO(gsh.dbSession)
	site, err := siteDAO.GetByID(ctx, nil, sku.SiteID, nil, false)
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Site from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site details for SKU, DB error", nil)
	}

	// Validate based on whether user is provider or tenant
	if infrastructureProvider != nil {
		// Validate that site belongs to the organization's infrastructure provider
		if site.InfrastructureProviderID != infrastructureProvider.ID {
			logger.Warn().Msg("SKU does not belong to a Site owned by org's Infrastructure Provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "SKU does not belong to a Site owned by current org", nil)
		}
	} else if tenant != nil {
		// Check if Tenant is privileged
		if !tenant.Config.TargetedInstanceCreation {
			logger.Warn().Msg("Tenant doesn't have targeted Instance creation capability, access denied")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Tenant must have targeted Instance creation capability in order to retrieve SKU", nil)
		}

		// Check if privileged Tenant has an account with Infrastructure Provider
		taDAO := cdbm.NewTenantAccountDAO(gsh.dbSession)
		_, taCount, serr := taDAO.GetAll(ctx, nil, cdbm.TenantAccountFilterInput{
			InfrastructureProviderID: &site.InfrastructureProviderID,
			TenantIDs:                []uuid.UUID{tenant.ID},
		}, cdbp.PageInput{}, []string{})
		if serr != nil {
			logger.Error().Err(serr).Msg("error retrieving Tenant Account for Site")
			return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Error retrieving Tenant Account for Site", nil)
		}

		if taCount == 0 {
			logger.Error().Msg("privileged Tenant doesn't have an account with Infrastructure Provider")
			return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "Privileged Tenant must have an account with Provider of SKU's Site", nil)
		}
	}

	// Create response
	apiSku := model.NewAPISku(sku)

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiSku)
}

const (
	createSkuMethod         = "/forge.Forge/CreateSku"
	findSkusByIDsMethod     = "/forge.Forge/FindSkusByIds"
	updateSkuMetadataMethod = "/forge.Forge/UpdateSkuMetadata"
	replaceSkuMethod        = "/forge.Forge/ReplaceSku"
	deleteSkuMethod         = "/forge.Forge/DeleteSku"
)

// CreateSkuHandler creates one SKU on a Site's Core service.
type CreateSkuHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewCreateSkuHandler initializes and returns a new CreateSkuHandler.
func NewCreateSkuHandler(dbSession *cdb.Session, scp *sc.ClientPool) CreateSkuHandler {
	return CreateSkuHandler{dbSession: dbSession, scp: scp, tracerSpan: cutil.NewTracerSpan()}
}

// Handle godoc
// @Summary Create SKU
// @Description Create a SKU on the selected Site's Core service.
// @Tags SKU
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param request body model.APISkuCreateRequest true "SKU create request"
// @Success 201 {object} model.APISkuMutationResponse
// @Router /v2/org/{org}/nico/sku [post]
func (csh CreateSkuHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("SKU", "Create", c, csh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	// Validate request data
	// Bind request data to API model
	apiReq := model.APISkuCreateRequest{}
	err := c.Bind(&apiReq)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiReq.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating SKU create request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating SKU create request data", verr)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: csh.dbSession, SCP: csh.scp,
		Org: org, User: dbUser, SiteID: apiReq.SiteID,
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	// Check if a SKU already exists for the given SKU ID and Site ID
	skuDAO := cdbm.NewSkuDAO(csh.dbSession)
	siteUUID, err := uuid.Parse(siteID)
	if err != nil {
		logger.Error().Err(err).Msg("error parsing Site ID")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Site ID", nil)
	}
	_, tot, err := skuDAO.GetAll(ctx, nil, cdbm.SkuFilterInput{SiteIDs: []uuid.UUID{siteUUID}, SkuIDs: []string{apiReq.ID}}, paginator.PageInput{})
	if err != nil {
		logger.Error().Err(err).Msg("error checking for existing SKUs")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to check for existing SKUs", nil)
	}
	if tot > 0 {
		return cutil.NewAPIErrorResponse(c, http.StatusConflict, fmt.Sprintf("SKU with ID: %s for Site: %s already exists", apiReq.ID, siteID), nil)
	}

	logger.Info().Str("skuID", apiReq.ID).Str("siteID", siteID).Msg("creating SKU via Core proxy")
	var ids corev1.SkuIdList
	if apiErr = common.ExecuteCoreGRPC(ctx, stc, createSkuMethod, apiReq.ToProto(), &ids, siteID); apiErr != nil {
		logAPIError(logger, apiErr, "failed to create SKU via Core proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	if len(ids.Ids) != 1 {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Core returned an unexpected SKU create response", nil)
	}

	var response corev1.SkuList
	apiErr = common.ExecuteCoreGRPC(
		ctx,
		stc,
		findSkusByIDsMethod,
		&corev1.SkusByIdsRequest{Ids: []string{ids.Ids[0]}},
		&response,
		siteID,
	)
	if apiErr == nil && len(response.Skus) != 1 {
		apiErr = cutil.NewAPIError(http.StatusNotFound, "Could not find SKU with the specified ID", nil)
	}
	if apiErr != nil {
		logger.Warn().Err(apiErr).Str("skuID", ids.Ids[0]).Str("siteID", siteID).
			Msg("SKU created but post-create retrieval failed; returning request-derived response")
		return c.JSON(http.StatusCreated, model.NewAPISkuMutationResponseFromCreateRequest(apiReq, ids.Ids[0], siteID))
	}
	return c.JSON(http.StatusCreated, model.NewAPISkuMutationResponse(response.Skus[0], siteID))
}

// UpdateSkuHandler partially updates one SKU on a Site's Core service.
type UpdateSkuHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewUpdateSkuHandler returns a new UpdateSkuHandler.
func NewUpdateSkuHandler(dbSession *cdb.Session, scp *sc.ClientPool) UpdateSkuHandler {
	return UpdateSkuHandler{dbSession: dbSession, scp: scp, tracerSpan: cutil.NewTracerSpan()}
}

// Handle godoc
// @Summary Update SKU
// @Description Update selected mutable fields on a SKU.
// @Tags SKU
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "SKU ID"
// @Param request body model.APISkuUpdateRequest true "SKU update request"
// @Success 200 {object} model.APISkuMutationResponse
// @Router /v2/org/{org}/nico/sku/{id} [patch]
func (ush UpdateSkuHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("SKU", "Update", c, ush.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	skuID := c.Param("id")
	if skuID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "SKU ID must be specified", nil)
	}
	apiReq := model.APISkuUpdateRequest{}
	err := c.Bind(&apiReq)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}
	err = apiReq.Validate()
	if err != nil {
		logger.Warn().Err(err).Msg("error validating SKU update request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Error validating SKU update request data", err)
	}

	skuDAO := cdbm.NewSkuDAO(ush.dbSession)
	savedSKU, err := skuDAO.Get(ctx, nil, skuID)
	if errors.Is(err, cdb.ErrDoesNotExist) {
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find SKU with the specified ID", nil)
	}
	if err != nil {
		logger.Error().Err(err).Str("skuID", skuID).Msg("error retrieving SKU from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve SKU, DB error", nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: ush.dbSession, SCP: ush.scp,
		Org: org, User: dbUser, SiteID: savedSKU.SiteID.String(),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	var response corev1.SkuList
	apiErr = common.ExecuteCoreGRPC(
		ctx,
		stc,
		findSkusByIDsMethod,
		&corev1.SkusByIdsRequest{Ids: []string{skuID}},
		&response,
		siteID,
	)
	if apiErr == nil && len(response.Skus) != 1 {
		apiErr = cutil.NewAPIError(http.StatusNotFound, "Could not find SKU with the specified ID", nil)
	}
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to retrieve SKU before update")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	apiReq.SKUID = skuID
	if apiReq.Components == nil {
		updated := apiReq.ApplyMetadataToProto(response.Skus[0])
		logger.Info().Str("skuID", skuID).Str("siteID", siteID).Msg("updating SKU metadata via Core proxy")
		if apiErr = common.ExecuteCoreGRPC(ctx, stc, updateSkuMetadataMethod, apiReq.ToMetadataProto(), nil, siteID); apiErr != nil {
			logAPIError(logger, apiErr, "failed to update SKU metadata via Core proxy")
			return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
		}
		return c.JSON(http.StatusOK, model.NewAPISkuMutationResponse(updated, siteID))
	}

	if response.Skus[0].SchemaVersion != model.CoreSkuSchemaVersion {
		return cutil.NewAPIErrorResponse(
			c,
			http.StatusConflict,
			"SKU components can only be updated for the current schema version; migrate the SKU before updating components",
			nil,
		)
	}

	updatedReq := apiReq.ToReplacementProto(response.Skus[0])
	var updated corev1.Sku
	logger.Info().Str("skuID", skuID).Str("siteID", siteID).Msg("updating SKU via Core proxy")
	if apiErr = common.ExecuteCoreGRPC(ctx, stc, replaceSkuMethod, updatedReq, &updated, siteID); apiErr != nil {
		logAPIError(logger, apiErr, "failed to update SKU via Core proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	return c.JSON(http.StatusOK, model.NewAPISkuMutationResponse(&updated, siteID))
}

// DeleteSkuHandler deletes one unused SKU from a Site's Core service.
type DeleteSkuHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewDeleteSkuHandler returns a new DeleteSkuHandler.
func NewDeleteSkuHandler(dbSession *cdb.Session, scp *sc.ClientPool) DeleteSkuHandler {
	return DeleteSkuHandler{dbSession: dbSession, scp: scp, tracerSpan: cutil.NewTracerSpan()}
}

// Handle godoc
// @Summary Delete SKU
// @Description Delete an unused SKU.
// @Tags SKU
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "SKU ID"
// @Success 204
// @Router /v2/org/{org}/nico/sku/{id} [delete]
func (dsh DeleteSkuHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("SKU", "Delete", c, dsh.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	skuID := c.Param("id")
	if skuID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "SKU ID must be specified", nil)
	}

	skuDAO := cdbm.NewSkuDAO(dsh.dbSession)
	savedSKU, err := skuDAO.Get(ctx, nil, skuID)
	if errors.Is(err, cdb.ErrDoesNotExist) {
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find SKU with the specified ID", nil)
	}
	if err != nil {
		logger.Error().Err(err).Str("skuID", skuID).Msg("error retrieving SKU from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve SKU, DB error", nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: dsh.dbSession, SCP: dsh.scp,
		Org: org, User: dbUser, SiteID: savedSKU.SiteID.String(),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	logger.Info().Str("skuID", skuID).Str("siteID", siteID).Msg("deleting SKU via Core proxy")
	if apiErr = common.ExecuteCoreGRPC(ctx, stc, deleteSkuMethod, &corev1.SkuIdList{Ids: []string{skuID}}, nil, siteID); apiErr != nil {
		logAPIError(logger, apiErr, "failed to delete SKU via Core proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	logger.Info().Str("skuID", skuID).Str("siteID", siteID).Msg("finishing API handler")
	return c.NoContent(http.StatusNoContent)
}
