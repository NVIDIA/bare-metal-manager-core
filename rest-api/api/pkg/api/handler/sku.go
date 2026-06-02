// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/NVIDIA/infra-controller-rest/api/internal/config"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/pagination"
	cutil "github.com/NVIDIA/infra-controller-rest/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
	cdbp "github.com/NVIDIA/infra-controller-rest/db/pkg/db/paginator"
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
