// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	auth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"
)

type ListMachineHealthReportHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

func NewListMachineHealthReportHandler(dbSession *cdb.Session, scp *sc.ClientPool, cfg *config.Config) ListMachineHealthReportHandler {
	return ListMachineHealthReportHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List Machine Health Reports
// @Description List Machine health report overrides through NICo Core. Provider Admin only.
// @Tags health-report
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Machine"
// @Success 200 {array} model.APIMachineHealthReportEntry
// @Router /v2/org/{org}/nico/machine/{machineId}/health-report [get]
func (h ListMachineHealthReportHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MachineHealthReport", "List", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		logger.Error().Msg("Invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("Error validating org membership for User in request")
		} else {
			logger.Warn().Msg("Could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	machineID := c.Param("id")
	if machineID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine ID was not specified in URL", nil)
	}

	provider, _, apiError := common.IsProviderOrTenant(ctx, logger, h.dbSession, org, dbUser, true, true)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	if provider == nil {
		logger.Warn().Msg("user does not have Provider role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	machine, err := cdbm.NewMachineDAO(h.dbSession).GetByID(ctx, nil, machineID, []string{cdbm.SiteRelationName}, false)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
		}
		logger.Error().Err(err).Msg("failed to retrieve Machine details from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Machine details, DB error", nil)
	}

	if machine.InfrastructureProviderID != provider.ID {
		logger.Error().Msg("Machine doesn't belong to org's Infrastructure provider")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
	}

	if machine.IsMissingOnSite {
		logger.Error().Msg("Machine is missing on site, unable to list health reports")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine is missing on site, unable to list health reports", nil)
	}

	if machine.Site == nil {
		logger.Error().Msg("Related Site was not returned for Machine DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site details for Machine, DB error", nil)
	}

	site := machine.Site

	if site.Status != cdbm.SiteStatusRegistered {
		logger.Warn().Msg("Site specified in request data is not in Registered state")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data is not in Registered state, cannot execute admin operation", nil)
	}

	stc, err := h.scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve workflow client for Site", nil)
	}

	logger.Info().Str("machine_id", machineID).Str("site_id", site.ID.String()).Msg("Listing Machine health reports via Core gRPC proxy")

	coreResp := &cwssaws.ListHealthReportResponse{}
	apiErr := common.ExecuteCoreGRPC(ctx, stc, cwssaws.Forge_ListMachineHealthReports_FullMethodName, model.NewMachineIDProto(machineID), coreResp, site.ID.String())
	if apiErr != nil {
		logAPIError(logger, apiErr, "Failed to list Machine health reports via Core gRPC proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	apiResp := []model.APIMachineHealthReportEntry{}
	for _, entry := range coreResp.GetHealthReportEntries() {
		apiEntry := model.APIMachineHealthReportEntry{}
		apiEntry.FromProto(entry)
		apiResp = append(apiResp, apiEntry)
	}

	return c.JSON(http.StatusOK, apiResp)
}

type InsertMachineHealthReportHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

func NewInsertMachineHealthReportHandler(dbSession *cdb.Session, scp *sc.ClientPool, cfg *config.Config) InsertMachineHealthReportHandler {
	return InsertMachineHealthReportHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Insert Machine Health Report
// @Description Add or update a Machine health report override through NICo Core. Provider Admin only.
// @Tags health-report
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Machine"
// @Param request body model.APIMachineHealthReportEntryRequest true "Machine health report"
// @Success 200 {object} model.APIMachineHealthReportEntry
// @Router /v2/org/{org}/nico/machine/{machineId}/health-report [put]
func (h InsertMachineHealthReportHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MachineHealthReport", "Insert", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		logger.Error().Msg("Invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("Error validating org membership for User in request")
		} else {
			logger.Warn().Msg("Could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	machineID := c.Param("id")
	if machineID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine ID was not specified in URL", nil)
	}

	var apiReq model.APIMachineHealthReportEntryRequest
	err = c.Bind(&apiReq)
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	err = apiReq.Validate()
	if err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	provider, _, apiError := common.IsProviderOrTenant(ctx, logger, h.dbSession, org, dbUser, true, true)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	if provider == nil {
		logger.Warn().Msg("user does not have Provider role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	machine, err := cdbm.NewMachineDAO(h.dbSession).GetByID(ctx, nil, machineID, []string{cdbm.SiteRelationName}, false)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
		}

		logger.Error().Err(err).Msg("failed to retrieve Machine details from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Machine details, DB error", nil)
	}

	if machine.InfrastructureProviderID != provider.ID {
		logger.Error().Msg("Machine doesn't belong to org's Infrastructure provider")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
	}

	if machine.IsMissingOnSite {
		logger.Error().Msg("Machine is missing on site, unable to insert health report")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine is missing on site, unable to insert health report", nil)
	}

	if machine.Site == nil {
		logger.Error().Msg("Related Site was not returned for Machine DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site details for Machine, DB error", nil)
	}

	site := machine.Site

	if site.Status != cdbm.SiteStatusRegistered {
		logger.Warn().Msg("Site specified in request data is not in Registered state")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data is not in Registered state, cannot execute admin operation", nil)
	}

	stc, err := h.scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve workflow client for Site", nil)
	}

	logger.Info().Str("machine_id", machineID).Str("source", apiReq.Source).Str("site_id", site.ID.String()).Msg("Inserting Machine health report via Core gRPC proxy")

	protoReq := apiReq.ToProto(machineID, dbUser.ID.String())
	apiErr := common.ExecuteCoreGRPC(ctx, stc, cwssaws.Forge_InsertMachineHealthReport_FullMethodName, protoReq, nil, site.ID.String())
	if apiErr != nil {
		logAPIError(logger, apiErr, "Failed to insert Machine health report via Core gRPC proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	apiResp := model.APIMachineHealthReportEntry{}
	apiResp.FromProto(protoReq.GetHealthReportEntry())

	return c.JSON(http.StatusOK, apiResp)
}

type RemoveMachineHealthReportHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

func NewRemoveMachineHealthReportHandler(dbSession *cdb.Session, scp *sc.ClientPool, cfg *config.Config) RemoveMachineHealthReportHandler {
	return RemoveMachineHealthReportHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Remove Machine Health Report
// @Description Remove a Machine health report override through NICo Core. Provider Admin only.
// @Tags health-report
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Machine"
// @Param source path string true "Health report source"
// @Success 204
// @Router /v2/org/{org}/nico/machine/{machineId}/health-report/{source} [delete]
func (h RemoveMachineHealthReportHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MachineHealthReport", "Remove", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		logger.Error().Msg("Invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("Error validating org membership for User in request")
		} else {
			logger.Warn().Msg("Could not validate org membership for user, access denied")
		}
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	machineID := c.Param("id")
	if machineID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine ID was not specified in URL", nil)
	}

	source := c.Param("source")
	if source == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "source is required", nil)
	}

	provider, _, apiError := common.IsProviderOrTenant(ctx, logger, h.dbSession, org, dbUser, true, true)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
	}

	if provider == nil {
		logger.Warn().Msg("user does not have Provider role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	machine, err := cdbm.NewMachineDAO(h.dbSession).GetByID(ctx, nil, machineID, []string{cdbm.SiteRelationName}, false)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
		}
		logger.Error().Err(err).Msg("failed to retrieve Machine details from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Machine details, DB error", nil)
	}

	if machine.InfrastructureProviderID != provider.ID {
		logger.Error().Msg("Machine doesn't belong to org's Infrastructure provider")
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Could not find Machine with specified ID", nil)
	}

	if machine.IsMissingOnSite {
		logger.Error().Msg("Machine is missing on site, unable to remove health report")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine is missing on site, unable to remove health report", nil)
	}

	if machine.Site == nil {
		logger.Error().Msg("Related Site was not returned for Machine DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Site details for Machine, DB error", nil)
	}

	site := machine.Site

	if site.Status != cdbm.SiteStatusRegistered {
		logger.Warn().Msg("Site specified in request data is not in Registered state")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Site specified in request data is not in Registered state, cannot execute admin operation", nil)
	}

	stc, err := h.scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve workflow client for Site", nil)
	}

	logger.Info().Str("machine_id", machineID).Str("source", source).Str("site_id", site.ID.String()).Msg("Removing Machine health report via Core gRPC proxy")

	apiErr := common.ExecuteCoreGRPC(ctx, stc, cwssaws.Forge_RemoveMachineHealthReport_FullMethodName, model.NewRemoveMachineHealthReportProto(machineID, source), nil, site.ID.String())
	if apiErr != nil {
		logAPIError(logger, apiErr, "Failed to remove Machine health report via Core gRPC proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	return c.NoContent(http.StatusNoContent)
}
