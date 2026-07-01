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

type DpuReprovisionHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

func NewDpuReprovisionHandler(dbSession *cdb.Session, scp *sc.ClientPool, cfg *config.Config) DpuReprovisionHandler {
	return DpuReprovisionHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Trigger DPU Reprovisioning
// @Description Trigger DPU reprovisioning for a Machine through NICo Core. Provider Admin only.
// @Tags dpu-reprovision
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Machine"
// @Param request body model.APIDpuReprovisionRequest true "DPU reprovision request"
// @Success 202 {object} model.APIMessageResponse
// @Router /v2/org/{org}/nico/machine/{machineId}/dpu/reprovision [patch]
func (h DpuReprovisionHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("DpuReprovision", "Trigger", c, h.tracerSpan)
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

	var apiReq model.APIDpuReprovisionRequest
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
		logger.Error().Msg("Machine is missing on site, unable to trigger DPU reprovisioning")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine is missing on site, unable to trigger DPU reprovisioning", nil)
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

	logger.Info().Str("machine_id", machineID).Str("mode", apiReq.Mode).Str("site_id", site.ID.String()).Msg("Triggering DPU reprovisioning via Core gRPC proxy")

	apiErr := common.ExecuteCoreGRPC(ctx, stc, cwssaws.Forge_TriggerDpuReprovisioning_FullMethodName, apiReq.ToProto(machineID), nil, site.ID.String())
	if apiErr != nil {
		logAPIError(logger, apiErr, "Failed to trigger DPU reprovisioning via Core gRPC proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	return c.JSON(http.StatusAccepted, model.APIMessageResponse{
		Message: "DPU reprovisioning request was accepted",
	})
}
