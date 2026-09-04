// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/labstack/echo/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

var machineChassisIDRegexp = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*$`)

// ResetMachineChassisHandler queues a chassis reset for a Machine.
type ResetMachineChassisHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

// NewResetMachineChassisHandler returns a new ResetMachineChassisHandler.
func NewResetMachineChassisHandler(dbSession *cdb.Session, scp *sc.ClientPool) ResetMachineChassisHandler {
	return ResetMachineChassisHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Reset Machine Chassis
// @Description Queue a Redfish chassis reset through the Machine Maintenance state.
// @Tags Machine
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "ID of Machine"
// @Param chassisId query string true "Case-sensitive Redfish chassis identifier"
// @Success 202 {object} model.APIMessageResponse
// @Router /v2/org/{org}/nico/machine/{machineId}/chassis/reset [patch]
func (h ResetMachineChassisHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Machine", "ResetChassis", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	if dbUser == nil {
		logger.Error().Msg("Invalid User object found in request context")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	machineID := c.Param("id")
	if machineID == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine ID was not specified in URL", nil)
	}

	chassisID := c.QueryParam("chassisId")
	if !machineChassisIDRegexp.MatchString(chassisID) {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "chassisId is required and may only contain letters, numbers, dots, underscores, or dashes", nil)
	}

	provider, apiError := common.IsProvider(ctx, logger, h.dbSession, org, dbUser, false)
	if apiError != nil {
		return cutil.NewAPIErrorResponse(c, apiError.Code, apiError.Message, apiError.Data)
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
		logger.Error().Msg("Machine is missing on site, unable to reset chassis")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Machine is missing on site, unable to reset chassis", nil)
	}
	if machine.IsAssigned {
		logger.Error().Msg("Machine is currently in use by an Instance and cannot have its chassis reset")
		return cutil.NewAPIErrorResponse(c, http.StatusPreconditionFailed, "Machine is currently in use by an Instance and cannot have its chassis reset", nil)
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

	coreReq := &corev1.AdminChassisResetRequest{
		MachineId: &corev1.MachineId{Id: machineID},
		ChassisId: chassisID,
	}
	logger.Info().Str("machine_id", machineID).Str("chassis_id", chassisID).Str("site_id", site.ID.String()).Msg("Queueing chassis reset via Core gRPC proxy")
	apiErr := common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_AdminChassisReset_FullMethodName, coreReq, nil, site.ID.String())
	if apiErr != nil {
		logAPIError(logger, apiErr, "Failed to queue chassis reset via Core gRPC proxy")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}

	return c.JSON(http.StatusAccepted, model.APIMessageResponse{
		Message: "Machine chassis reset request was accepted",
	})
}
