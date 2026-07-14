// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	corev1 "github.com/NVIDIA/infra-controller/rest-api/proto/core/gen/v1"
)

type measurementTrustHandler struct {
	dbSession  *cdb.Session
	scp        *sc.ClientPool
	tracerSpan *cutil.TracerSpan
}

func newMeasurementTrustHandler(dbSession *cdb.Session, scp *sc.ClientPool) measurementTrustHandler {
	return measurementTrustHandler{
		dbSession:  dbSession,
		scp:        scp,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// CreateMeasurementTrustedMachineHandler creates a machine trust approval.
type CreateMeasurementTrustedMachineHandler struct{ measurementTrustHandler }

// NewCreateMeasurementTrustedMachineHandler returns a machine trust approval creation handler.
func NewCreateMeasurementTrustedMachineHandler(dbSession *cdb.Session, scp *sc.ClientPool) CreateMeasurementTrustedMachineHandler {
	return CreateMeasurementTrustedMachineHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle creates a machine trust approval.
func (h CreateMeasurementTrustedMachineHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedMachine", "Create", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	var apiReq model.APIMeasurementTrustedMachineCreateRequest
	if err := c.Bind(&apiReq); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid request body", nil)
	}
	if err := apiReq.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: apiReq.SiteID,
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.AddMeasurementTrustedMachineResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_AddMeasurementTrustedMachine_FullMethodName, apiReq.ToProto(), coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to create machine trust approval")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	return c.JSON(http.StatusCreated, model.NewAPIMeasurementTrustedMachine(coreResp.GetApprovalRecord()))
}

// ListMeasurementTrustedMachinesHandler lists machine trust approvals.
type ListMeasurementTrustedMachinesHandler struct{ measurementTrustHandler }

// NewListMeasurementTrustedMachinesHandler returns a machine trust approval list handler.
func NewListMeasurementTrustedMachinesHandler(dbSession *cdb.Session, scp *sc.ClientPool) ListMeasurementTrustedMachinesHandler {
	return ListMeasurementTrustedMachinesHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle lists machine trust approvals.
func (h ListMeasurementTrustedMachinesHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedMachine", "List", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: c.QueryParam("siteId"),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.ListMeasurementTrustedMachinesResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_ListMeasurementTrustedMachines_FullMethodName, &corev1.ListMeasurementTrustedMachinesRequest{}, coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to list machine trust approvals")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	var resp model.APIMeasurementTrustedMachines
	resp.FromProto(coreResp.GetApprovalRecords())
	return c.JSON(http.StatusOK, resp)
}

// DeleteMeasurementTrustedMachineHandler deletes a machine trust approval.
type DeleteMeasurementTrustedMachineHandler struct{ measurementTrustHandler }

// NewDeleteMeasurementTrustedMachineHandler returns a machine trust approval deletion handler.
func NewDeleteMeasurementTrustedMachineHandler(dbSession *cdb.Session, scp *sc.ClientPool) DeleteMeasurementTrustedMachineHandler {
	return DeleteMeasurementTrustedMachineHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle deletes a machine trust approval.
func (h DeleteMeasurementTrustedMachineHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedMachine", "Delete", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	apiReq := model.APIMeasurementTrustedMachineDeleteRequest{Selector: c.QueryParam("selector"), ID: c.Param("id")}
	if err := apiReq.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: c.QueryParam("siteId"),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.RemoveMeasurementTrustedMachineResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_RemoveMeasurementTrustedMachine_FullMethodName, apiReq.ToProto(), coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to delete machine trust approval")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	return c.JSON(http.StatusOK, model.NewAPIMeasurementTrustedMachine(coreResp.GetApprovalRecord()))
}

// CreateMeasurementTrustedProfileHandler creates a profile trust approval.
type CreateMeasurementTrustedProfileHandler struct{ measurementTrustHandler }

// NewCreateMeasurementTrustedProfileHandler returns a profile trust approval creation handler.
func NewCreateMeasurementTrustedProfileHandler(dbSession *cdb.Session, scp *sc.ClientPool) CreateMeasurementTrustedProfileHandler {
	return CreateMeasurementTrustedProfileHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle creates a profile trust approval.
func (h CreateMeasurementTrustedProfileHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedProfile", "Create", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	var apiReq model.APIMeasurementTrustedProfileCreateRequest
	if err := c.Bind(&apiReq); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid request body", nil)
	}
	if err := apiReq.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: apiReq.SiteID,
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.AddMeasurementTrustedProfileResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_AddMeasurementTrustedProfile_FullMethodName, apiReq.ToProto(), coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to create profile trust approval")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	return c.JSON(http.StatusCreated, model.NewAPIMeasurementTrustedProfile(coreResp.GetApprovalRecord()))
}

// ListMeasurementTrustedProfilesHandler lists profile trust approvals.
type ListMeasurementTrustedProfilesHandler struct{ measurementTrustHandler }

// NewListMeasurementTrustedProfilesHandler returns a profile trust approval list handler.
func NewListMeasurementTrustedProfilesHandler(dbSession *cdb.Session, scp *sc.ClientPool) ListMeasurementTrustedProfilesHandler {
	return ListMeasurementTrustedProfilesHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle lists profile trust approvals.
func (h ListMeasurementTrustedProfilesHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedProfile", "List", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: c.QueryParam("siteId"),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.ListMeasurementTrustedProfilesResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_ListMeasurementTrustedProfiles_FullMethodName, &corev1.ListMeasurementTrustedProfilesRequest{}, coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to list profile trust approvals")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	var resp model.APIMeasurementTrustedProfiles
	resp.FromProto(coreResp.GetApprovalRecords())
	return c.JSON(http.StatusOK, resp)
}

// DeleteMeasurementTrustedProfileHandler deletes a profile trust approval.
type DeleteMeasurementTrustedProfileHandler struct{ measurementTrustHandler }

// NewDeleteMeasurementTrustedProfileHandler returns a profile trust approval deletion handler.
func NewDeleteMeasurementTrustedProfileHandler(dbSession *cdb.Session, scp *sc.ClientPool) DeleteMeasurementTrustedProfileHandler {
	return DeleteMeasurementTrustedProfileHandler{newMeasurementTrustHandler(dbSession, scp)}
}

// Handle deletes a profile trust approval.
func (h DeleteMeasurementTrustedProfileHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("MeasurementTrustedProfile", "Delete", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	apiReq := model.APIMeasurementTrustedProfileDeleteRequest{Selector: c.QueryParam("selector"), ID: c.Param("id")}
	if err := apiReq.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	stc, siteID, apiErr := common.AuthorizeProviderSiteForCore(common.AuthorizeProviderSiteForCoreInput{
		Ctx: ctx, Logger: logger, DBSession: h.dbSession, SCP: h.scp, Org: org, User: dbUser, SiteID: c.QueryParam("siteId"),
	})
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	coreResp := &corev1.RemoveMeasurementTrustedProfileResponse{}
	apiErr = common.ExecuteCoreGRPC(ctx, stc, corev1.Forge_RemoveMeasurementTrustedProfile_FullMethodName, apiReq.ToProto(), coreResp, siteID)
	if apiErr != nil {
		logAPIError(logger, apiErr, "failed to delete profile trust approval")
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, nil)
	}
	return c.JSON(http.StatusOK, model.NewAPIMeasurementTrustedProfile(coreResp.GetApprovalRecord()))
}
