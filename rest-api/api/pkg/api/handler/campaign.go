// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	temporalEnums "go.temporal.io/api/enums/v1"
	tClient "go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/pagination"
	sc "github.com/NVIDIA/infra-controller/rest-api/api/pkg/client/site"
	auth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	flowv1 "github.com/NVIDIA/infra-controller/rest-api/proto/flow/gen/v1"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"
)

// prepareCampaignHandler runs the auth + site lookup + Flow-enabled check +
// Temporal client retrieval shared by every Campaign handler.
func prepareCampaignHandler(
	c echo.Context,
	dbSession *cdb.Session,
	scp *sc.ClientPool,
	dbUser *cdbm.User,
	org string,
	siteIDStr string,
	logger zerolog.Logger,
	ctx context.Context,
) (*cdbm.Site, tClient.Client, *cutil.APIError) {
	if dbUser == nil {
		logger.Error().Msg("invalid User object found in request context")
		return nil, nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	ok, err := auth.ValidateOrgMembership(dbUser, org)
	if !ok {
		if err != nil {
			logger.Error().Err(err).Msg("error validating org membership for User in request")
		} else {
			logger.Warn().Msg("could not validate org membership for user, access denied")
		}
		return nil, nil, cutil.NewAPIError(http.StatusForbidden, fmt.Sprintf("Failed to validate membership for org: %s", org), nil)
	}

	if !auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole) {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return nil, nil, cutil.NewAPIError(http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	infrastructureProvider, err := common.GetInfrastructureProviderForOrg(ctx, nil, dbSession, org)
	if err != nil {
		logger.Warn().Err(err).Msg("error getting infrastructure provider for org")
		return nil, nil, cutil.NewAPIError(http.StatusBadRequest, "Failed to retrieve Infrastructure Provider for org", nil)
	}

	site, err := common.GetSiteFromIDString(ctx, nil, siteIDStr, dbSession)
	if err != nil {
		switch {
		case errors.Is(err, common.ErrInvalidID):
			return nil, nil, cutil.NewAPIError(http.StatusBadRequest, "Failed to validate Site specified in request: invalid ID", nil)
		case errors.Is(err, cdb.ErrDoesNotExist):
			return nil, nil, cutil.NewAPIError(http.StatusBadRequest, "Site specified in request does not exist", nil)
		default:
			logger.Error().Err(err).Msg("error retrieving Site from DB")
			return nil, nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve Site specified in request due to DB error", nil)
		}
	}

	if site.InfrastructureProviderID != infrastructureProvider.ID {
		return nil, nil, cutil.NewAPIError(http.StatusForbidden, "Site specified in request doesn't belong to current org's Provider", nil)
	}

	siteConfig := &cdbm.SiteConfig{}
	if site.Config != nil {
		siteConfig = site.Config
	}
	if !siteConfig.Flow {
		logger.Warn().Msg("site does not have NICo Flow enabled")
		return nil, nil, cutil.NewAPIError(http.StatusPreconditionFailed, "Site does not have NICo Flow enabled", nil)
	}

	stc, err := scp.GetClientByID(site.ID)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve Temporal client for Site")
		return nil, nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve client for Site", nil)
	}

	return site, stc, nil
}

// campaignWorkflowOptions returns the standard site-queue workflow options for
// a campaign action with the given deterministic workflow ID.
func campaignWorkflowOptions(workflowID string) tClient.StartWorkflowOptions {
	return tClient.StartWorkflowOptions{
		ID:                       workflowID,
		WorkflowIDReusePolicy:    temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
	}
}

// ~~~~~ Create Campaign Handler ~~~~~ //

// CreateCampaignHandler is the API Handler for creating a Campaign.
type CreateCampaignHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateCampaignHandler initializes a new CreateCampaignHandler.
func NewCreateCampaignHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) CreateCampaignHandler {
	return CreateCampaignHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Create a Campaign
// @Description Create a Campaign (operation run): a phased, policy-gated rollout of one operation across many racks. The configuration is validated server-side; on validation failure no state changes.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param body body model.APICampaignCreateRequest true "Create campaign request"
// @Success 201 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign [post]
func (h CreateCampaignHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "Create", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	apiRequest := model.APICampaignCreateRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if verr := apiRequest.Validate(); verr != nil {
		logger.Warn().Err(verr).Msg("error validating create campaign request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, verr.Error(), nil)
	}

	_, stc, apiErr := prepareCampaignHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	flowRequest, ferr := apiRequest.ToProto()
	if ferr != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, ferr.Error(), nil)
	}

	// Dedicated workflow ID per request so Create is never deduped.
	workflowID := fmt.Sprintf("campaign-create-%s", uuid.NewString())

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, campaignWorkflowOptions(workflowID), "CreateCampaign", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule CreateCampaign workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Campaign creation workflow", nil)
	}

	var flowResponse flowv1.CreateOperationRunResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Campaign", "CreateCampaign")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from CreateCampaign workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Campaign creation workflow on Site: %s", unwrapErr), nil)
	}

	// Flow's CreateOperationRun returns only the new run's ID. Echo the known
	// fields so the client gets the canonical identity without an extra GET; a
	// campaign always starts Pending. The operation type is firmware (the only
	// supported operation today).
	created := &model.APICampaign{
		ID:            flowResponse.GetId().GetId(),
		Name:          apiRequest.Name,
		Description:   apiRequest.Description,
		OperationType: model.APIOperationTypeFirmwareControl,
		Status:        "Pending",
		StatusReason:  "None",
	}

	logger.Info().Str("CampaignID", created.ID).Msg("finishing API handler")
	return c.JSON(http.StatusCreated, created)
}

// ~~~~~ Get Campaign Handler ~~~~~ //

// GetCampaignHandler is the API Handler for getting a Campaign by ID.
type GetCampaignHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetCampaignHandler initializes a new GetCampaignHandler.
func NewGetCampaignHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) GetCampaignHandler {
	return GetCampaignHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get a Campaign
// @Description Get a Campaign (operation run) by UUID. Set includeStats=true for derived per-phase outcome counts.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param siteId query string true "ID of the Site"
// @Param includeStats query boolean false "Include derived per-phase outcome stats (default false)"
// @Success 200 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign/{id} [get]
func (h GetCampaignHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "Get", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	var apiRequest model.APICampaignGetRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareCampaignHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	flowRequest := &flowv1.GetOperationRunRequest{
		Id:           &flowv1.UUID{Id: campaignID},
		IncludeStats: apiRequest.IncludeStats,
	}
	workflowID := fmt.Sprintf("campaign-get-%s", campaignID)

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, campaignWorkflowOptions(workflowID), "GetCampaign", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetCampaign workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Campaign retrieval workflow", nil)
	}

	var flowResponse flowv1.GetOperationRunResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Campaign", "GetCampaign")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetCampaign workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Campaign retrieval workflow on Site: %s", unwrapErr), nil)
	}

	run := flowResponse.GetOperationRun()
	if run == nil || run.GetSummary() == nil || run.GetSummary().GetId().GetId() == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Campaign not found", nil)
	}

	apiCampaign := model.NewAPICampaignFromProto(run)
	logger.Info().Str("CampaignID", apiCampaign.ID).Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiCampaign)
}

// ~~~~~ List Campaigns Handler ~~~~~ //

// ListCampaignsHandler is the API Handler for listing Campaigns on a Site.
type ListCampaignsHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewListCampaignsHandler initializes a new ListCampaignsHandler.
func NewListCampaignsHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) ListCampaignsHandler {
	return ListCampaignsHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List Campaigns
// @Description List Campaigns (operation runs) on a Site, newest first, with optional status and operationType filters and pagination.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteId query string true "ID of the Site"
// @Param status query string false "Filter by campaign status"
// @Param operationType query string false "Filter by operation type (PowerControl|FirmwareControl)"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Success 200 {array} model.APICampaign
// @Router /v2/org/{org}/nico/campaign [get]
func (h ListCampaignsHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "List", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	var apiRequest model.APICampaignListRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest, pagination.PageRequest{}); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareCampaignHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	pageRequest := pagination.PageRequest{}
	if err := c.Bind(&pageRequest); err != nil {
		logger.Warn().Err(err).Msg("error binding pagination request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request pagination data", nil)
	}
	if err := pageRequest.Validate(nil); err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	flowRequest, ferr := apiRequest.ToProto(pageRequest)
	if ferr != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, ferr.Error(), nil)
	}

	workflowID := fmt.Sprintf("campaign-list-%s", common.QueryParamHash(apiRequest.QueryValues(pageRequest)))

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, campaignWorkflowOptions(workflowID), "GetAllCampaigns", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetAllCampaigns workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Campaign list workflow", nil)
	}

	var flowResponse flowv1.ListOperationRunsResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Campaign", "GetAllCampaigns")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetAllCampaigns workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Campaign list workflow on Site: %s", unwrapErr), nil)
	}

	apiCampaigns := make([]*model.APICampaign, 0, len(flowResponse.GetOperationRuns()))
	for _, s := range flowResponse.GetOperationRuns() {
		apiCampaigns = append(apiCampaigns, model.NewAPICampaignFromSummary(s))
	}

	total := int(flowResponse.GetTotal())
	pageResponse := pagination.NewPageResponse(*pageRequest.PageNumber, *pageRequest.PageSize, total, pageRequest.OrderByStr)
	pageHeader, err := json.Marshal(pageResponse)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling pagination response")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create pagination response", nil)
	}
	c.Response().Header().Set(pagination.ResponseHeaderName, string(pageHeader))

	logger.Info().Int("Count", len(apiCampaigns)).Int("Total", total).Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiCampaigns)
}

// ~~~~~ List Campaign Targets Handler ~~~~~ //

// ListCampaignTargetsHandler is the API Handler for listing a Campaign's
// per-rack execution targets.
type ListCampaignTargetsHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewListCampaignTargetsHandler initializes a new ListCampaignTargetsHandler.
func NewListCampaignTargetsHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) ListCampaignTargetsHandler {
	return ListCampaignTargetsHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List Campaign targets
// @Description List a Campaign's materialized per-rack execution targets, with optional status and phaseScope filters and pagination. Each target references its Task via taskId.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param siteId query string true "ID of the Site"
// @Param status query string false "Filter by target status"
// @Param phaseScope query string false "Phase scope (currentPhase|completedPhases|currentAndCompletedPhases; default currentPhase)"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Success 200 {array} model.APICampaignTarget
// @Router /v2/org/{org}/nico/campaign/{id}/target [get]
func (h ListCampaignTargetsHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "ListTargets", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	var apiRequest model.APICampaignTargetsListRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest, pagination.PageRequest{}); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareCampaignHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	pageRequest := pagination.PageRequest{}
	if err := c.Bind(&pageRequest); err != nil {
		logger.Warn().Err(err).Msg("error binding pagination request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request pagination data", nil)
	}
	if err := pageRequest.Validate(nil); err != nil {
		logger.Warn().Err(err).Msg("error validating pagination request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to validate pagination request data", err)
	}

	flowRequest := apiRequest.ToProto(campaignID, pageRequest)
	workflowID := fmt.Sprintf("campaign-targets-%s-%s", campaignID, common.QueryParamHash(apiRequest.QueryValues(pageRequest)))

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, campaignWorkflowOptions(workflowID), "GetCampaignTargets", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetCampaignTargets workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Campaign targets workflow", nil)
	}

	var flowResponse flowv1.ListOperationRunTargetsResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Campaign", "GetCampaignTargets")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetCampaignTargets workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Campaign targets workflow on Site: %s", unwrapErr), nil)
	}

	apiTargets := make([]*model.APICampaignTarget, 0, len(flowResponse.GetTargets()))
	for _, t := range flowResponse.GetTargets() {
		apiTargets = append(apiTargets, model.NewAPICampaignTarget(t))
	}

	total := int(flowResponse.GetTotal())
	pageResponse := pagination.NewPageResponse(*pageRequest.PageNumber, *pageRequest.PageSize, total, pageRequest.OrderByStr)
	pageHeader, err := json.Marshal(pageResponse)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling pagination response")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create pagination response", nil)
	}
	c.Response().Header().Set(pagination.ResponseHeaderName, string(pageHeader))

	logger.Info().Int("Count", len(apiTargets)).Int("Total", total).Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiTargets)
}

// ~~~~~ Lifecycle Handlers (pause/resume/advance/cancel) ~~~~~ //

// runCampaignLifecycle executes one OperationRun-returning lifecycle workflow
// and renders the resulting campaign. It centralizes the auth/site prep,
// workflow execution, and error handling shared by pause/resume/advance/cancel.
func runCampaignLifecycle(
	c echo.Context,
	dbSession *cdb.Session,
	scp *sc.ClientPool,
	dbUser *cdbm.User,
	org, siteID, campaignID, action, workflowName string,
	flowRequest any,
	logger zerolog.Logger,
	ctx context.Context,
) error {
	_, stc, apiErr := prepareCampaignHandler(c, dbSession, scp, dbUser, org, siteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	workflowID := fmt.Sprintf("campaign-%s-%s", action, campaignID)

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, campaignWorkflowOptions(workflowID), workflowName, flowRequest)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to schedule %s workflow", workflowName)
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, fmt.Sprintf("Failed to schedule Campaign %s workflow", action), nil)
	}

	var flowResponse flowv1.OperationRun
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Campaign", workflowName)
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msgf("failed to get result from %s workflow", workflowName)
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Campaign %s workflow on Site: %s", action, unwrapErr), nil)
	}

	apiCampaign := model.NewAPICampaignFromProto(&flowResponse)
	logger.Info().Str("CampaignID", apiCampaign.ID).Msg("finishing API handler")
	return c.JSON(http.StatusAccepted, apiCampaign)
}

// campaignLifecycleHandler is the shared dependency set for the campaign
// lifecycle handlers (pause/resume/advance/cancel).
type campaignLifecycleHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

func newCampaignLifecycleHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) campaignLifecycleHandler {
	return campaignLifecycleHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// PauseCampaignHandler pauses a running Campaign.
type PauseCampaignHandler struct{ campaignLifecycleHandler }

// NewPauseCampaignHandler initializes a new PauseCampaignHandler.
func NewPauseCampaignHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) PauseCampaignHandler {
	return PauseCampaignHandler{newCampaignLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Pause a Campaign
// @Description Pause a running Campaign. In-flight target tasks continue; no new targets are claimed until resumed.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param body body model.APICampaignSiteRequest true "Pause campaign request"
// @Success 202 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign/{id}/pause [post]
func (h PauseCampaignHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "Pause", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	apiRequest := model.APICampaignSiteRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: campaignID}}
	return runCampaignLifecycle(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, campaignID, "pause", "PauseCampaign", flowRequest, logger, ctx)
}

// ResumeCampaignHandler resumes an operator-paused Campaign.
type ResumeCampaignHandler struct{ campaignLifecycleHandler }

// NewResumeCampaignHandler initializes a new ResumeCampaignHandler.
func NewResumeCampaignHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) ResumeCampaignHandler {
	return ResumeCampaignHandler{newCampaignLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Resume a Campaign
// @Description Resume an operator-paused Campaign. A Campaign paused at a phase gate must be advanced with the advance endpoint instead.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param body body model.APICampaignSiteRequest true "Resume campaign request"
// @Success 202 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign/{id}/resume [post]
func (h ResumeCampaignHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "Resume", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	apiRequest := model.APICampaignSiteRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: campaignID}}
	return runCampaignLifecycle(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, campaignID, "resume", "ResumeCampaign", flowRequest, logger, ctx)
}

// AdvanceCampaignPhaseHandler opens the next phase of a phase-gated Campaign.
type AdvanceCampaignPhaseHandler struct{ campaignLifecycleHandler }

// NewAdvanceCampaignPhaseHandler initializes a new AdvanceCampaignPhaseHandler.
func NewAdvanceCampaignPhaseHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) AdvanceCampaignPhaseHandler {
	return AdvanceCampaignPhaseHandler{newCampaignLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Advance a Campaign to its next phase
// @Description Open the next phase of a Campaign paused at a phase gate. Optionally guard with expectedPhaseIndex so a stale client cannot advance the wrong phase.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param body body model.APICampaignAdvanceRequest true "Advance campaign request"
// @Success 202 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign/{id}/advance [post]
func (h AdvanceCampaignPhaseHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "AdvancePhase", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	apiRequest := model.APICampaignAdvanceRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.AdvanceOperationRunPhaseRequest{
		Id:                 &flowv1.UUID{Id: campaignID},
		ExpectedPhaseIndex: apiRequest.ExpectedPhaseIndex,
	}
	return runCampaignLifecycle(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, campaignID, "advance", "AdvanceCampaignPhase", flowRequest, logger, ctx)
}

// CancelCampaignHandler cancels a Campaign and its in-flight targets.
type CancelCampaignHandler struct{ campaignLifecycleHandler }

// NewCancelCampaignHandler initializes a new CancelCampaignHandler.
func NewCancelCampaignHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) CancelCampaignHandler {
	return CancelCampaignHandler{newCampaignLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Cancel a Campaign
// @Description Cancel a Campaign. Best-effort cancellation cascades to the current phase's in-flight target tasks.
// @Tags campaign
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Campaign"
// @Param body body model.APICampaignCancelRequest true "Cancel campaign request"
// @Success 202 {object} model.APICampaign
// @Router /v2/org/{org}/nico/campaign/{id}/cancel [post]
func (h CancelCampaignHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Campaign", "Cancel", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	campaignID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("campaign_id", campaignID), logger)
	if _, err := uuid.Parse(campaignID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Campaign ID specified in URL", nil)
	}

	apiRequest := model.APICampaignCancelRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.CancelOperationRunRequest{
		Id:     &flowv1.UUID{Id: campaignID},
		Reason: apiRequest.Reason,
	}
	return runCampaignLifecycle(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, campaignID, "cancel", "CancelCampaign", flowRequest, logger, ctx)
}
