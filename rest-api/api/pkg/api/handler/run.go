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

// prepareRunHandler runs the auth + site lookup + Flow-enabled check +
// Temporal client retrieval shared by every Run handler.
func prepareRunHandler(
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

// runWorkflowOptions returns the standard site-queue workflow options for
// a run action with the given deterministic workflow ID.
func runWorkflowOptions(workflowID string) tClient.StartWorkflowOptions {
	return tClient.StartWorkflowOptions{
		ID:                       workflowID,
		WorkflowIDReusePolicy:    temporalEnums.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
		WorkflowIDConflictPolicy: temporalEnums.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowExecutionTimeout: cutil.WorkflowExecutionTimeout,
		TaskQueue:                queue.SiteTaskQueue,
	}
}

// ~~~~~ Create Run Handler ~~~~~ //

// CreateRunHandler is the API Handler for creating a Run.
type CreateRunHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateRunHandler initializes a new CreateRunHandler.
func NewCreateRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) CreateRunHandler {
	return CreateRunHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Create a Run
// @Description Create a Run: a phased, policy-gated execution of one operation across many racks. The configuration is validated server-side; on validation failure no state changes.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param body body model.APIRunCreateRequest true "Create run request"
// @Success 201 {object} model.APIRun
// @Router /v2/org/{org}/nico/run [post]
func (h CreateRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "Create", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	apiRequest := model.APIRunCreateRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if verr := apiRequest.Validate(); verr != nil {
		logger.Warn().Err(verr).Msg("error validating create run request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, verr.Error(), nil)
	}

	_, stc, apiErr := prepareRunHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	flowRequest, ferr := apiRequest.ToProto()
	if ferr != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, ferr.Error(), nil)
	}

	// Dedicated workflow ID per request so Create is never deduped.
	workflowID := fmt.Sprintf("run-create-%s", uuid.NewString())

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, runWorkflowOptions(workflowID), "CreateRun", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule CreateRun workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Run creation workflow", nil)
	}

	var flowResponse flowv1.CreateOperationRunResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Run", "CreateRun")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from CreateRun workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Run creation workflow on Site: %s", unwrapErr), nil)
	}

	// Flow's CreateOperationRun returns only the new run's ID. Echo the known
	// fields so the client gets the canonical identity without an extra GET; a
	// run always starts Pending. The operation type is firmware (the only
	// supported operation today).
	created := &model.APIRun{
		ID:            flowResponse.GetId().GetId(),
		Name:          apiRequest.Name,
		Description:   apiRequest.Description,
		OperationType: model.APIOperationTypeFirmwareControl,
		Status:        "Pending",
		StatusReason:  "None",
	}

	logger.Info().Str("RunID", created.ID).Msg("finishing API handler")
	return c.JSON(http.StatusCreated, created)
}

// ~~~~~ Get Run Handler ~~~~~ //

// GetRunHandler is the API Handler for getting a Run by ID.
type GetRunHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetRunHandler initializes a new GetRunHandler.
func NewGetRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) GetRunHandler {
	return GetRunHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Get a Run
// @Description Get a Run by UUID. Set includeStats=true for derived per-phase outcome counts.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param siteId query string true "ID of the Site"
// @Param includeStats query boolean false "Include derived per-phase outcome stats (default false)"
// @Success 200 {object} model.APIRun
// @Router /v2/org/{org}/nico/run/{id} [get]
func (h GetRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "Get", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	var apiRequest model.APIRunGetRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareRunHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	flowRequest := &flowv1.GetOperationRunRequest{
		Id:           &flowv1.UUID{Id: runID},
		IncludeStats: apiRequest.IncludeStats,
	}
	workflowID := fmt.Sprintf("run-get-%s", runID)

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, runWorkflowOptions(workflowID), "GetRun", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetRun workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Run retrieval workflow", nil)
	}

	var flowResponse flowv1.GetOperationRunResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Run", "GetRun")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetRun workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Run retrieval workflow on Site: %s", unwrapErr), nil)
	}

	run := flowResponse.GetOperationRun()
	if run == nil || run.GetSummary() == nil || run.GetSummary().GetId().GetId() == "" {
		return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Run not found", nil)
	}

	apiRun := model.NewAPIRunFromProto(run)
	logger.Info().Str("RunID", apiRun.ID).Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiRun)
}

// ~~~~~ List Runs Handler ~~~~~ //

// GetAllRunHandler is the API Handler for listing Runs on a Site.
type GetAllRunHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllRunHandler initializes a new GetAllRunHandler.
func NewGetAllRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) GetAllRunHandler {
	return GetAllRunHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List Runs
// @Description List Runs (operation runs) on a Site, newest first, with optional status and operationType filters and pagination.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param siteId query string true "ID of the Site"
// @Param status query string false "Filter by run status"
// @Param operationType query string false "Filter by operation type (PowerControl|FirmwareControl)"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Success 200 {array} model.APIRun
// @Router /v2/org/{org}/nico/run [get]
func (h GetAllRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "List", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	var apiRequest model.APIRunGetAllRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest, pagination.PageRequest{}); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareRunHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
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

	workflowID := fmt.Sprintf("run-list-%s", common.QueryParamHash(apiRequest.QueryValues(pageRequest)))

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, runWorkflowOptions(workflowID), "GetAllRuns", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetAllRuns workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Run list workflow", nil)
	}

	var flowResponse flowv1.ListOperationRunsResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Run", "GetAllRuns")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetAllRuns workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Run list workflow on Site: %s", unwrapErr), nil)
	}

	apiRuns := make([]*model.APIRun, 0, len(flowResponse.GetOperationRuns()))
	for _, s := range flowResponse.GetOperationRuns() {
		apiRuns = append(apiRuns, model.NewAPIRunFromSummary(s))
	}

	total := int(flowResponse.GetTotal())
	pageResponse := pagination.NewPageResponse(*pageRequest.PageNumber, *pageRequest.PageSize, total, pageRequest.OrderByStr)
	pageHeader, err := json.Marshal(pageResponse)
	if err != nil {
		logger.Error().Err(err).Msg("error marshaling pagination response")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to create pagination response", nil)
	}
	c.Response().Header().Set(pagination.ResponseHeaderName, string(pageHeader))

	logger.Info().Int("Count", len(apiRuns)).Int("Total", total).Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiRuns)
}

// ~~~~~ List Run Targets Handler ~~~~~ //

// GetRunTargetsHandler is the API Handler for listing a Run's
// per-rack execution targets.
type GetRunTargetsHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetRunTargetsHandler initializes a new GetRunTargetsHandler.
func NewGetRunTargetsHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) GetRunTargetsHandler {
	return GetRunTargetsHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List Run targets
// @Description List a Run's materialized per-rack execution targets, with optional status and phaseScope filters and pagination. Each target references its Task via taskId.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param siteId query string true "ID of the Site"
// @Param status query string false "Filter by target status"
// @Param phaseScope query string false "Phase scope (currentPhase|completedPhases|currentAndCompletedPhases; default currentPhase)"
// @Param pageNumber query integer false "Page number of results returned"
// @Param pageSize query integer false "Number of results per page"
// @Success 200 {array} model.APIRunTarget
// @Router /v2/org/{org}/nico/run/{id}/target [get]
func (h GetRunTargetsHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "ListTargets", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	var apiRequest model.APIRunTargetGetAllRequest
	if err := common.ValidateKnownQueryParams(c.QueryParams(), apiRequest, pagination.PageRequest{}); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	_, stc, apiErr := prepareRunHandler(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, logger, ctx)
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

	flowRequest := apiRequest.ToProto(runID, pageRequest)
	workflowID := fmt.Sprintf("run-targets-%s-%s", runID, common.QueryParamHash(apiRequest.QueryValues(pageRequest)))

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, runWorkflowOptions(workflowID), "GetRunTargets", flowRequest)
	if err != nil {
		logger.Error().Err(err).Msg("failed to schedule GetRunTargets workflow")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to schedule Run targets workflow", nil)
	}

	var flowResponse flowv1.ListOperationRunTargetsResponse
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Run", "GetRunTargets")
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msg("failed to get result from GetRunTargets workflow")
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Run targets workflow on Site: %s", unwrapErr), nil)
	}

	apiTargets := make([]*model.APIRunTarget, 0, len(flowResponse.GetTargets()))
	for _, t := range flowResponse.GetTargets() {
		apiTargets = append(apiTargets, model.NewAPIRunTarget(t))
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

// executeRunLifecycleWorkflow executes one OperationRun-returning lifecycle workflow
// and renders the resulting run. It centralizes the auth/site prep,
// workflow execution, and error handling shared by pause/resume/advance/cancel.
func executeRunLifecycleWorkflow(
	c echo.Context,
	dbSession *cdb.Session,
	scp *sc.ClientPool,
	dbUser *cdbm.User,
	org, siteID, runID, action, workflowName string,
	flowRequest any,
	logger zerolog.Logger,
	ctx context.Context,
) error {
	_, stc, apiErr := prepareRunHandler(c, dbSession, scp, dbUser, org, siteID, logger, ctx)
	if apiErr != nil {
		return cutil.NewAPIErrorResponse(c, apiErr.Code, apiErr.Message, apiErr.Data)
	}

	workflowID := fmt.Sprintf("run-%s-%s", action, runID)

	wfCtx, cancel := context.WithTimeout(ctx, cutil.WorkflowContextTimeout)
	defer cancel()

	we, err := stc.ExecuteWorkflow(wfCtx, runWorkflowOptions(workflowID), workflowName, flowRequest)
	if err != nil {
		logger.Error().Err(err).Msgf("failed to schedule %s workflow", workflowName)
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, fmt.Sprintf("Failed to schedule Run %s workflow", action), nil)
	}

	var flowResponse flowv1.OperationRun
	if err := we.Get(wfCtx, &flowResponse); err != nil {
		var timeoutErr *tp.TimeoutError
		if errors.As(err, &timeoutErr) || err == context.DeadlineExceeded || wfCtx.Err() != nil {
			return common.TerminateWorkflowOnTimeOut(c, logger, stc, workflowID, err, "Run", workflowName)
		}
		code, unwrapErr := common.UnwrapWorkflowError(err)
		logger.Error().Err(unwrapErr).Msgf("failed to get result from %s workflow", workflowName)
		return cutil.NewAPIErrorResponse(c, code, fmt.Sprintf("Failed to execute Run %s workflow on Site: %s", action, unwrapErr), nil)
	}

	apiRun := model.NewAPIRunFromProto(&flowResponse)
	logger.Info().Str("RunID", apiRun.ID).Msg("finishing API handler")
	return c.JSON(http.StatusAccepted, apiRun)
}

// runLifecycleHandler is the shared dependency set for the run
// lifecycle handlers (pause/resume/advance/cancel).
type runLifecycleHandler struct {
	dbSession  *cdb.Session
	tc         tClient.Client
	scp        *sc.ClientPool
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

func newRunLifecycleHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) runLifecycleHandler {
	return runLifecycleHandler{
		dbSession:  dbSession,
		tc:         tc,
		scp:        scp,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// PauseRunHandler pauses a running Run.
type PauseRunHandler struct{ runLifecycleHandler }

// NewPauseRunHandler initializes a new PauseRunHandler.
func NewPauseRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) PauseRunHandler {
	return PauseRunHandler{newRunLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Pause a Run
// @Description Pause a running Run. In-flight target tasks continue; no new targets are claimed until resumed.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param body body model.APIRunSiteRequest true "Pause run request"
// @Success 202 {object} model.APIRun
// @Router /v2/org/{org}/nico/run/{id}/pause [post]
func (h PauseRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "Pause", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	apiRequest := model.APIRunSiteRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.PauseOperationRunRequest{Id: &flowv1.UUID{Id: runID}}
	return executeRunLifecycleWorkflow(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, runID, "pause", "PauseRun", flowRequest, logger, ctx)
}

// ResumeRunHandler resumes an operator-paused Run.
type ResumeRunHandler struct{ runLifecycleHandler }

// NewResumeRunHandler initializes a new ResumeRunHandler.
func NewResumeRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) ResumeRunHandler {
	return ResumeRunHandler{newRunLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Resume a Run
// @Description Resume an operator-paused Run. A Run paused at a phase gate must be advanced with the advance endpoint instead.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param body body model.APIRunSiteRequest true "Resume run request"
// @Success 202 {object} model.APIRun
// @Router /v2/org/{org}/nico/run/{id}/resume [post]
func (h ResumeRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "Resume", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	apiRequest := model.APIRunSiteRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.ResumeOperationRunRequest{Id: &flowv1.UUID{Id: runID}}
	return executeRunLifecycleWorkflow(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, runID, "resume", "ResumeRun", flowRequest, logger, ctx)
}

// AdvanceRunPhaseHandler opens the next phase of a phase-gated Run.
type AdvanceRunPhaseHandler struct{ runLifecycleHandler }

// NewAdvanceRunPhaseHandler initializes a new AdvanceRunPhaseHandler.
func NewAdvanceRunPhaseHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) AdvanceRunPhaseHandler {
	return AdvanceRunPhaseHandler{newRunLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Advance a Run to its next phase
// @Description Open the next phase of a Run paused at a phase gate. Optionally guard with expectedPhaseIndex so a stale client cannot advance the wrong phase.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param body body model.APIRunAdvanceRequest true "Advance run request"
// @Success 202 {object} model.APIRun
// @Router /v2/org/{org}/nico/run/{id}/advance [post]
func (h AdvanceRunPhaseHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "AdvancePhase", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	apiRequest := model.APIRunAdvanceRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.AdvanceOperationRunPhaseRequest{
		Id:                 &flowv1.UUID{Id: runID},
		ExpectedPhaseIndex: apiRequest.ExpectedPhaseIndex,
	}
	return executeRunLifecycleWorkflow(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, runID, "advance", "AdvanceRunPhase", flowRequest, logger, ctx)
}

// CancelRunHandler cancels a Run and its in-flight targets.
type CancelRunHandler struct{ runLifecycleHandler }

// NewCancelRunHandler initializes a new CancelRunHandler.
func NewCancelRunHandler(dbSession *cdb.Session, tc tClient.Client, scp *sc.ClientPool, cfg *config.Config) CancelRunHandler {
	return CancelRunHandler{newRunLifecycleHandler(dbSession, tc, scp, cfg)}
}

// Handle godoc
// @Summary Cancel a Run
// @Description Cancel a Run. Best-effort cancellation cascades to the current phase's in-flight target tasks.
// @Tags run
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param id path string true "UUID of the Run"
// @Param body body model.APIRunCancelRequest true "Cancel run request"
// @Success 202 {object} model.APIRun
// @Router /v2/org/{org}/nico/run/{id}/cancel [post]
func (h CancelRunHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Run", "Cancel", c, h.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}

	runID := c.Param("id")
	h.tracerSpan.SetAttribute(handlerSpan, attribute.String("run_id", runID), logger)
	if _, err := uuid.Parse(runID); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Run ID specified in URL", nil)
	}

	apiRequest := model.APIRunCancelRequest{}
	if err := c.Bind(&apiRequest); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data", nil)
	}
	if err := apiRequest.Validate(); err != nil {
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, err.Error(), nil)
	}

	flowRequest := &flowv1.CancelOperationRunRequest{
		Id:     &flowv1.UUID{Id: runID},
		Reason: apiRequest.Reason,
	}
	return executeRunLifecycleWorkflow(c, h.dbSession, h.scp, dbUser, org, apiRequest.SiteID, runID, "cancel", "CancelRun", flowRequest, logger, ctx)
}
