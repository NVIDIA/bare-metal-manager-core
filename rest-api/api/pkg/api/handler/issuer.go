// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/NVIDIA/infra-controller/rest-api/api/internal/config"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/handler/util/common"
	"github.com/NVIDIA/infra-controller/rest-api/api/pkg/api/model"
	auth "github.com/NVIDIA/infra-controller/rest-api/auth/pkg/authorization"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
)

// issuerOrgMappingLockKey serializes all Issuer mutations that can change the
// global organization-mapping invariant.
const issuerOrgMappingLockKey = "issuer:organization-mapping-namespace"

// issuerAPIUnavailableMessage is returned by every Issuer endpoint when the
// static configuration owns issuer trust: Keycloak is a privileged built-in IdP,
// and a dynamic ConfigMap issuer lets the token pick its own org. In both cases
// operators configure auth through the ConfigMap issuers block instead.
const issuerAPIUnavailableMessage = "Issuer management via the API is unavailable while Keycloak is enabled or the static configuration " +
	"defines a dynamic issuer (orgAttribute, orgDisplayAttribute, or rolesAttribute claim mapping). " +
	"Disable Keycloak and remove dynamic claim mappings from the ConfigMap issuers block to manage static custom Issuers via the API."

// ~~~~~ Create Handler ~~~~~ //

// CreateIssuerHandler is the API Handler for creating a new Issuer. Created
// Issuers always have origin=custom, and create is rejected when the static
// ConfigMap issuers block contains keycloak, kas-legacy, or kas-ssa origins.
type CreateIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewCreateIssuerHandler initializes and returns a new handler for creating Issuer
func NewCreateIssuerHandler(dbSession *cdb.Session, cfg *config.Config) CreateIssuerHandler {
	return CreateIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Register an external JWT issuer
// @Description Register a runtime-managed external JWT issuer (Provider Admin only)
// @Tags issuer
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param issuer body model.APIIssuerCreateRequest true "Issuer to create"
// @Success 201 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer [put]
func (cih CreateIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Create", c, cih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Issuer creation is only supported in disconnected mode
	if !cih.cfg.GetEnvDisconnected() {
		logger.Warn().Msg("Issuer creation is only supported in disconnected mode")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Issuer management via the API is only supported in disconnected mode", nil)
	}

	// Validate that the static configuration does not own issuer trust
	if cih.cfg.GetKeycloakEnabled() || cih.cfg.HasDynamicConfigMapIssuers() {
		logger.Warn().Msg("Issuer API is unavailable, static configuration owns issuer trust")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, issuerAPIUnavailableMessage, nil)
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

	// Validate role, Issuer management is a provider-level trust operation so only Provider Admins are allowed
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	// Validate request
	// Bind request data to API model
	apiRequest := model.APIIssuerCreateRequest{}
	err = c.Bind(&apiRequest)
	if err != nil {
		logger.Warn().Err(err).Msg("error binding request data into API model")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Failed to parse request data, potentially invalid structure", nil)
	}

	// Validate request attributes
	verr := apiRequest.Validate()
	if verr != nil {
		logger.Warn().Err(verr).Msg("error validating Issuer creation request data")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, verr.Error(), nil)
	}

	// A custom Issuer may not join a trust plane owned by a privileged IdP
	if cih.cfg.HasPrivilegedStaticIssuerOrigins() {
		logger.Warn().Msg("static configuration defines privileged issuer origins, cannot create custom Issuer")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest,
			"Cannot add a custom Issuer while keycloak, kas-legacy, or kas-ssa issuers are defined in the static configuration. "+
				"Remove those issuers from the ConfigMap issuers block first.", nil)
	}

	createInput := apiRequest.ToCreateInput(&dbUser.ID)

	// Static ConfigMap issuers always win, a runtime-managed Issuer may not claim their URL or name
	if cih.cfg.IsStaticIssuer(createInput.IssuerURL, createInput.Name) {
		logger.Warn().Str("issuer", createInput.IssuerURL).Msg("Issuer URL or name is reserved by a statically-configured issuer")
		return cutil.NewAPIErrorResponse(c, http.StatusConflict, "Issuer URL or name is reserved by a statically-configured issuer", nil)
	}

	issuerDAO := cdbm.NewIssuerDAO(cih.dbSession)

	issuer, err := cdb.WithTxResult(ctx, cih.dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
		// acquire an advisory lock on the Issuer organization mapping on which there could be contention
		// this lock is released when the transaction commits or rollsback
		derr := tx.AcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(issuerOrgMappingLockKey), true)
		if derr != nil {
			logger.Error().Err(derr).Msg("Failed to acquire advisory lock on Issuer organization mapping")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Issuer, could not acquire data store lock on Issuers", nil)
		}

		// Validate the Issuer being created against the combined static and DB issuer set
		candidate := createInput.ToIssuer()
		derr = cih.cfg.ValidateCombinedIssuers(ctx, cih.dbSession, tx, &candidate, nil)
		if derr != nil {
			logger.Warn().Err(derr).Msg("Issuer is not valid against the combined issuer set")
			return nil, cutil.NewAPIError(http.StatusBadRequest, fmt.Sprintf("Invalid issuer configuration: %s", derr), nil)
		}

		createdIssuer, derr := issuerDAO.Create(ctx, tx, createInput)
		if derr != nil {
			if (&cdb.PostgresErrorChecker{}).IsUniqueConstraintError(derr) {
				logger.Warn().Err(derr).Msg("Issuer with URL or name already exists")
				return nil, cutil.NewAPIError(http.StatusConflict, "An Issuer with this URL or name already exists", nil)
			}
			logger.Error().Err(derr).Msg("error creating Issuer record in DB")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to create Issuer", nil)
		}
		return createdIssuer, nil
	})
	if err != nil {
		return common.HandleTxError(c, logger, err, "Failed to create Issuer, DB transaction error")
	}

	// Apply to the live registry on this replica (read-your-write). Other replicas
	// converge on their next periodic reload.
	rerr := cih.cfg.ReloadDBIssuers(ctx, cih.dbSession)
	if rerr != nil {
		logger.Warn().Err(rerr).Msg("Issuer created but live registry reload failed, will converge on next reload")
	}

	// Create response
	logger.Info().Str("issuer", issuer.IssuerURL).Msg("finishing API handler")
	return c.JSON(http.StatusCreated, model.NewAPIIssuer(issuer))
}

// ~~~~~ GetAll Handler ~~~~~ //

// GetAllIssuerHandler is the API Handler for getting all Issuers of the provider
type GetAllIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetAllIssuerHandler initializes and returns a new handler for getting all Issuers
func NewGetAllIssuerHandler(dbSession *cdb.Session, cfg *config.Config) GetAllIssuerHandler {
	return GetAllIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary List external JWT issuers
// @Description List the provider's runtime-managed external JWT issuers (Provider Admin only)
// @Tags issuer
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Success 200 {object} []model.APIIssuer
// @Router /v2/org/{org}/nico/issuer [get]
func (gaih GetAllIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "GetAll", c, gaih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Issuer API is only supported in disconnected mode
	if !gaih.cfg.GetEnvDisconnected() {
		logger.Warn().Msg("Issuer API is only supported in disconnected mode")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Issuer management via the API is only supported in disconnected mode", nil)
	}

	// Validate that the static configuration does not own issuer trust
	if gaih.cfg.GetKeycloakEnabled() || gaih.cfg.HasDynamicConfigMapIssuers() {
		logger.Warn().Msg("Issuer API is unavailable, static configuration owns issuer trust")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, issuerAPIUnavailableMessage, nil)
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

	// Validate role, Issuer management is a provider-level trust operation so only Provider Admins are allowed
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	issuerDAO := cdbm.NewIssuerDAO(gaih.dbSession)
	issuers, err := issuerDAO.GetAll(ctx, nil, cdbm.IssuerFilterInput{})
	if err != nil {
		logger.Error().Err(err).Msg("error retrieving Issuers from DB")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Issuers, DB error", nil)
	}

	// Create response
	apiIssuers := []*model.APIIssuer{}
	for i := range issuers {
		apiIssuers = append(apiIssuers, model.NewAPIIssuer(&issuers[i]))
	}

	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, apiIssuers)
}

// ~~~~~ Get Handler ~~~~~ //

// GetIssuerHandler is the API Handler for retrieving an Issuer
type GetIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewGetIssuerHandler initializes and returns a new handler to retrieve Issuer
func NewGetIssuerHandler(dbSession *cdb.Session, cfg *config.Config) GetIssuerHandler {
	return GetIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Retrieve an external JWT issuer
// @Description Retrieve a runtime-managed external JWT issuer by ID (Provider Admin only)
// @Tags issuer
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param issuerId path string true "ID of the issuer"
// @Success 200 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer/{issuerId} [get]
func (gih GetIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Get", c, gih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Issuer API is only supported in disconnected mode
	if !gih.cfg.GetEnvDisconnected() {
		logger.Warn().Msg("Issuer API is only supported in disconnected mode")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Issuer management via the API is only supported in disconnected mode", nil)
	}

	// Validate that the static configuration does not own issuer trust
	if gih.cfg.GetKeycloakEnabled() || gih.cfg.HasDynamicConfigMapIssuers() {
		logger.Warn().Msg("Issuer API is unavailable, static configuration owns issuer trust")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, issuerAPIUnavailableMessage, nil)
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

	// Validate role, Issuer management is a provider-level trust operation so only Provider Admins are allowed
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	// Get Issuer ID from URL param
	issuerStrID := c.Param("issuerId")
	issuerID, err := uuid.Parse(issuerStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Issuer ID in URL", nil)
	}

	issuerDAO := cdbm.NewIssuerDAO(gih.dbSession)
	issuer, err := issuerDAO.GetByID(ctx, nil, issuerID)
	if err != nil {
		if err == cdb.ErrDoesNotExist {
			return cutil.NewAPIErrorResponse(c, http.StatusNotFound, "Issuer not found", nil)
		}
		logger.Error().Err(err).Msg("error retrieving Issuer DB entity")
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve Issuer, DB error", nil)
	}

	// Send response
	logger.Info().Msg("finishing API handler")
	return c.JSON(http.StatusOK, model.NewAPIIssuer(issuer))
}

// ~~~~~ Delete Handler ~~~~~ //

// DeleteIssuerHandler is the API Handler for deleting an Issuer
type DeleteIssuerHandler struct {
	dbSession  *cdb.Session
	cfg        *config.Config
	tracerSpan *cutil.TracerSpan
}

// NewDeleteIssuerHandler initializes and returns a new handler for deleting Issuer
func NewDeleteIssuerHandler(dbSession *cdb.Session, cfg *config.Config) DeleteIssuerHandler {
	return DeleteIssuerHandler{
		dbSession:  dbSession,
		cfg:        cfg,
		tracerSpan: cutil.NewTracerSpan(),
	}
}

// Handle godoc
// @Summary Delete an external JWT issuer
// @Description Delete a runtime-managed external JWT issuer and withdraw its trust (Provider Admin only)
// @Tags issuer
// @Produce json
// @Security ApiKeyAuth
// @Param org path string true "Name of NGC organization"
// @Param issuerId path string true "ID of the issuer"
// @Success 200 {object} model.APIIssuer
// @Router /v2/org/{org}/nico/issuer/{issuerId} [delete]
func (dih DeleteIssuerHandler) Handle(c echo.Context) error {
	org, dbUser, ctx, logger, handlerSpan := common.SetupHandler("Issuer", "Delete", c, dih.tracerSpan)
	if handlerSpan != nil {
		defer handlerSpan.End()
	}
	if dbUser == nil {
		return cutil.NewAPIErrorResponse(c, http.StatusInternalServerError, "Failed to retrieve current user", nil)
	}

	// Issuer API is only supported in disconnected mode
	if !dih.cfg.GetEnvDisconnected() {
		logger.Warn().Msg("Issuer API is only supported in disconnected mode")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Issuer management via the API is only supported in disconnected mode", nil)
	}

	// Validate that the static configuration does not own issuer trust
	if dih.cfg.GetKeycloakEnabled() || dih.cfg.HasDynamicConfigMapIssuers() {
		logger.Warn().Msg("Issuer API is unavailable, static configuration owns issuer trust")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, issuerAPIUnavailableMessage, nil)
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

	// Validate role, Issuer management is a provider-level trust operation so only Provider Admins are allowed
	ok = auth.ValidateUserRoles(dbUser, org, nil, auth.ProviderAdminRole)
	if !ok {
		logger.Warn().Msg("user does not have Provider Admin role, access denied")
		return cutil.NewAPIErrorResponse(c, http.StatusForbidden, "User does not have Provider Admin role with org", nil)
	}

	// Get Issuer ID from URL param
	issuerStrID := c.Param("issuerId")
	issuerID, err := uuid.Parse(issuerStrID)
	if err != nil {
		logger.Warn().Err(err).Msg("error parsing id in url into uuid")
		return cutil.NewAPIErrorResponse(c, http.StatusBadRequest, "Invalid Issuer ID in URL", nil)
	}

	issuerDAO := cdbm.NewIssuerDAO(dih.dbSession)

	issuer, err := cdb.WithTxResult(ctx, dih.dbSession, func(tx *cdb.Tx) (*cdbm.Issuer, error) {
		// acquire an advisory lock on the Issuer organization mapping on which there could be contention
		// this lock is released when the transaction commits or rollsback
		derr := tx.AcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(issuerOrgMappingLockKey), true)
		if derr != nil {
			logger.Error().Err(derr).Msg("Failed to acquire advisory lock on Issuer organization mapping")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Issuer, could not acquire data store lock on Issuers", nil)
		}

		// Check that the Issuer exists, it is read under the lock so a concurrent
		// delete or update cannot slip in between the check and the write
		existing, derr := issuerDAO.GetByID(ctx, tx, issuerID)
		if derr != nil {
			if derr == cdb.ErrDoesNotExist {
				return nil, cutil.NewAPIError(http.StatusNotFound, "Issuer not found", nil)
			}
			logger.Error().Err(derr).Msg("error retrieving Issuer DB entity")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to retrieve Issuer to delete, DB error", nil)
		}

		// Validate the issuer set that remains after this Issuer is withdrawn
		derr = dih.cfg.ValidateCombinedIssuers(ctx, dih.dbSession, tx, nil, &issuerID)
		if derr != nil {
			logger.Warn().Err(derr).Msg("remaining issuer set is not valid without this Issuer")
			return nil, cutil.NewAPIError(http.StatusBadRequest, fmt.Sprintf("Invalid issuer configuration: %s", derr), nil)
		}

		derr = issuerDAO.Delete(ctx, tx, issuerID)
		if derr != nil {
			logger.Error().Err(derr).Msg("error deleting Issuer record in DB")
			return nil, cutil.NewAPIError(http.StatusInternalServerError, "Failed to delete Issuer", nil)
		}
		return existing, nil
	})
	if err != nil {
		return common.HandleTxError(c, logger, err, "Failed to delete Issuer, DB transaction error")
	}

	// Withdraw trust from the live registry on this replica. Other replicas
	// converge on their next periodic reload.
	rerr := dih.cfg.ReloadDBIssuers(ctx, dih.dbSession)
	if rerr != nil {
		logger.Warn().Err(rerr).Msg("Issuer deleted but live registry reload failed, will converge on next reload")
	}

	// Create response
	logger.Info().Str("issuer", issuer.IssuerURL).Msg("finishing API handler")
	return c.JSON(http.StatusOK, model.NewAPIIssuer(issuer))
}
