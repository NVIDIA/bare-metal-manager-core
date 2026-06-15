/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package operatingsystem

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"go.temporal.io/sdk/client"
	tp "go.temporal.io/sdk/temporal"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	cdbp "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/paginator"
	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"

	sc "github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/client/site"
	"github.com/NVIDIA/infra-controller/rest-api/workflow/pkg/queue"

	cwssaws "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/schema/site-agent/workflows/v1"

	swe "github.com/NVIDIA/infra-controller/rest-api/site-workflow/pkg/error"

	cwutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
)

// TODO: Retire these activities and workflows

// ManageOperatingSystemPush is an activity wrapper for pushing Operating System
// changes (create/update/delete) from REST to nico-core via per-site workflows.
type ManageOperatingSystemPush struct {
	dbSession      *cdb.Session
	siteClientPool *sc.ClientPool
}

// NewManageOperatingSystemPush returns a new ManageOperatingSystemPush activity.
func NewManageOperatingSystemPush(dbSession *cdb.Session, siteClientPool *sc.ClientPool) ManageOperatingSystemPush {
	return ManageOperatingSystemPush{
		dbSession:      dbSession,
		siteClientPool: siteClientPool,
	}
}

// SynchronizeOperatingSystemToSites propagates an OS create/update/delete to all
// associated sites. Individual site failures are logged but do not abort the loop.
func (mop ManageOperatingSystemPush) SynchronizeOperatingSystemToSites(ctx context.Context, osID uuid.UUID, operation string) error {
	logger := log.With().Str("Activity", "SynchronizeOperatingSystemToSites").
		Str("OS ID", osID.String()).Str("Operation", operation).Logger()
	logger.Info().Msg("starting activity")

	osDAO := cdbm.NewOperatingSystemDAO(mop.dbSession)

	os, err := osDAO.GetByID(ctx, nil, osID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			if operation == "Delete" {
				logger.Info().Msg("Operating System not found, already deleted — nothing to do")
				return nil
			}
			logger.Warn().Msg("Operating System not yet visible — will retry")
			return err
		}
		logger.Error().Err(err).Msg("failed to retrieve Operating System from DB")
		return err
	}

	switch operation {
	case "Create":
		return mop.synchronizeCreate(ctx, logger, os)
	case "Update":
		return mop.synchronizeUpdate(ctx, logger, os)
	case "Delete":
		return mop.synchronizeDelete(ctx, logger, os)
	default:
		logger.Error().Str("Operation", operation).Msg("unknown synchronization operation")
		return errors.New("unknown synchronization operation: " + operation)
	}
}

func (mop ManageOperatingSystemPush) synchronizeCreate(ctx context.Context, logger zerolog.Logger, os *cdbm.OperatingSystem) error {
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mop.dbSession)
	ossas, _, err := ossaDAO.GetAll(ctx, nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve OSSAs from DB")
		return err
	}

	if len(ossas) == 0 {
		logger.Info().Msg("no site associations, nothing to synchronize")
		return nil
	}

	request := mop.buildCreateRequest(os)
	siteErrors := 0

	for _, ossa := range ossas {
		slogger := logger.With().Str("Site ID", ossa.SiteID.String()).Logger()

		if os.Type == cdbm.OperatingSystemTypeTemplatedIPXE {
			if skip := mop.checkTemplateAvailability(ctx, slogger, ossa.SiteID, os); skip {
				continue
			}
		}

		stc, cerr := mop.siteClientPool.GetClientByID(ossa.SiteID)
		if cerr != nil {
			slogger.Error().Err(cerr).Msg("failed to retrieve Temporal client for Site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "failed to connect to site")
			siteErrors++
			continue
		}

		workflowOptions := client.StartWorkflowOptions{
			ID:                       "templated-ipxe-os-create-" + ossa.SiteID.String() + "-" + os.ID.String(),
			WorkflowExecutionTimeout: cwutil.WorkflowExecutionTimeout,
			TaskQueue:                queue.SiteTaskQueue,
		}

		slogger.Info().Msg("triggering CreateOperatingSystem workflow on site")
		we, werr := stc.ExecuteWorkflow(ctx, workflowOptions, "CreateOperatingSystem", request)
		if werr != nil {
			slogger.Error().Err(werr).Msg("failed to start CreateOperatingSystem workflow on site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "failed to start create workflow on site")
			siteErrors++
			continue
		}

		if werr = we.Get(ctx, nil); werr != nil {
			slogger.Error().Err(werr).Msg("CreateOperatingSystem workflow failed on site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "create workflow failed on site")
			siteErrors++
			continue
		}

		slogger.Info().Msg("CreateOperatingSystem workflow completed on site")
		mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusSynced, "Operating System successfully created on site")
	}

	mop.updateAggregateOSStatus(ctx, logger, os, siteErrors > 0)
	return nil
}

func (mop ManageOperatingSystemPush) synchronizeUpdate(ctx context.Context, logger zerolog.Logger, os *cdbm.OperatingSystem) error {
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mop.dbSession)

	if err := mop.expandGlobalScopeAssociations(ctx, logger, os, ossaDAO); err != nil {
		return err
	}

	ossas, _, err := ossaDAO.GetAll(ctx, nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve OSSAs from DB")
		return err
	}

	if len(ossas) == 0 {
		logger.Info().Msg("no site associations, nothing to synchronize")
		return nil
	}

	request := mop.buildUpdateRequest(os)
	siteErrors := 0

	for _, ossa := range ossas {
		slogger := logger.With().Str("Site ID", ossa.SiteID.String()).Logger()

		if os.Type == cdbm.OperatingSystemTypeTemplatedIPXE {
			if skip := mop.checkTemplateAvailability(ctx, slogger, ossa.SiteID, os); skip {
				continue
			}
		}

		mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusSyncing, "received Operating System update, syncing to site")
		if _, verr := ossaDAO.GenerateAndUpdateVersion(ctx, nil, ossa.ID); verr != nil {
			slogger.Error().Err(verr).Msg("failed to update OSSA version")
		}

		stc, cerr := mop.siteClientPool.GetClientByID(ossa.SiteID)
		if cerr != nil {
			slogger.Error().Err(cerr).Msg("failed to retrieve Temporal client for Site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "failed to connect to site")
			siteErrors++
			continue
		}

		workflowOptions := client.StartWorkflowOptions{
			ID:                       "ipxe-os-update-" + ossa.SiteID.String() + "-" + os.ID.String(),
			WorkflowExecutionTimeout: cwutil.WorkflowExecutionTimeout,
			TaskQueue:                queue.SiteTaskQueue,
		}

		slogger.Info().Msg("triggering UpdateOperatingSystem workflow on site")
		we, werr := stc.ExecuteWorkflow(ctx, workflowOptions, "UpdateOperatingSystem", request)
		if werr != nil {
			slogger.Error().Err(werr).Msg("failed to start UpdateOperatingSystem workflow on site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "failed to start update workflow on site")
			siteErrors++
			continue
		}

		if werr = we.Get(ctx, nil); werr != nil {
			slogger.Error().Err(werr).Msg("UpdateOperatingSystem workflow failed on site")
			mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusError, "update workflow failed on site")
			siteErrors++
			continue
		}

		slogger.Info().Msg("UpdateOperatingSystem workflow completed on site")
		mop.updateOSSAStatus(ctx, slogger, ossaDAO, ossa.ID, cdbm.OperatingSystemSiteAssociationStatusSynced, "Operating System successfully updated on site")
	}

	mop.updateAggregateOSStatus(ctx, logger, os, siteErrors > 0)
	return nil
}

func (mop ManageOperatingSystemPush) synchronizeDelete(ctx context.Context, logger zerolog.Logger, os *cdbm.OperatingSystem) error {
	ossaDAO := cdbm.NewOperatingSystemSiteAssociationDAO(mop.dbSession)
	ossas, _, err := ossaDAO.GetAll(ctx, nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve OSSAs from DB")
		return err
	}

	if len(ossas) == 0 {
		logger.Info().Msg("no site associations, soft-deleting OS directly")
		osDAO := cdbm.NewOperatingSystemDAO(mop.dbSession)
		if derr := osDAO.Delete(ctx, nil, os.ID); derr != nil {
			logger.Error().Err(derr).Msg("failed to soft-delete Operating System")
			return derr
		}
		return nil
	}

	deleteRequest := &cwssaws.DeleteOperatingSystemRequest{
		Id: &cwssaws.OperatingSystemId{Value: os.ID.String()},
	}

	for _, ossa := range ossas {
		slogger := logger.With().Str("Site ID", ossa.SiteID.String()).Logger()

		stc, cerr := mop.siteClientPool.GetClientByID(ossa.SiteID)
		if cerr != nil {
			slogger.Error().Err(cerr).Msg("failed to retrieve Temporal client for Site")
			continue
		}

		workflowOptions := client.StartWorkflowOptions{
			ID:        "ipxe-os-delete-" + ossa.SiteID.String() + "-" + os.ID.String(),
			TaskQueue: queue.SiteTaskQueue,
		}

		slogger.Info().Msg("triggering DeleteOperatingSystem workflow on site")
		we, werr := stc.ExecuteWorkflow(ctx, workflowOptions, "DeleteOperatingSystem", deleteRequest)
		if werr != nil {
			slogger.Error().Err(werr).Msg("failed to start DeleteOperatingSystem workflow on site")
			continue
		}

		werr = we.Get(ctx, nil)
		if werr != nil {
			var applicationErr *tp.ApplicationError
			if errors.As(werr, &applicationErr) && applicationErr.Type() == swe.ErrTypeCarbideObjectNotFound {
				slogger.Warn().Msg("CarbideObjectNotFound on delete, treating as success")
				werr = nil
			}
		}
		if werr != nil {
			slogger.Error().Err(werr).Msg("DeleteOperatingSystem workflow failed on site")
			continue
		}

		slogger.Info().Msg("DeleteOperatingSystem workflow completed on site")
		if derr := ossaDAO.Delete(ctx, nil, ossa.ID); derr != nil {
			slogger.Error().Err(derr).Msg("failed to delete OSSA after successful site delete")
		}
	}

	// Check if all associations have been cleaned up; if so, soft-delete the OS.
	remaining, _, err := ossaDAO.GetAll(ctx, nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
		cdbp.PageInput{Limit: cutil.GetPtr(1)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to check remaining OSSAs after delete")
		return err
	}

	osDAO := cdbm.NewOperatingSystemDAO(mop.dbSession)
	if len(remaining) == 0 {
		if derr := osDAO.Delete(ctx, nil, os.ID); derr != nil {
			logger.Error().Err(derr).Msg("failed to soft-delete Operating System after all sites cleaned up")
			return derr
		}
		logger.Info().Msg("all site associations deleted, Operating System soft-deleted")
	}

	return nil
}

// expandGlobalScopeAssociations creates OSSAs for any new provider sites that were added
// after the OS was originally created (global scope only).
func (mop ManageOperatingSystemPush) expandGlobalScopeAssociations(ctx context.Context, logger zerolog.Logger, os *cdbm.OperatingSystem, ossaDAO cdbm.OperatingSystemSiteAssociationDAO) error {
	if os.IpxeOsScope == nil || *os.IpxeOsScope != cdbm.OperatingSystemScopeGlobal {
		return nil
	}
	if os.InfrastructureProviderID == nil {
		logger.Warn().Msg("global-scope OS has no InfrastructureProviderID, skipping expansion")
		return nil
	}

	stDAO := cdbm.NewSiteDAO(mop.dbSession)
	providerSites, _, err := stDAO.GetAll(ctx, nil, cdbm.SiteFilterInput{
		InfrastructureProviderIDs: []uuid.UUID{*os.InfrastructureProviderID},
		Statuses:                  []string{cdbm.SiteStatusRegistered},
	}, cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve provider sites for global-scope expansion")
		return err
	}

	existingOssas, _, err := ossaDAO.GetAll(ctx, nil,
		cdbm.OperatingSystemSiteAssociationFilterInput{OperatingSystemIDs: []uuid.UUID{os.ID}},
		cdbp.PageInput{Limit: cutil.GetPtr(cdbp.TotalLimit)}, nil)
	if err != nil {
		logger.Error().Err(err).Msg("failed to retrieve existing OSSAs for global-scope expansion")
		return err
	}

	existingSites := map[uuid.UUID]struct{}{}
	for _, ea := range existingOssas {
		existingSites[ea.SiteID] = struct{}{}
	}

	sdDAO := cdbm.NewStatusDetailDAO(mop.dbSession)
	for _, ps := range providerSites {
		if _, ok := existingSites[ps.ID]; ok {
			continue
		}
		ossa, serr := ossaDAO.Create(ctx, nil, cdbm.OperatingSystemSiteAssociationCreateInput{
			OperatingSystemID: os.ID,
			SiteID:            ps.ID,
			Status:            cdbm.OperatingSystemSiteAssociationStatusSyncing,
		})
		if serr != nil {
			logger.Error().Err(serr).Str("Site ID", ps.ID.String()).Msg("failed to create OSSA for global-scope expansion")
			continue
		}
		sdDAO.CreateFromParams(ctx, nil, ossa.ID.String(),
			cdbm.OperatingSystemSiteAssociationStatusSyncing,
			cutil.GetPtr("auto-associated during global-scope update sync"))
		if _, verr := ossaDAO.GenerateAndUpdateVersion(ctx, nil, ossa.ID); verr != nil {
			logger.Error().Err(verr).Str("Site ID", ps.ID.String()).Msg("failed to update version for new OSSA")
		}
	}
	return nil
}

// checkTemplateAvailability returns true if the site should be skipped (template not available).
func (mop ManageOperatingSystemPush) checkTemplateAvailability(ctx context.Context, logger zerolog.Logger, siteID uuid.UUID, os *cdbm.OperatingSystem) bool {
	if os.IpxeTemplateId == nil {
		return false
	}
	tmplUUID, parseErr := uuid.Parse(*os.IpxeTemplateId)
	if parseErr != nil {
		logger.Error().Err(parseErr).Str("TemplateId", *os.IpxeTemplateId).Msg("invalid iPXE template UUID")
		return true
	}
	itsaDAO := cdbm.NewIpxeTemplateSiteAssociationDAO(mop.dbSession)
	_, err := itsaDAO.GetByIpxeTemplateIDAndSiteID(ctx, nil, tmplUUID, siteID, nil)
	if err != nil {
		if errors.Is(err, cdb.ErrDoesNotExist) {
			logger.Warn().Str("TemplateId", *os.IpxeTemplateId).
				Msg("iPXE template not available at site, skipping sync")
		} else {
			logger.Error().Err(err).Msg("error checking iPXE template availability at site")
		}
		return true
	}
	return false
}

func (mop ManageOperatingSystemPush) buildCreateRequest(os *cdbm.OperatingSystem) *cwssaws.CreateOperatingSystemRequest {
	return &cwssaws.CreateOperatingSystemRequest{
		Id:                     &cwssaws.OperatingSystemId{Value: os.ID.String()},
		Name:                   os.Name,
		Description:            os.Description,
		TenantOrganizationId:   os.Org,
		IsActive:               os.IsActive,
		AllowOverride:          os.AllowOverride,
		PhoneHomeEnabled:       os.PhoneHomeEnabled,
		UserData:               os.UserData,
		IpxeScript:             os.IpxeScript,
		IpxeTemplateId:         ipxeTemplateIdPtr(os.IpxeTemplateId),
		IpxeTemplateParameters: modelParamsToProto(os.IpxeTemplateParameters),
		IpxeTemplateArtifacts:  modelArtifactsToProto(os.IpxeTemplateArtifacts),
	}
}

func (mop ManageOperatingSystemPush) buildUpdateRequest(os *cdbm.OperatingSystem) *cwssaws.UpdateOperatingSystemRequest {
	return &cwssaws.UpdateOperatingSystemRequest{
		Id:                         &cwssaws.OperatingSystemId{Value: os.ID.String()},
		Name:                       &os.Name,
		Description:                os.Description,
		IsActive:                   &os.IsActive,
		AllowOverride:              &os.AllowOverride,
		PhoneHomeEnabled:           &os.PhoneHomeEnabled,
		UserData:                   os.UserData,
		IpxeScript:                 os.IpxeScript,
		IpxeTemplateId:             ipxeTemplateIdPtr(os.IpxeTemplateId),
		IpxeTemplateParameters:     &cwssaws.IpxeTemplateParameters{Items: modelParamsToProto(os.IpxeTemplateParameters)},
		IpxeTemplateArtifacts:      &cwssaws.IpxeTemplateArtifacts{Items: modelArtifactsToProto(os.IpxeTemplateArtifacts)},
		IpxeTemplateDefinitionHash: os.IpxeTemplateDefinitionHash,
	}
}

// updateOSSAStatus is a helper to update the OSSA status and create a status detail entry.
func (mop ManageOperatingSystemPush) updateOSSAStatus(ctx context.Context, logger zerolog.Logger, ossaDAO cdbm.OperatingSystemSiteAssociationDAO, ossaID uuid.UUID, status string, message string) {
	if _, err := ossaDAO.Update(ctx, nil, cdbm.OperatingSystemSiteAssociationUpdateInput{
		OperatingSystemSiteAssociationID: ossaID,
		Status:                           cutil.GetPtr(status),
	}); err != nil {
		logger.Error().Err(err).Str("Status", status).Msg("failed to update OSSA status")
		return
	}
	sdDAO := cdbm.NewStatusDetailDAO(mop.dbSession)
	if _, err := sdDAO.CreateFromParams(ctx, nil, ossaID.String(), status, &message); err != nil {
		logger.Error().Err(err).Msg("failed to create status detail for OSSA")
	}
}

// updateAggregateOSStatus computes and writes the aggregate OS status after sync.
// If any artifact has CACHED_ONLY strategy, the OS stays Provisioning until
// the inbound inventory confirms all cached_url values are set on core.
func (mop ManageOperatingSystemPush) updateAggregateOSStatus(ctx context.Context, logger zerolog.Logger, os *cdbm.OperatingSystem, hadErrors bool) {
	osDAO := cdbm.NewOperatingSystemDAO(mop.dbSession)

	var newStatus string
	var statusMessage string

	if hadErrors {
		newStatus = cdbm.OperatingSystemStatusError
		statusMessage = "failed to sync Operating System to one or more sites"
	} else if hasCachedOnlyArtifact(os.IpxeTemplateArtifacts) {
		newStatus = cdbm.OperatingSystemStatusProvisioning
		statusMessage = "Operating System synced to all sites, waiting for artifact caching"
	} else {
		newStatus = cdbm.OperatingSystemStatusReady
		statusMessage = "Operating System successfully synced to all sites"
	}

	if _, err := osDAO.Update(ctx, nil, cdbm.OperatingSystemUpdateInput{
		OperatingSystemId: os.ID,
		Status:            &newStatus,
	}); err != nil {
		logger.Error().Err(err).Msg("failed to update aggregate OS status")
		return
	}

	sdDAO := cdbm.NewStatusDetailDAO(mop.dbSession)
	if _, err := sdDAO.CreateFromParams(ctx, nil, os.ID.String(), newStatus, &statusMessage); err != nil {
		logger.Error().Err(err).Msg("failed to create status detail for aggregate OS status")
	}
}

func hasCachedOnlyArtifact(artifacts []cdbm.OperatingSystemIpxeArtifact) bool {
	for _, a := range artifacts {
		if a.CacheStrategy == cwssaws.IpxeTemplateArtifactCacheStrategy_CACHED_ONLY.String() {
			return true
		}
	}
	return false
}

// ipxeTemplateIdPtr converts a nullable string UUID to the proto IpxeTemplateId message.
func ipxeTemplateIdPtr(id *string) *cwssaws.IpxeTemplateId {
	if id == nil {
		return nil
	}
	return &cwssaws.IpxeTemplateId{Value: *id}
}

// modelParamsToProto converts DB model iPXE parameters to proto representation.
func modelParamsToProto(params []cdbm.OperatingSystemIpxeParameter) []*cwssaws.IpxeTemplateParameter {
	result := make([]*cwssaws.IpxeTemplateParameter, 0, len(params))
	for _, p := range params {
		result = append(result, &cwssaws.IpxeTemplateParameter{Name: p.Name, Value: p.Value})
	}
	return result
}

// modelArtifactsToProto converts DB model iPXE artifacts to proto representation.
func modelArtifactsToProto(artifacts []cdbm.OperatingSystemIpxeArtifact) []*cwssaws.IpxeTemplateArtifact {
	result := make([]*cwssaws.IpxeTemplateArtifact, 0, len(artifacts))
	for _, a := range artifacts {
		strategy := cwssaws.IpxeTemplateArtifactCacheStrategy(cwssaws.IpxeTemplateArtifactCacheStrategy_value[a.CacheStrategy])
		result = append(result, &cwssaws.IpxeTemplateArtifact{
			Name:          a.Name,
			Url:           a.URL,
			Sha:           a.SHA,
			AuthType:      a.AuthType,
			AuthToken:     a.AuthToken,
			CacheStrategy: strategy,
		})
	}
	return result
}
