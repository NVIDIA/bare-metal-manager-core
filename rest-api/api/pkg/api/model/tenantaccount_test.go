// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	cutil "github.com/NVIDIA/infra-controller/rest-api/common/pkg/util"
	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPITenantAccountCreateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APITenantAccountCreateRequest
		expectErr bool
		errStr    string
	}{
		{
			desc:      "ok when infrastructureProviderID is omitted (inferred from org by handler)",
			obj:       APITenantAccountCreateRequest{TenantID: cutil.GetPtr(uuid.New().String())},
			expectErr: false,
		},
		{
			desc:      "errors when infrastructureProviderID is invalid",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: "non-uuid", TenantID: cutil.GetPtr(uuid.New().String())},
			expectErr: true,
			errStr:    "infrastructureProviderId: " + validationErrorInvalidUUID + ".",
		},
		{
			desc:      "ok when tenantID and tenantOrg are empty",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String()},
			expectErr: true,
			errStr:    "tenantId: " + validationErrorTenantIDOrOrgRequired + "; tenantOrg: " + validationErrorTenantIDOrOrgRequired + ".",
		},
		{
			desc:      "error when TenantID is invalid",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantID: cutil.GetPtr("non-uuid")},
			expectErr: true,
			errStr:    "tenantId: " + validationErrorInvalidUUID + ".",
		},
		{
			desc:      "error when TenantOrg is invalid",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantOrg: cutil.GetPtr("n")},
			expectErr: true,
			errStr:    "tenantOrg: " + validationErrorStringLength + ".",
		},
		{
			desc:      "ok with valid values - with tenantID",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantID: cutil.GetPtr(uuid.New().String())},
			expectErr: false,
		},
		{
			desc:      "ok with valid values - with tenantOrg",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantOrg: cutil.GetPtr("SomeOrgName")},
			expectErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate()
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				assert.Equal(t, tc.errStr, err.Error())
			}
		})
	}
}

func TestAPITenantAccountUpdateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APITenantAccountUpdateRequest
		expectErr bool
		errStr    string
	}{
		{
			desc:      "errors when tenantContactID is invalid",
			obj:       APITenantAccountUpdateRequest{TenantContactID: cutil.GetPtr("non-uuid")},
			expectErr: true,
			errStr:    "tenantContactId: " + validationErrorInvalidUUID + ".",
		},
		{
			desc:      "ok when tenantContactID is not provided",
			obj:       APITenantAccountUpdateRequest{},
			expectErr: false,
		},
		{
			desc:      "ok when tenantContactID is valid",
			obj:       APITenantAccountUpdateRequest{TenantContactID: cutil.GetPtr(uuid.New().String())},
			expectErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate()
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				assert.Equal(t, tc.errStr, err.Error())
			}
		})
	}
}

func TestAPITenantAccountNew(t *testing.T) {
	dbObj := &cdbm.TenantAccount{
		ID:                        uuid.New(),
		TenantID:                  cutil.GetPtr(uuid.New()),
		TenantOrg:                 "testOrg",
		InfrastructureProviderID:  uuid.New(),
		InfrastructureProviderOrg: "testIPOrg",
		TenantContactID:           cutil.GetPtr(uuid.New()),
		Status:                    "Invited",
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}
	dbUsr := &cdbm.User{
		ID:          uuid.New(),
		StarfleetID: cutil.GetPtr("sf"),
		FirstName:   cutil.GetPtr("t"),
		LastName:    cutil.GetPtr("s"),
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	dbObj2 := &cdbm.TenantAccount{
		ID:                        uuid.New(),
		TenantID:                  cutil.GetPtr(uuid.New()),
		TenantOrg:                 "testOrg",
		InfrastructureProviderID:  uuid.New(),
		InfrastructureProviderOrg: "testIPOrg",
		TenantContact:             dbUsr,
		TenantContactID:           cutil.GetPtr(uuid.New()),
		Status:                    "Invited",
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}
	apiUsr := NewAPIUserFromDBUser(*dbUsr)

	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbObj.ID.String(),
			Status:   cdbm.TenantAccountStatusInvited,
			Message:  cutil.GetPtr("received tenant account creation request, pending accept"),
			Created:  time.Now(),
			Updated:  time.Now(),
		},
		{
			ID:       uuid.New(),
			EntityID: dbObj.ID.String(),
			Status:   cdbm.TenantAccountStatusReady,
			Message:  cutil.GetPtr("received tenant account update request, ready"),
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	msh := []APIStatusDetail{}
	for _, s := range dbsds {
		msh = append(msh, NewAPIStatusDetail(s))
	}
	tests := []struct {
		desc   string
		dbObj  *cdbm.TenantAccount
		sdObj  []cdbm.StatusDetail
		apiObj *APITenantAccount
	}{
		{
			desc:  "success with TenantContact nil",
			dbObj: dbObj,
			sdObj: dbsds,
			apiObj: &APITenantAccount{
				ID:                        dbObj.ID.String(),
				InfrastructureProviderID:  dbObj.InfrastructureProviderID.String(),
				InfrastructureProviderOrg: dbObj.InfrastructureProviderOrg,
				TenantID:                  cutil.GetPtr(dbObj.TenantID.String()),
				TenantOrg:                 dbObj.TenantOrg,
				TenantContact:             nil,
				AllocationCount:           2,
				Status:                    dbObj.Status,
				StatusHistory:             msh,
				Created:                   dbObj.Created,
				Updated:                   dbObj.Updated,
			},
		},
		{
			desc:  "success with TenantContact not nil",
			dbObj: dbObj2,
			sdObj: dbsds,
			apiObj: &APITenantAccount{
				ID:                        dbObj2.ID.String(),
				InfrastructureProviderID:  dbObj2.InfrastructureProviderID.String(),
				InfrastructureProviderOrg: dbObj2.InfrastructureProviderOrg,
				TenantID:                  cutil.GetPtr(dbObj2.TenantID.String()),
				TenantOrg:                 dbObj.TenantOrg,
				TenantContact:             apiUsr,
				AllocationCount:           2,
				Status:                    dbObj2.Status,
				StatusHistory:             msh,
				Created:                   dbObj2.Created,
				Updated:                   dbObj2.Updated,
			},
		},
		{
			desc:  "status history is an empty slice (not nil) when no status details exist",
			dbObj: dbObj,
			sdObj: []cdbm.StatusDetail{},
			apiObj: &APITenantAccount{
				ID:                         dbObj.ID.String(),
				AccountNumberDeprecated:    cutil.GetPtr(dbObj.AccountNumber),
				InfrastructureProviderID:   dbObj.InfrastructureProviderID.String(),
				InfrastructureProviderOrg:  dbObj.InfrastructureProviderOrg,
				SubscriptionIDDeprecated:   dbObj.SubscriptionID,
				SubscriptionTierDeprecated: dbObj.SubscriptionTier,
				TenantID:                   cutil.GetPtr(dbObj.TenantID.String()),
				TenantOrg:                  dbObj.TenantOrg,
				TenantContact:              nil,
				AllocationCount:            2,
				Status:                     dbObj.Status,
				StatusHistory:              []APIStatusDetail{},
				Created:                    dbObj.Created,
				Updated:                    dbObj.Updated,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPITenantAccount(tc.dbObj, tc.sdObj, 2)
			assert.Equal(t, tc.apiObj.ID, got.ID)
			assert.Equal(t, tc.apiObj.InfrastructureProviderID, got.InfrastructureProviderID)
			assert.Equal(t, tc.apiObj.InfrastructureProviderOrg, got.InfrastructureProviderOrg)
			assert.Equal(t, tc.apiObj.TenantID, got.TenantID)
			assert.Equal(t, tc.apiObj.TenantOrg, got.TenantOrg)
			assert.Equal(t, tc.apiObj.TenantContact, got.TenantContact)
			assert.Equal(t, tc.apiObj.AllocationCount, got.AllocationCount)
			assert.Equal(t, tc.apiObj.Status, got.Status)
			assert.Equal(t, tc.apiObj.StatusHistory, got.StatusHistory)
			assert.NotNil(t, got.StatusHistory)
		})
	}
}
