// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"reflect"
	"testing"
	"time"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
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
			desc:      "errors when infrastructureProviderID is not provided",
			obj:       APITenantAccountCreateRequest{TenantID: cdb.GetStrPtr(uuid.New().String())},
			expectErr: true,
			errStr:    "infrastructureProviderId: " + validationErrorValueRequired + ".",
		},
		{
			desc:      "errors when infrastructureProviderID is invalid",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: "non-uuid", TenantID: cdb.GetStrPtr(uuid.New().String())},
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
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantID: cdb.GetStrPtr("non-uuid")},
			expectErr: true,
			errStr:    "tenantId: " + validationErrorInvalidUUID + ".",
		},
		{
			desc:      "error when TenantOrg is invalid",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantOrg: cdb.GetStrPtr("n")},
			expectErr: true,
			errStr:    "tenantOrg: " + validationErrorStringLength + ".",
		},
		{
			desc:      "ok with valid values - with tenantID",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantID: cdb.GetStrPtr(uuid.New().String())},
			expectErr: false,
		},
		{
			desc:      "ok with valid values - with tenantOrg",
			obj:       APITenantAccountCreateRequest{InfrastructureProviderID: uuid.New().String(), TenantOrg: cdb.GetStrPtr("SomeOrgName")},
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
			obj:       APITenantAccountUpdateRequest{TenantContactID: cdb.GetStrPtr("non-uuid")},
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
			obj:       APITenantAccountUpdateRequest{TenantContactID: cdb.GetStrPtr(uuid.New().String())},
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
		AccountNumber:             "acctNum",
		TenantID:                  cdb.GetUUIDPtr(uuid.New()),
		TenantOrg:                 "testOrg",
		InfrastructureProviderID:  uuid.New(),
		InfrastructureProviderOrg: "testIPOrg",
		SubscriptionID:            cdb.GetStrPtr(uuid.New().String()),
		SubscriptionTier:          cdb.GetStrPtr("someTier"),
		TenantContactID:           cdb.GetUUIDPtr(uuid.New()),
		Status:                    "Invited",
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}
	dbUsr := &cdbm.User{
		ID:          uuid.New(),
		StarfleetID: cdb.GetStrPtr("sf"),
		FirstName:   cdb.GetStrPtr("t"),
		LastName:    cdb.GetStrPtr("s"),
		Created:     cdb.GetCurTime(),
		Updated:     cdb.GetCurTime(),
	}
	dbObj2 := &cdbm.TenantAccount{
		ID:                        uuid.New(),
		AccountNumber:             "acctNum",
		TenantID:                  cdb.GetUUIDPtr(uuid.New()),
		TenantOrg:                 "testOrg",
		InfrastructureProviderID:  uuid.New(),
		InfrastructureProviderOrg: "testIPOrg",
		SubscriptionID:            cdb.GetStrPtr(uuid.New().String()),
		SubscriptionTier:          cdb.GetStrPtr("someTier"),
		TenantContact:             dbUsr,
		TenantContactID:           cdb.GetUUIDPtr(uuid.New()),
		Status:                    "Invited",
		Created:                   cdb.GetCurTime(),
		Updated:                   cdb.GetCurTime(),
	}
	apiUsr := NewAPIUserFromDBUser(*dbUsr)
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbObj.ID.String(),
			Status:   cdbm.TenantAccountStatusPending,
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
				AccountNumber:             dbObj.AccountNumber,
				InfrastructureProviderID:  dbObj.InfrastructureProviderID.String(),
				InfrastructureProviderOrg: dbObj.InfrastructureProviderOrg,
				SubscriptionID:            dbObj.SubscriptionID,
				SubscriptionTier:          dbObj.SubscriptionTier,
				TenantID:                  cdb.GetStrPtr(dbObj.TenantID.String()),
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
				AccountNumber:             dbObj2.AccountNumber,
				InfrastructureProviderID:  dbObj2.InfrastructureProviderID.String(),
				InfrastructureProviderOrg: dbObj.InfrastructureProviderOrg,
				SubscriptionID:            dbObj2.SubscriptionID,
				SubscriptionTier:          dbObj2.SubscriptionTier,
				TenantID:                  cdb.GetStrPtr(dbObj2.TenantID.String()),
				TenantOrg:                 dbObj.TenantOrg,
				TenantContact:             apiUsr,
				AllocationCount:           2,
				Status:                    dbObj2.Status,
				StatusHistory:             msh,
				Created:                   dbObj2.Created,
				Updated:                   dbObj2.Updated,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPITenantAccount(tc.dbObj, tc.sdObj, 2)
			assert.Equal(t, true, reflect.DeepEqual(got, tc.apiObj))
		})
	}
}
