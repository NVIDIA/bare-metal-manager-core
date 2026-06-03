// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdmu "github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	"github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIOperatingSystemCreateRequest_Validate(t *testing.T) {
	tests := []struct {
		desc      string
		obj       APIOperatingSystemCreateRequest
		expectErr bool
	}{
		{
			desc:      "error when Name is not provided",
			obj:       APIOperatingSystemCreateRequest{Description: cdb.GetStrPtr("ab"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APIOperatingSystemCreateRequest{Name: "a", Description: cdb.GetStrPtr("ab"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false},
			expectErr: true,
		},
		{
			desc:      "ok when description is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false},
			expectErr: false,
		},
		{
			desc:      "error when InfrastructID is not nil",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: cdb.GetStrPtr(uuid.New().String()), TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false},
			expectErr: true,
		},
		{
			desc:      "error when IpxeScript is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr(""), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false},
			expectErr: true,
		},
		{
			desc:      "error when ImageURL is invalid",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("imagenet/iso"), UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when ImageSHA is invalid",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("tttt"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when only ImageURL is specified not other image attribute",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://image.net/iso")},
			expectErr: true,
		},
		{
			desc:      "error when only ImageURL is specified but not site ID",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://image.net/iso")},
			expectErr: true,
		},
		{
			desc:      "error when siteIDs are specified but no imageURL",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", SiteIDs: []string{uuid.NewString()}},
			expectErr: true,
		},
		{
			desc:      "error when ImageDisk is invalid",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageDisk: cdb.GetStrPtr("tttt/"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when ImageURL not specified but ImageAuthType is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageAuthType: cdb.GetStrPtr(""), UserData: nil, AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when ImageAuthToken is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageAuthToken: cdb.GetStrPtr(""), UserData: nil, AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when both RootFsID and RootFsLabel are populated",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), RootFsLabel: cdb.GetStrPtr("test-label"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when imageURL not specified but RootFsID is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), RootFsID: cdb.GetStrPtr(""), UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when imageURL not specified but RootFsLabel is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), RootFsLabel: cdb.GetStrPtr(""), UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but no imageAuthType",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthToken: cdb.GetStrPtr("rsa")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but imageAuthType is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthToken: cdb.GetStrPtr("rsa"), ImageAuthType: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthType are specified but no imageAuthToken",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthType: cdb.GetStrPtr("Bearer")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthType are specified but imageAuthToken is empty",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthType: cdb.GetStrPtr("Bearer"), ImageAuthToken: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but imageAuthType is invalid",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthType: cdb.GetStrPtr("VAPID"), ImageAuthToken: cdb.GetStrPtr("rsa")},
			expectErr: true,
		},
		{
			desc:      "error when IpxeScript and ImageURL both specified",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when IpxeScript and SiteID both specified",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), SiteIDs: []string{uuid.NewString()}, UserData: cdb.GetStrPtr("ud"), AllowOverride: true},
			expectErr: true,
		},
		{
			desc:      "error when IpxeScript specified but enableBlockStorage is true",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: true, EnableBlockStorage: true},
			expectErr: true,
		},
		{
			desc:      "error when imageURL is specified but neither rootFsLabel nor rootFsID is",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", ImageURL: cdb.GetStrPtr("http://image.net/iso")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL is specified but multiple sites specified",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), SiteIDs: []string{uuid.NewString(), uuid.NewString()}, ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), IsCloudInit: true, AllowOverride: false},
			expectErr: true,
		},
		{
			desc:      "error when enableBlockStorage is true",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false, EnableBlockStorage: true},
			expectErr: true,
		},
		{
			desc:      "ok when all fields are speced",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", Description: cdb.GetStrPtr("test"), InfrastructureProviderID: nil, TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr("ud"), IsCloudInit: true, AllowOverride: false, EnableBlockStorage: false},
			expectErr: false,
		},
		{
			desc:      "ok when only required valid ipxe fields present",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", TenantID: cdb.GetStrPtr(uuid.New().String()), IpxeScript: cdb.GetStrPtr("ipxe"), IsCloudInit: true, AllowOverride: false},
			expectErr: false,
		},
		{
			desc:      "ok when only required valid image fields present",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), SiteIDs: []string{uuid.NewString()}, ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), IsCloudInit: true, AllowOverride: false},
			expectErr: false,
		},
		{
			desc:      "ok when empty strings specified for optional image fields",
			obj:       APIOperatingSystemCreateRequest{Name: "abc", TenantID: cdb.GetStrPtr(uuid.New().String()), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), SiteIDs: []string{uuid.NewString()}, ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), IsCloudInit: true, AllowOverride: false, ImageDisk: cdb.GetStrPtr(""), ImageAuthType: cdb.GetStrPtr(""), ImageAuthToken: cdb.GetStrPtr("")},
			expectErr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			err := tc.obj.Validate()
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPIOperatingSystemUpdateRequest_Validate(t *testing.T) {
	existingImageBasedOS := &cdbm.OperatingSystem{
		ID:        uuid.New(),
		Name:      "ab",
		ImageURL:  cdb.GetStrPtr("https://oldimagepath.iso"),
		ImageSHA:  cdb.GetStrPtr("tttt"),
		RootFsID:  cdb.GetStrPtr("fsID"),
		Status:    cdbm.OperatingSystemStatusPending,
		Type:      cdbm.OperatingSystemTypeImage,
		CreatedBy: uuid.New(),
	}

	existingIpxeBasedOS := &cdbm.OperatingSystem{
		ID:         uuid.New(),
		Name:       "ab",
		IpxeScript: cdb.GetStrPtr("original ipxe"),
		Status:     cdbm.OperatingSystemStatusPending,
		Type:       cdbm.OperatingSystemTypeIPXE,
		CreatedBy:  uuid.New(),
	}

	existingImageBasedOSWithFSLabel := &cdbm.OperatingSystem{
		ID:          uuid.New(),
		Name:        "abc",
		ImageURL:    cdb.GetStrPtr("https://oldimagepath.iso"),
		ImageSHA:    cdb.GetStrPtr("tttt"),
		RootFsLabel: cdb.GetStrPtr("10886660c5b2746ff48224646c5094ebcf88c889"),
		Status:      cdbm.OperatingSystemStatusPending,
		Type:        cdbm.OperatingSystemTypeImage,
		CreatedBy:   uuid.New(),
	}
	tests := []struct {
		desc       string
		obj        APIOperatingSystemUpdateRequest
		existingOS *cdbm.OperatingSystem
		expectErr  bool
	}{
		{
			desc:      "ok when Name is not provided",
			obj:       APIOperatingSystemUpdateRequest{Description: cdb.GetStrPtr("ab")},
			expectErr: false,
		},
		{
			desc:      "ok when Description is not provided",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("ab")},
			expectErr: false,
		},
		{
			desc:      "error when Name is provided but is empty",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr(""), Description: cdb.GetStrPtr("ab")},
			expectErr: true,
		},
		{
			desc:      "error when Name is no valid string",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("a"), Description: cdb.GetStrPtr("ab")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL is not valid",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("imagenet")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthType are specified but no imageAuthToken",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthType: cdb.GetStrPtr("Bearer")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthType are specified but imageAuthToken is empty",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthType: cdb.GetStrPtr("Bearer"), ImageAuthToken: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but no imageAuthType",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthToken: cdb.GetStrPtr("rsa")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but imageAuthType is invalid",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthToken: cdb.GetStrPtr("rsa"), ImageAuthType: cdb.GetStrPtr("VAPID")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and imageAuthToken are specified but imageAuthType is empty",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), ImageAuthToken: cdb.GetStrPtr("rsa"), ImageAuthType: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:      "error when imageURL and ipxeScript both specified",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://image.net/iso"), IpxeScript: cdb.GetStrPtr("ipxe")},
			expectErr: true,
		},
		{
			desc:      "error when both RootFsID and RootFsLabel are populated",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), RootFsLabel: cdb.GetStrPtr("test-label")},
			expectErr: true,
		},
		{
			desc:      "error when os created with rootFsID but request to update rootFsLabel",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsLabel: cdb.GetStrPtr("test-label")},
			expectErr: true,
		},
		{
			desc:      "error when os created with rootFsID and try to clear it without specifying rootFsLabel",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("")},
			expectErr: true,
		},
		{
			desc:       "error when os created with rootFsLabel but request to update rootFsID",
			obj:        APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e")},
			existingOS: existingImageBasedOSWithFSLabel,
			expectErr:  true,
		},
		{
			desc:       "error when os created with rootFsLabel and try to clear it without specifying rootFsID",
			obj:        APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsLabel: cdb.GetStrPtr("")},
			existingOS: existingImageBasedOSWithFSLabel,
			expectErr:  true,
		},
		{
			desc:       "error when ipxeScript is empty",
			obj:        APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("abc"), IpxeScript: cdb.GetStrPtr("")},
			existingOS: existingIpxeBasedOS,
			expectErr:  true,
		},
		{
			desc:      "ok when description is not valid with empty",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("ab"), Description: cdb.GetStrPtr("")},
			expectErr: false,
		},
		{
			desc:       "ok when all valid fields for ipxe are provided",
			obj:        APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("ab"), Description: cdb.GetStrPtr("test"), IpxeScript: cdb.GetStrPtr("ipxe"), UserData: cdb.GetStrPtr(cdmu.TestCommonCloudInit), IsCloudInit: cdb.GetBoolPtr(false), AllowOverride: cdb.GetBoolPtr(true)},
			existingOS: existingIpxeBasedOS,
			expectErr:  false,
		},
		{
			desc:      "ok when all valid image fields provided",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("ab"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e")},
			expectErr: false,
		},
		{
			desc:      "ok when optional image fields are empty",
			obj:       APIOperatingSystemUpdateRequest{Name: cdb.GetStrPtr("ab"), ImageURL: cdb.GetStrPtr("http://iso.net/iso"), ImageSHA: cdb.GetStrPtr("a1efca12ea51069abb123bf9c77889fcc2a31cc5483fc14d115e44fdf07c7980"), RootFsID: cdb.GetStrPtr("666c2eee-193d-42db-a490-4c444342bd4e"), ImageDisk: cdb.GetStrPtr(""), ImageAuthType: cdb.GetStrPtr(""), ImageAuthToken: cdb.GetStrPtr("")},
			expectErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			var os *cdbm.OperatingSystem
			if tc.existingOS != nil {
				os = tc.existingOS
			} else {
				os = existingImageBasedOS
			}
			err := tc.obj.Validate(os)
			assert.Equal(t, tc.expectErr, err != nil)
			if err != nil {
				fmt.Println(err.Error())
			}
		})
	}
}

func TestAPIOperatingSystemCreateRequest_ValidateAndSetUserData(t *testing.T) {
	type fields struct {
		Name              string
		Description       *string
		TenantID          *string
		OperatingSystemID *string
		IpxeScript        *string
		UserData          *string
		PhoneHomeEnabled  *bool
	}
	tests := []struct {
		name         string
		fields       fields
		phoneHomeUrl *string
		wantErr      bool
	}{
		{
			name: "test valid Operating System PhoneHome enabled create request when userData is nil",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Operating System PhoneHome enabled create request when userData is empty",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr(""),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is invalid",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("test"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      true,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is valid YAML but invalid cloud-config",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("#test"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      true,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is valid YAML and valid cloud-config but comments only",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("#cloud-config"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      true,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome disabled create request when userData is invalid",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("test"),
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr:      false,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome nil create request when userData is invalid",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr("test"),
				PhoneHomeEnabled:  nil,
			},
			wantErr:      false,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
		{
			name: "test valid Instance PhoneHome enabled create request when userData is valid",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				TenantID:          db.GetStrPtr(uuid.NewString()),
				OperatingSystemID: cdb.GetStrPtr(uuid.NewString()),
				UserData:          cdb.GetStrPtr(util.TestCommonCloudInit),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: cdb.GetStrPtr("http://localhost/local"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			icr := APIOperatingSystemCreateRequest{
				Name:             tt.fields.Name,
				Description:      tt.fields.Description,
				TenantID:         tt.fields.TenantID,
				IpxeScript:       tt.fields.IpxeScript,
				UserData:         tt.fields.UserData,
				PhoneHomeEnabled: tt.fields.PhoneHomeEnabled,
			}

			err := icr.ValidateAndSetUserData(*tt.phoneHomeUrl)
			if (err != nil) != tt.wantErr {
				marshalledErr, _ := json.Marshal(err)
				t.Errorf("APIOperatingSystemCreateRequest.ValidateAndSetUserData() error = %v, wantErr %v", string(marshalledErr), tt.wantErr)
			}

			if err != nil {
				return
			}

			if icr.PhoneHomeEnabled != nil && *icr.PhoneHomeEnabled {
				assert.NotNil(t, icr.UserData)
				assert.Contains(t, *icr.UserData, *tt.phoneHomeUrl)
				// split string into new line and make sure always first line is #cloud-config
				lines := strings.Split(*icr.UserData, "\n")
				assert.Equal(t, util.SiteCloudConfig, lines[0])
				assert.NotEqual(t, util.SiteCloudConfig, lines[1])
			}
		})
	}
}

func TestAPIOperatingSystemUpdateRequest_ValidateAndSetUserData(t *testing.T) {
	type fields struct {
		Name              string
		Description       *string
		OperatingSystemID *string
		UserData          *string
		PhoneHomeEnabled  *bool
	}

	existingPhoneHomeEnabledOS := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(cdmu.TestCommonPhoneHomeCloudInit),
		PhoneHomeEnabled: true,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	existingPhoneHomeEnabledOSUserdataNil := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         nil,
		PhoneHomeEnabled: true,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	existingPhoneHomeDisabledOS := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(cdmu.TestCommonCloudInit),
		PhoneHomeEnabled: false,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	existingPhoneHomeDisabledOSNilUserData := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         nil,
		PhoneHomeEnabled: false,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	existingOSWithPhoneHomeOnlyUserData := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(util.TestCommonPhoneHomeOnlyCloudInit),
		PhoneHomeEnabled: false,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	existingOSWithXMLUserData := &cdbm.OperatingSystem{
		ID:               uuid.New(),
		Name:             "ab",
		IpxeScript:       cdb.GetStrPtr("original ipxe"),
		UserData:         cdb.GetStrPtr(util.TestCommonXMLUserData),
		PhoneHomeEnabled: false,
		Status:           cdbm.OperatingSystemStatusReady,
		Type:             cdbm.OperatingSystemTypeIPXE,
		CreatedBy:        uuid.New(),
	}

	tests := []struct {
		name                     string
		fields                   fields
		phoneHomeUrl             string
		userDataNegativeSearches []string
		wantErr                  bool
		existingOS               *cdbm.OperatingSystem
	}{
		{
			name: "test valid Operating System PhoneHome disabled update request when userData is nil and existing OS has enabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingPhoneHomeEnabledOS.ID.String()),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeEnabledOS,
		},
		{
			name: "test valid PhoneHome enabled, request userData is nil, existing OS userdata is nil, and existing OS has phonehome enabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingPhoneHomeEnabledOS.ID.String()),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeEnabledOSUserdataNil,
		},
		{
			name: "test valid Operating System PhoneHome enabled update request when userData is nil and existing OS has disabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingPhoneHomeDisabledOS.ID.String()),
				UserData:          nil,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeDisabledOS,
		},
		{
			name: "test valid Operating System PhoneHome enabled update request when userData is empty and existing OS has disabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingPhoneHomeDisabledOS.ID.String()),
				UserData:          cdb.GetStrPtr(""),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeDisabledOS,
		},
		{
			name: "test valid Operating System PhoneHome enabled update request when userData is present and existing OS has disabled",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingPhoneHomeDisabledOSNilUserData.ID.String()),
				UserData:          &cdmu.TestCommonCloudInit,
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeDisabledOSNilUserData,
		},
		{
			name: "test valid Operating System PhoneHome disabled update request when userData is present with only phone home section",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingOSWithPhoneHomeOnlyUserData.ID.String()),
				PhoneHomeEnabled:  cdb.GetBoolPtr(false),
			},
			wantErr:      false,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingOSWithPhoneHomeOnlyUserData,
		},
		{
			name: "test invalid Operating System PhoneHome enabled update request when userData is XML",
			fields: fields{
				Name:              "test-name",
				Description:       cdb.GetStrPtr("Test description"),
				OperatingSystemID: db.GetStrPtr(existingOSWithXMLUserData.ID.String()),
				PhoneHomeEnabled:  cdb.GetBoolPtr(true),
			},
			wantErr:      true,
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingOSWithXMLUserData,
		},
		{
			name: "success ipxe request arbitrary user-data, OS phone-home disabled, request phonehome nil",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr("random:\narbitrary\n"),
				PhoneHomeEnabled: nil,
			},
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeDisabledOSNilUserData,
			wantErr:      false,
		},
		{
			name: "success ipxe request arbitrary user-data, OS phone-home disabled, request phonehome enabled",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr("random:\narbitrary\n"),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			existingOS: existingPhoneHomeDisabledOSNilUserData,
			wantErr:    true,
		},
		{
			name: "fail ipxe request invalid user-data, OS phone-home disabled, request phonehome enabled",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr("random:\narbitrary\n"),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			existingOS: existingPhoneHomeDisabledOSNilUserData,
			wantErr:    true,
		},
		{
			name: "success ipxe request invalid user-data, OS phone-home disabled, request phonehome disabled",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr("random:\narbitrary\n"),
				PhoneHomeEnabled: cdb.GetBoolPtr(false),
			},
			phoneHomeUrl: "http://localhost/local",
			existingOS:   existingPhoneHomeDisabledOSNilUserData,
			wantErr:      false,
		},
		{
			name: "success ipxe request invalid user-data, OS phone-home disabled, request phonehome enabled, OS user-data nil, request user-data empty",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr(""),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			existingOS: existingPhoneHomeDisabledOSNilUserData,
			wantErr:    false,
		},
		{
			name: "success ipxe, request valid user-data, OS phone-home disabled, request phonehome disabled, OS user-data nil, request user-data has phone-home only",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr(cdmu.TestCommonPhoneHomeSegment),
				PhoneHomeEnabled: cdb.GetBoolPtr(false),
			},
			phoneHomeUrl: "http://localhost",
			existingOS:   existingPhoneHomeDisabledOSNilUserData,
			wantErr:      false,
		},
		{
			name: "success ipxe, request valid user-data, OS phone-home disabled, request phonehome disabled, OS user-data nil, request user-data has phone-home multiple times",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr(cdmu.TestCommonPhoneHomeSegment + cdmu.TestCommonPhoneHomeSegment + cdmu.TestCommonPhoneHomeSegment),
				PhoneHomeEnabled: cdb.GetBoolPtr(false),
			},
			phoneHomeUrl: "http://localhost",
			existingOS:   existingPhoneHomeDisabledOSNilUserData,
			wantErr:      false,
		},
		{
			name: "success ipxe, request valid user-data, OS phone-home disabled, request phonehome enabled, OS user-data nil, request user-data has phone-home already",
			fields: fields{
				Name:             "test-name",
				Description:      cdb.GetStrPtr("test"),
				UserData:         cdb.GetStrPtr(cdmu.TestCommonCloudInit + "\n" + cdmu.TestCommonPhoneHomeOnlyCloudInit),
				PhoneHomeEnabled: cdb.GetBoolPtr(true),
			},
			phoneHomeUrl:             "http://localhost",
			existingOS:               existingPhoneHomeDisabledOSNilUserData,
			userDataNegativeSearches: []string{"TestCommonPhoneHomeOnlyCloudInit"}, // It's looking for a comment in the TestCommonPhoneHomeOnlyCloudInit value.
			wantErr:                  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osur := APIOperatingSystemUpdateRequest{
				Name:             &tt.fields.Name,
				Description:      tt.fields.Description,
				UserData:         tt.fields.UserData,
				PhoneHomeEnabled: tt.fields.PhoneHomeEnabled,
			}

			err := osur.ValidateAndSetUserData(tt.phoneHomeUrl, tt.existingOS)
			if tt.wantErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			if len(tt.userDataNegativeSearches) > 0 {
				// If user-data is nil, then it certainly won't
				// have things we don't want it to have.
				if osur.UserData != nil {
					for _, search := range tt.userDataNegativeSearches {
						assert.NotContains(t, *osur.UserData, search)
					}
				}
			}

			if osur.PhoneHomeEnabled != nil && *osur.PhoneHomeEnabled {
				assert.NotNil(t, osur.UserData)
				assert.Contains(t, *osur.UserData, tt.phoneHomeUrl)
				// split string into new line and make sure always first line is #cloud-config
				lines := strings.Split(*osur.UserData, "\n")
				assert.Equal(t, util.SiteCloudConfig, lines[0])
				assert.Equal(t, util.SiteCloudConfig, lines[0])
				assert.NotEqual(t, util.SiteCloudConfig, lines[1])
			}

			if osur.PhoneHomeEnabled != nil && !*osur.PhoneHomeEnabled {
				// If phone-home is disabled, user-data can validly be nil.
				if osur.UserData != nil {
					assert.NotContains(t, *osur.UserData, tt.phoneHomeUrl)
				}
			}
		})
	}
}

func TestAPIOperatingSystemNew(t *testing.T) {
	dbOS := &cdbm.OperatingSystem{
		ID:                       uuid.New(),
		Name:                     "test",
		Description:              cdb.GetStrPtr("test"),
		Org:                      "test",
		InfrastructureProviderID: cdb.GetUUIDPtr(uuid.New()),
		TenantID:                 cdb.GetUUIDPtr(uuid.New()),
		IpxeScript:               cdb.GetStrPtr("ipxe"),
		UserData:                 cdb.GetStrPtr("ud"),
		IsCloudInit:              true,
		AllowOverride:            false,
		Status:                   cdbm.OperatingSystemStatusPending,
		Created:                  cdb.GetCurTime(),
		Updated:                  cdb.GetCurTime(),
	}
	dbsds := []cdbm.StatusDetail{
		{
			ID:       uuid.New(),
			EntityID: dbOS.ID.String(),
			Status:   cdbm.OperatingSystemStatusPending,
			Created:  time.Now(),
			Updated:  time.Now(),
		},
	}
	dbossa := []cdbm.OperatingSystemSiteAssociation{
		{ID: uuid.New(), OperatingSystemID: dbOS.ID, SiteID: uuid.New(), Version: cdb.GetStrPtr("1233"), Status: cdbm.OperatingSystemSiteAssociationStatusSyncing},
	}
	sttsmap := map[uuid.UUID]*cdbm.TenantSite{
		dbossa[0].SiteID: {
			ID:                  uuid.New(),
			TenantID:            *dbOS.TenantID,
			TenantOrg:           "test",
			SiteID:              dbossa[0].SiteID,
			EnableSerialConsole: true,
			Config:              map[string]interface{}{},
			Created:             cdb.GetCurTime(),
			Updated:             cdb.GetCurTime(),
		},
	}
	tests := []struct {
		desc    string
		dbObj   *cdbm.OperatingSystem
		sdObj   []cdbm.StatusDetail
		osas    []cdbm.OperatingSystemSiteAssociation
		sttsmap map[uuid.UUID]*cdbm.TenantSite
	}{
		{
			desc:    "test creating API OperatingSystem",
			dbObj:   dbOS,
			sdObj:   dbsds,
			osas:    dbossa,
			sttsmap: sttsmap,
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := NewAPIOperatingSystem(tc.dbObj, tc.sdObj, tc.osas, tc.sttsmap)
			assert.Equal(t, tc.dbObj.ID.String(), got.ID)
			assert.Equal(t, *tc.dbObj.Description, *got.Description)
		})
	}
}
