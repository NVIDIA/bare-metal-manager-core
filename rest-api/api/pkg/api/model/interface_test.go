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
	"github.com/stretchr/testify/require"
)

func TestNewAPIInterface(t *testing.T) {
	type args struct {
		dbis *cdbm.Interface
	}

	dbis := &cdbm.Interface{
		ID:                 uuid.New(),
		InstanceID:         uuid.New(),
		SubnetID:           cdb.GetUUIDPtr(uuid.New()),
		VpcPrefixID:        nil,
		MachineInterfaceID: cdb.GetUUIDPtr(uuid.New()),
		RequestedIpAddress: cdb.GetStrPtr("192.0.2.10"),
		Created:            time.Now(),
		Updated:            time.Now(),
	}

	tests := []struct {
		name string
		args args
		want *APIInterface
	}{
		{
			name: "test new API Interface Subnet initializer",
			args: args{
				dbis: dbis,
			},
			want: &APIInterface{
				ID:                 dbis.ID.String(),
				InstanceID:         dbis.InstanceID.String(),
				SubnetID:           cdb.GetStrPtr(dbis.SubnetID.String()),
				RequestedIpAddress: cdb.GetStrPtr("192.0.2.10"),
				Status:             dbis.Status,
				Created:            dbis.Created,
				Updated:            dbis.Updated,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAPIInterface(tt.args.dbis); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAPIInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIInterfaceCreateOrUpdateRequest_InlineRoutingProfileValidate(t *testing.T) {
	tests := []struct {
		name                       string
		req                        APIInterfaceCreateOrUpdateRequest
		wantErr                    bool
		wantErrorContains          []string
		wantAllowedAnycastPrefixes []string
		wantNonNilPrefixes         bool
	}{
		{
			name: "VPC Prefix interface accepts IPv4 and IPv6 anycast prefixes",
			req: APIInterfaceCreateOrUpdateRequest{
				VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
				InlineRoutingProfile: &APIInterfaceInlineRoutingProfile{
					AllowedAnycastPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"},
				},
			},
			wantAllowedAnycastPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"},
		},
		{
			name: "explicit empty routing profile stays non-nil with empty anycast prefixes",
			req: APIInterfaceCreateOrUpdateRequest{
				VpcPrefixID:          cdb.GetStrPtr(uuid.NewString()),
				InlineRoutingProfile: &APIInterfaceInlineRoutingProfile{},
			},
			wantAllowedAnycastPrefixes: []string{},
			wantNonNilPrefixes:         true,
		},
		{
			name: "invalid anycast prefix returns field-specific error",
			req: APIInterfaceCreateOrUpdateRequest{
				VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
				InlineRoutingProfile: &APIInterfaceInlineRoutingProfile{
					AllowedAnycastPrefixes: []string{"not-a-prefix"},
				},
			},
			wantErr:           true,
			wantErrorContains: []string{"allowedAnycastPrefixes", "not-a-prefix"},
		},
		{
			name: "Subnet interface rejects routing profile",
			req: APIInterfaceCreateOrUpdateRequest{
				SubnetID:             cdb.GetStrPtr(uuid.NewString()),
				InlineRoutingProfile: &APIInterfaceInlineRoutingProfile{},
			},
			wantErr:           true,
			wantErrorContains: []string{"inlineRoutingProfile", "cannot be specified for Subnet based Interfaces"},
		},
		{
			name: "Subnet interface accepts nil routing profile",
			req: APIInterfaceCreateOrUpdateRequest{
				SubnetID: cdb.GetStrPtr(uuid.NewString()),
			},
		},
		{
			name: "VPC Prefix interface accepts nil routing profile",
			req: APIInterfaceCreateOrUpdateRequest{
				VpcPrefixID: cdb.GetStrPtr(uuid.NewString()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr {
				require.Error(t, err)
				for _, want := range tt.wantErrorContains {
					assert.Contains(t, err.Error(), want)
				}
				return
			}

			assert.NoError(t, err)
			if tt.req.InlineRoutingProfile != nil {
				if tt.wantNonNilPrefixes {
					assert.NotNil(t, tt.req.InlineRoutingProfile.AllowedAnycastPrefixes)
				}
				assert.Equal(t, tt.wantAllowedAnycastPrefixes, tt.req.InlineRoutingProfile.AllowedAnycastPrefixes)
			}
		})
	}
}

func TestAPIInterfaceInlineRoutingProfile_ToDB(t *testing.T) {
	var nilProfile *APIInterfaceInlineRoutingProfile
	assert.Nil(t, nilProfile.ToDB())

	emptyProfile := (&APIInterfaceInlineRoutingProfile{}).ToDB()
	require.NotNil(t, emptyProfile)
	assert.NotNil(t, emptyProfile.AllowedAnycastPrefixes)
	assert.Empty(t, emptyProfile.AllowedAnycastPrefixes)

	apiProfile := &APIInterfaceInlineRoutingProfile{
		AllowedAnycastPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"},
	}
	dbProfile := apiProfile.ToDB()
	require.NotNil(t, dbProfile)
	assert.Equal(t, []string{"192.0.2.0/24", "2001:db8::/64"}, dbProfile.AllowedAnycastPrefixes)

	apiProfile.AllowedAnycastPrefixes[0] = "198.51.100.0/24"
	assert.Equal(t, []string{"192.0.2.0/24", "2001:db8::/64"}, dbProfile.AllowedAnycastPrefixes)
}

func TestAPIInterfaceInlineRoutingProfile_FromDB(t *testing.T) {
	dbProfile := &cdbm.InterfaceInlineRoutingProfile{
		AllowedAnycastPrefixes: []string{"192.0.2.0/24", "2001:db8::/64"},
	}
	apiProfile := &APIInterfaceInlineRoutingProfile{}
	apiProfile.FromDB(dbProfile)
	assert.Equal(t, []string{"192.0.2.0/24", "2001:db8::/64"}, apiProfile.AllowedAnycastPrefixes)

	dbProfile.AllowedAnycastPrefixes[0] = "198.51.100.0/24"
	assert.Equal(t, []string{"192.0.2.0/24", "2001:db8::/64"}, apiProfile.AllowedAnycastPrefixes)

	var nilProfile *APIInterfaceInlineRoutingProfile
	nilProfile.FromDB(dbProfile)
}

func TestAPIInterfaceCreateRequest_Validate(t *testing.T) {
	type fields struct {
		SubnetID    *string
		VpcPrefixID *string
		IPAddress   *string
		IsPhysical  bool
		Device      *string

		DeviceInstance    *int
		VirtualFunctionID *int
	}
	tests := []struct {
		name             string
		fields           fields
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name: "test valid Interface Subnet request",
			fields: fields{
				SubnetID: cdb.GetStrPtr(uuid.New().String()),
			},
			wantErr: false,
		},
		{
			name: "test valid Interface VpcPrefix request",
			fields: fields{
				VpcPrefixID: cdb.GetStrPtr(uuid.New().String()),
				IPAddress:   cdb.GetStrPtr("192.0.2.11"),
				IsPhysical:  true,
			},
			wantErr: false,
		},
		{
			name: "test invalid Interface Subnet request",
			fields: fields{
				SubnetID: cdb.GetStrPtr("bad-uuid"),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface VpcPrefix request",
			fields: fields{
				VpcPrefixID: cdb.GetStrPtr("bad-uuid"),
				IsPhysical:  true,
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface request",
			fields: fields{
				VpcPrefixID: cdb.GetStrPtr(uuid.New().String()),
				SubnetID:    cdb.GetStrPtr(uuid.New().String()),
			},
			wantErr: true,
		},
		{
			name: "test valid Interface device and deviceInterface request",
			fields: fields{
				VpcPrefixID:    cdb.GetStrPtr(uuid.New().String()),
				IsPhysical:     true,
				Device:         cdb.GetStrPtr("test-device"),
				DeviceInstance: cdb.GetIntPtr(15),
			},
			wantErr: false,
		},
		{
			name: "test invalid Interface device and deviceInterface request",
			fields: fields{
				VpcPrefixID:    cdb.GetStrPtr(uuid.New().String()),
				IsPhysical:     false,
				Device:         cdb.GetStrPtr("test-device"),
				DeviceInstance: cdb.GetIntPtr(1),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface device and deviceInterface request",
			fields: fields{
				VpcPrefixID:       cdb.GetStrPtr(uuid.New().String()),
				IPAddress:         cdb.GetStrPtr("192.0.2.11"),
				IsPhysical:        false,
				Device:            cdb.GetStrPtr("test-device"),
				DeviceInstance:    cdb.GetIntPtr(1),
				VirtualFunctionID: cdb.GetIntPtr(20),
			},
			wantErr: true,
		},
		{
			name: "test valid Interface device and deviceInterface request",
			fields: fields{
				VpcPrefixID:       cdb.GetStrPtr(uuid.New().String()),
				IsPhysical:        false,
				Device:            cdb.GetStrPtr("test-device"),
				DeviceInstance:    cdb.GetIntPtr(1),
				VirtualFunctionID: cdb.GetIntPtr(1),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface device and deviceInstance request",
			fields: fields{
				Device:      cdb.GetStrPtr("test-device"),
				VpcPrefixID: cdb.GetStrPtr(uuid.New().String()),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface device and deviceInterface request",
			fields: fields{
				DeviceInstance: cdb.GetIntPtr(1),
				VpcPrefixID:    cdb.GetStrPtr(uuid.New().String()),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface ipAddress with subnet request",
			fields: fields{
				SubnetID:  cdb.GetStrPtr(uuid.New().String()),
				IPAddress: cdb.GetStrPtr("192.0.2.11"),
			},
			wantErr:          true,
			wantErrorMessage: "cannot be specified for Subnet based Interfaces",
		},
		{
			name: "test invalid Interface ipAddress without subnet or vpc prefix request",
			fields: fields{
				IPAddress: cdb.GetStrPtr("192.0.2.11"),
			},
			wantErr:          true,
			wantErrorMessage: "either `subnetId` or `vpcPrefixId` must be specified",
		},
		{
			name: "test invalid Interface ipAddress with final host bit 0",
			fields: fields{
				VpcPrefixID: cdb.GetStrPtr(uuid.New().String()),
				IPAddress:   cdb.GetStrPtr("192.0.2.10"),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface ipAddress request",
			fields: fields{
				VpcPrefixID: cdb.GetStrPtr(uuid.New().String()),
				IPAddress:   cdb.GetStrPtr("not-an-ip"),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface device and deviceInterface request",
			fields: fields{
				Device:         cdb.GetStrPtr("test-device"),
				DeviceInstance: cdb.GetIntPtr(1),
			},
			wantErr: true,
		},
		{
			name: "test invalid Interface device and deviceInterface request",
			fields: fields{
				Device:         cdb.GetStrPtr("test-device"),
				DeviceInstance: cdb.GetIntPtr(1),
				SubnetID:       cdb.GetStrPtr(uuid.New().String()),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iscr := APIInterfaceCreateOrUpdateRequest{
				SubnetID:       tt.fields.SubnetID,
				VpcPrefixID:    tt.fields.VpcPrefixID,
				IPAddress:      tt.fields.IPAddress,
				IsPhysical:     tt.fields.IsPhysical,
				Device:         tt.fields.Device,
				DeviceInstance: tt.fields.DeviceInstance,
			}
			err := iscr.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("APIInterfaceCreateOrUpdateRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErrorMessage != "" && err != nil {
				assert.Contains(t, err.Error(), tt.wantErrorMessage)
			}
		})
	}
}
