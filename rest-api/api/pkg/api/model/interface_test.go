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
